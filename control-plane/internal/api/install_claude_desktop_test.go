package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// TestClaudeDesktopPlan_RegistersAgentlockAndWrapsUserServers covers the
// happy path: plan emits a write op whose content has BOTH our standalone
// "agentlock" observability entry AND every user mcpServers entry rewritten
// to spawn `agentlock mcp-proxy ... -- <original-cmd> <args>`.
func TestClaudeDesktopPlan_RegistersAgentlockAndWrapsUserServers(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)

	// Seed an existing config carrying a user-installed MCP server.
	existing := `{
		"mcpServers": {
			"filesystem": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
				"env": {"FOO": "bar"}
			}
		}
	}`
	planBody := fmt.Sprintf(`{
		"session_id": %q,
		"harnesses": ["claude-desktop"],
		"daemon_url": "http://127.0.0.1:7878",
		"config_dir_override": "/tmp/fake-claude-desktop",
		"existing_files": {"/tmp/fake-claude-desktop/claude_desktop_config.json": %q}
	}`, fx.sessionID, existing)
	res, err := http.Post(fx.srv.URL+"/v1/install/plan", "application/json", strings.NewReader(planBody))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d body=%s", res.StatusCode, buf.String())
	}

	var plan map[string]any
	_ = json.NewDecoder(res.Body).Decode(&plan)
	ops, _ := plan["operations"].([]any)
	if len(ops) != 1 {
		t.Fatalf("expected 1 op, got %d: %+v", len(ops), plan)
	}
	op, _ := ops[0].(map[string]any)

	content, _ := op["content"].(string)
	var got map[string]any
	if err := json.Unmarshal([]byte(content), &got); err != nil {
		t.Fatalf("content not valid JSON: %v\n%s", err, content)
	}
	servers, _ := got["mcpServers"].(map[string]any)

	// Standalone observability entry must still be present.
	agentlockEntry, _ := servers["agentlock"].(map[string]any)
	if agentlockEntry == nil {
		t.Fatalf("missing standalone agentlock entry: %s", content)
	}

	// User's filesystem entry must be WRAPPED (command -> agentlock,
	// args[0] -> "mcp-proxy", original preserved).
	fs, _ := servers["filesystem"].(map[string]any)
	if fs == nil {
		t.Fatalf("user filesystem server lost: %s", content)
	}
	if fs["command"] != "agentlock" {
		t.Fatalf("filesystem.command not wrapped: %v", fs["command"])
	}
	args, _ := fs["args"].([]any)
	if len(args) < 5 || args[0] != "mcp-proxy" || args[1] != "--name" || args[2] != "filesystem" || args[3] != "--" || args[4] != "npx" {
		t.Fatalf("filesystem.args not wrapped correctly: %+v", args)
	}
	original, _ := fs["_agentlock_original"].(map[string]any)
	if original == nil {
		t.Fatalf("filesystem._agentlock_original missing: %+v", fs)
	}
	if original["command"] != "npx" {
		t.Fatalf("preserved command wrong: %v", original["command"])
	}
}

// TestMergeClaudeDesktopConfig_IsIdempotentAfterWrap: re-running install
// must not double-wrap. The second merge sees an already-wrapped entry,
// recovers the stashed original from _agentlock_original, and re-wraps
// from scratch — yielding identical output.
func TestMergeClaudeDesktopConfig_IsIdempotentAfterWrap(t *testing.T) {
	existing := `{
		"mcpServers": {
			"filesystem": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
			}
		}
	}`
	first, err := mergeClaudeDesktopConfig([]byte(existing), "http://127.0.0.1:7878", "agentlock")
	if err != nil {
		t.Fatalf("first merge: %v", err)
	}
	second, err := mergeClaudeDesktopConfig(first, "http://127.0.0.1:7878", "agentlock")
	if err != nil {
		t.Fatalf("second merge: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("non-idempotent re-wrap:\nfirst:  %s\nsecond: %s", first, second)
	}

	// Spot-check that the wrap structure was preserved across both passes:
	// args still start with mcp-proxy, original still pinned.
	var got map[string]any
	_ = json.Unmarshal(second, &got)
	servers, _ := got["mcpServers"].(map[string]any)
	fs, _ := servers["filesystem"].(map[string]any)
	args, _ := fs["args"].([]any)
	if len(args) == 0 || args[0] != "mcp-proxy" {
		t.Fatalf("re-wrap lost mcp-proxy prefix: %+v", args)
	}
	original, _ := fs["_agentlock_original"].(map[string]any)
	if original == nil || original["command"] != "npx" {
		t.Fatalf("re-wrap lost original: %+v", fs)
	}
}

// TestStripClaudeDesktopConfig_RestoresWrappedEntries: uninstall must
// restore each user-wrapped entry from its stashed _agentlock_original
// AND drop our standalone observability entry. Net effect: config
// returns to its pre-install state byte-for-byte (modulo whitespace).
func TestStripClaudeDesktopConfig_RestoresWrappedEntries(t *testing.T) {
	pre := `{
		"mcpServers": {
			"filesystem": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
				"env": {"FOO": "bar"}
			}
		}
	}`
	wrapped, err := mergeClaudeDesktopConfig([]byte(pre), "http://127.0.0.1:7878", "agentlock")
	if err != nil {
		t.Fatalf("merge: %v", err)
	}

	out, removed, err := stripClaudeDesktopConfig(wrapped)
	if err != nil {
		t.Fatalf("strip: %v", err)
	}
	if removed != 2 {
		t.Fatalf("expected 2 removals (1 wrap restore + 1 standalone drop), got %d", removed)
	}

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("strip output not JSON: %v\n%s", err, out)
	}
	servers, _ := got["mcpServers"].(map[string]any)
	if _, ok := servers["agentlock"]; ok {
		t.Fatalf("standalone agentlock entry not removed: %s", out)
	}
	fs, _ := servers["filesystem"].(map[string]any)
	if fs == nil {
		t.Fatalf("filesystem entry lost during strip: %s", out)
	}
	if fs["command"] != "npx" {
		t.Fatalf("filesystem.command not restored: %v", fs["command"])
	}
	if _, ok := fs["_agentlock_original"]; ok {
		t.Fatalf("_agentlock_original leaked into restored entry: %+v", fs)
	}
	if _, ok := fs["_agentlock"]; ok {
		t.Fatalf("_agentlock marker leaked into restored entry: %+v", fs)
	}
	env, _ := fs["env"].(map[string]any)
	if env["FOO"] != "bar" {
		t.Fatalf("user env lost on restore: %+v", env)
	}
}

// TestStripClaudeDesktopConfig_LeavesUnmarkedAgentlockUntouched: if a
// user happens to name their own server "agentlock" without our marker,
// strip must not touch it.
func TestStripClaudeDesktopConfig_LeavesUnmarkedAgentlockUntouched(t *testing.T) {
	cfg := `{"mcpServers":{"agentlock":{"command":"my-tool","args":[]}}}`
	out, removed, err := stripClaudeDesktopConfig([]byte(cfg))
	if err != nil {
		t.Fatalf("strip: %v", err)
	}
	if removed != 0 {
		t.Fatalf("expected 0 removals on unmarked entry, got %d (out=%s)", removed, out)
	}
}

// TestClaudeDesktopPlan_WarningsCarryEnforcementCaveat: the plan still
// emits a warning explaining what we DO and DON'T cover so dashboards
// and reports can't promise enforcement we can't deliver.
func TestClaudeDesktopPlan_WarningsCarryEnforcementCaveat(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	planBody := fmt.Sprintf(`{
		"session_id": %q,
		"harnesses": ["claude-desktop"],
		"daemon_url": "http://127.0.0.1:7878",
		"config_dir_override": "/tmp/fake-claude-desktop"
	}`, fx.sessionID)
	res, err := http.Post(fx.srv.URL+"/v1/install/plan", "application/json", strings.NewReader(planBody))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer res.Body.Close()
	var plan map[string]any
	_ = json.NewDecoder(res.Body).Decode(&plan)
	warnings, _ := plan["warnings"].([]any)
	if len(warnings) == 0 {
		t.Fatalf("expected at least one warning, got %+v", plan)
	}
}

// TestHarnessForPath_ClaudeDesktop ensures the manifest uninstall path
// dispatches strip ops back to stripClaudeDesktopConfig.
func TestHarnessForPath_ClaudeDesktop(t *testing.T) {
	cases := []struct{ path, want string }{
		{"/Users/x/Library/Application Support/Claude/claude_desktop_config.json", "claude-desktop"},
		{"/home/x/AppData/Roaming/Claude/claude_desktop_config.json", "claude-desktop"},
		{"/Users/x/.claude/settings.json", "claude-code"},
	}
	for _, c := range cases {
		got := harnessForPath(c.path)
		if got != c.want {
			t.Errorf("harnessForPath(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}
