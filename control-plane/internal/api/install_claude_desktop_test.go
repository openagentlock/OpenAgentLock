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
// dispatches strip ops back to the right helper. Both
// claude_desktop_config.json and extensions-installations.json must
// resolve to "claude-desktop" so the uninstall switch can find them.
func TestHarnessForPath_ClaudeDesktop(t *testing.T) {
	cases := []struct{ path, want string }{
		{"/Users/x/Library/Application Support/Claude/claude_desktop_config.json", "claude-desktop"},
		{"/home/x/AppData/Roaming/Claude/claude_desktop_config.json", "claude-desktop"},
		{"/Users/x/Library/Application Support/Claude/extensions-installations.json", "claude-desktop"},
		{"/Users/x/.claude/settings.json", "claude-code"},
	}
	for _, c := range cases {
		got := harnessForPath(c.path)
		if got != c.want {
			t.Errorf("harnessForPath(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

// --- Desktop Extensions registry tests --------------------------------

// sampleRegistry returns a canonical extensions-installations.json
// fixture matching the real shape Claude Desktop writes (registry-side
// metadata + nested manifest + mcp_config). One enabled extension and
// one disabled extension cover the wrap/skip dispatch. The fixture
// uses manifest_version "0.2" because that's what Anthropic's
// real-world Filesystem extension ships with — wrap must bump it to
// "0.3" so the _meta slot is schema-valid.
func sampleRegistry(t *testing.T) []byte {
	t.Helper()
	return []byte(`{
	  "extensions": {
	    "ant.dir.ant.anthropic.filesystem": {
	      "id": "ant.dir.ant.anthropic.filesystem",
	      "version": "0.2.2",
	      "hash": "504c1ac54eee79c4592c568e63790edf8713d12c8676507b6ce33a003172368c",
	      "installedAt": "2026-05-07T06:05:05.968Z",
	      "manifest": {
	        "manifest_version": "0.2",
	        "name": "Filesystem",
	        "server": {
	          "type": "node",
	          "entry_point": "dist/index.js",
	          "mcp_config": {
	            "command": "node",
	            "args": ["${__dirname}/dist/index.js", "${user_config.allowed_directories}"]
	          }
	        }
	      },
	      "signatureInfo": {"status": "unsigned"},
	      "source": "registry"
	    },
	    "ant.dir.disabled-thing": {
	      "id": "ant.dir.disabled-thing",
	      "version": "0.0.1",
	      "manifest": {
	        "manifest_version": "0.2",
	        "server": {
	          "mcp_config": {"command": "node", "args": ["server.js"]}
	        }
	      },
	      "source": "registry"
	    }
	  }
	}`)
}

// TestExtensionRegistry_WrapsEnabledEntries: one extension enabled,
// one disabled — only the enabled one gets wrapped, the disabled one
// is left alone.
func TestExtensionRegistry_WrapsEnabledEntries(t *testing.T) {
	settings := map[string]extensionSettings{
		"ant.dir.ant.anthropic.filesystem": {IsEnabled: true},
		"ant.dir.disabled-thing":           {IsEnabled: false},
	}
	out, err := mergeExtensionRegistry(sampleRegistry(t), "http://127.0.0.1:7878", "agentlock", settings)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	exts, _ := got["extensions"].(map[string]any)

	// Enabled extension must be wrapped.
	enabled, _ := exts["ant.dir.ant.anthropic.filesystem"].(map[string]any)
	manifest := enabled["manifest"].(map[string]any)
	if manifest["manifest_version"] != "0.3" {
		t.Fatalf("enabled extension manifest_version not bumped to 0.3: %v", manifest["manifest_version"])
	}
	mcp := manifest["server"].(map[string]any)["mcp_config"].(map[string]any)
	if mcp["command"] != "agentlock" {
		t.Fatalf("enabled extension command not wrapped: %v", mcp["command"])
	}
	args, _ := mcp["args"].([]any)
	if len(args) < 5 || args[0] != "mcp-proxy" || args[1] != "--name" || args[2] != "ant.dir.ant.anthropic.filesystem" || args[3] != "--" || args[4] != "node" {
		t.Fatalf("enabled extension args not wrapped correctly: %+v", args)
	}
	// Markers live under _meta.agentlock at the manifest root, not
	// inside mcp_config (the v0.3 schema is additionalProperties:false
	// on mcp_config).
	if _, ok := mcp["_agentlock_original"]; ok {
		t.Fatalf("legacy _agentlock_original leaked into mcp_config: %+v", mcp)
	}
	meta, _ := manifest["_meta"].(map[string]any)
	agentlockMeta, _ := meta["agentlock"].(map[string]any)
	if agentlockMeta == nil {
		t.Fatalf("enabled extension missing _meta.agentlock block")
	}
	if agentlockMeta["original_command"] != "node" {
		t.Fatalf("_meta.agentlock.original_command wrong: %v", agentlockMeta["original_command"])
	}
	if agentlockMeta["original_manifest_version"] != "0.2" {
		t.Fatalf("_meta.agentlock.original_manifest_version not stashed: %v", agentlockMeta["original_manifest_version"])
	}

	// Disabled extension must be untouched (still raw "node", no _meta).
	disabled, _ := exts["ant.dir.disabled-thing"].(map[string]any)
	dManifest := disabled["manifest"].(map[string]any)
	dmcp := dManifest["server"].(map[string]any)["mcp_config"].(map[string]any)
	if dmcp["command"] != "node" {
		t.Fatalf("disabled extension was wrapped (should be untouched): %v", dmcp)
	}
	if dManifest["manifest_version"] != "0.2" {
		t.Fatalf("disabled extension manifest_version was modified: %v", dManifest["manifest_version"])
	}
	if _, ok := dManifest["_meta"]; ok {
		t.Fatalf("disabled extension grew a _meta block: %+v", dManifest)
	}
}

// TestExtensionRegistry_PreservesUnknownKeys: registry entries carry
// audit trail fields (hash, installedAt, signatureInfo, source) that
// Claude Desktop uses for update checks and signature verification.
// Wrap + strip MUST round-trip these unchanged or we'd break Anthropic's
// trust path.
func TestExtensionRegistry_PreservesUnknownKeys(t *testing.T) {
	settings := map[string]extensionSettings{
		"ant.dir.ant.anthropic.filesystem": {IsEnabled: true},
		"ant.dir.disabled-thing":           {IsEnabled: false},
	}
	wrapped, err := mergeExtensionRegistry(sampleRegistry(t), "http://127.0.0.1:7878", "agentlock", settings)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	var got map[string]any
	_ = json.Unmarshal(wrapped, &got)
	exts := got["extensions"].(map[string]any)
	enabled := exts["ant.dir.ant.anthropic.filesystem"].(map[string]any)
	if enabled["hash"] != "504c1ac54eee79c4592c568e63790edf8713d12c8676507b6ce33a003172368c" {
		t.Fatalf("hash field lost: %v", enabled["hash"])
	}
	if enabled["installedAt"] != "2026-05-07T06:05:05.968Z" {
		t.Fatalf("installedAt field lost: %v", enabled["installedAt"])
	}
	if enabled["source"] != "registry" {
		t.Fatalf("source field lost: %v", enabled["source"])
	}
	sig, _ := enabled["signatureInfo"].(map[string]any)
	if sig == nil || sig["status"] != "unsigned" {
		t.Fatalf("signatureInfo lost: %v", enabled["signatureInfo"])
	}
}

// TestExtensionRegistry_Idempotent: re-running install (same daemon
// URL, same settings) on already-wrapped registry produces byte-
// identical output. Drift-correcting: a user who edited the wrapped
// args is reset to the canonical wrap on re-run.
func TestExtensionRegistry_Idempotent(t *testing.T) {
	settings := map[string]extensionSettings{
		"ant.dir.ant.anthropic.filesystem": {IsEnabled: true},
		"ant.dir.disabled-thing":           {IsEnabled: false},
	}
	first, err := mergeExtensionRegistry(sampleRegistry(t), "http://127.0.0.1:7878", "agentlock", settings)
	if err != nil {
		t.Fatalf("first merge: %v", err)
	}
	second, err := mergeExtensionRegistry(first, "http://127.0.0.1:7878", "agentlock", settings)
	if err != nil {
		t.Fatalf("second merge: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("non-idempotent re-wrap:\nfirst:  %s\nsecond: %s", first, second)
	}
}

// TestExtensionRegistry_StripRestoresOriginal: wrap then strip yields
// an mcp_config + manifest_version equivalent to the pre-wrap original.
// We don't compare byte-for-byte against sampleRegistry because the
// json.MarshalIndent roundtrip may reorder keys.
func TestExtensionRegistry_StripRestoresOriginal(t *testing.T) {
	// Mark the second extension explicitly disabled so it doesn't get
	// wrapped (default-when-missing is enabled, see collectExtensionSettings).
	settings := map[string]extensionSettings{
		"ant.dir.ant.anthropic.filesystem": {IsEnabled: true},
		"ant.dir.disabled-thing":           {IsEnabled: false},
	}
	wrapped, err := mergeExtensionRegistry(sampleRegistry(t), "http://127.0.0.1:7878", "agentlock", settings)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	stripped, removed, err := stripExtensionRegistry(wrapped)
	if err != nil {
		t.Fatalf("strip: %v", err)
	}
	if removed != 1 {
		t.Fatalf("expected 1 entry restored, got %d", removed)
	}

	var got map[string]any
	_ = json.Unmarshal(stripped, &got)
	exts := got["extensions"].(map[string]any)
	enabled := exts["ant.dir.ant.anthropic.filesystem"].(map[string]any)
	manifest := enabled["manifest"].(map[string]any)
	if manifest["manifest_version"] != "0.2" {
		t.Fatalf("strip didn't restore manifest_version: %v", manifest["manifest_version"])
	}
	mcp := manifest["server"].(map[string]any)["mcp_config"].(map[string]any)
	if mcp["command"] != "node" {
		t.Fatalf("strip didn't restore command: %v", mcp["command"])
	}
	if _, ok := manifest["_meta"]; ok {
		t.Fatalf("_meta leaked through strip: %+v", manifest)
	}
}

// TestExtensionRegistry_DisabledExtensionUnwindsExistingWrap: if an
// extension was wrapped at install time and then disabled by the user
// before re-running install, the next install pass should unwind the
// wrap so the on-disk manifest stops routing through agentlock.
func TestExtensionRegistry_DisabledExtensionUnwindsExistingWrap(t *testing.T) {
	enabledFirst := map[string]extensionSettings{
		"ant.dir.ant.anthropic.filesystem": {IsEnabled: true},
		"ant.dir.disabled-thing":           {IsEnabled: false},
	}
	wrapped, err := mergeExtensionRegistry(sampleRegistry(t), "http://127.0.0.1:7878", "agentlock", enabledFirst)
	if err != nil {
		t.Fatalf("first merge: %v", err)
	}
	// Now flip the formerly-enabled extension to disabled and re-merge.
	disabledNow := map[string]extensionSettings{
		"ant.dir.ant.anthropic.filesystem": {IsEnabled: false},
		"ant.dir.disabled-thing":           {IsEnabled: false},
	}
	out, err := mergeExtensionRegistry(wrapped, "http://127.0.0.1:7878", "agentlock", disabledNow)
	if err != nil {
		t.Fatalf("second merge: %v", err)
	}
	var got map[string]any
	_ = json.Unmarshal(out, &got)
	exts := got["extensions"].(map[string]any)
	fs := exts["ant.dir.ant.anthropic.filesystem"].(map[string]any)
	manifest := fs["manifest"].(map[string]any)
	mcp := manifest["server"].(map[string]any)["mcp_config"].(map[string]any)
	if mcp["command"] != "node" {
		t.Fatalf("disabling didn't unwind wrap: command=%v", mcp["command"])
	}
	if manifest["manifest_version"] != "0.2" {
		t.Fatalf("disabling didn't restore manifest_version: %v", manifest["manifest_version"])
	}
}

// --- Bundle manifest tests (the actual launch-source path) -----------

// sampleBundleManifest mirrors a real Claude Desktop Extension bundle
// manifest.json — the file under <config-dir>/Claude Extensions/<id>/
// that Claude Desktop reads to spawn the extension's MCP server.
// manifest_version "0.2" is what Anthropic's filesystem extension
// ships today; wrap must bump it to "0.3" so _meta validates.
func sampleBundleManifest(t *testing.T) []byte {
	t.Helper()
	return []byte(`{
	  "manifest_version": "0.2",
	  "name": "Filesystem",
	  "version": "0.2.2",
	  "description": "Read and write files.",
	  "author": {"name": "Anthropic"},
	  "server": {
	    "type": "node",
	    "entry_point": "dist/index.js",
	    "mcp_config": {
	      "command": "node",
	      "args": ["${__dirname}/dist/index.js", "${user_config.allowed_directories}"]
	    }
	  }
	}`)
}

// TestBundleManifest_WrapsAndBumpsManifestVersion is the load-bearing
// test for Desktop Extension gating: the wrap rewrites mcp_config to
// route through agentlock, parks the original under _meta.agentlock,
// and bumps manifest_version 0.2 → 0.3 so the _meta block is schema-
// valid against Claude Desktop's MCPB validator.
func TestBundleManifest_WrapsAndBumpsManifestVersion(t *testing.T) {
	out, ok := mergeBundleManifest(sampleBundleManifest(t),
		"ant.dir.ant.anthropic.filesystem",
		"http://127.0.0.1:7878", "agentlock", nil)
	if !ok {
		t.Fatalf("merge returned ok=false")
	}
	var manifest map[string]any
	if err := json.Unmarshal(out, &manifest); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if manifest["manifest_version"] != "0.3" {
		t.Fatalf("manifest_version not bumped to 0.3: %v", manifest["manifest_version"])
	}
	mcp := manifest["server"].(map[string]any)["mcp_config"].(map[string]any)
	if mcp["command"] != "agentlock" {
		t.Fatalf("command not rewritten to agentlock: %v", mcp["command"])
	}
	args, _ := mcp["args"].([]any)
	if len(args) < 5 || args[0] != "mcp-proxy" || args[3] != "--" || args[4] != "node" {
		t.Fatalf("args not wrapped correctly: %+v", args)
	}
	// No legacy markers under mcp_config (would fail v0.3 schema).
	if _, ok := mcp["_agentlock_original"]; ok {
		t.Fatalf("legacy _agentlock_original leaked into mcp_config: %+v", mcp)
	}
	agentlockMeta, _ := manifest["_meta"].(map[string]any)["agentlock"].(map[string]any)
	if agentlockMeta == nil {
		t.Fatalf("missing _meta.agentlock block")
	}
	if agentlockMeta["original_command"] != "node" {
		t.Fatalf("original_command not stashed: %v", agentlockMeta["original_command"])
	}
	if agentlockMeta["original_manifest_version"] != "0.2" {
		t.Fatalf("original_manifest_version not stashed: %v", agentlockMeta["original_manifest_version"])
	}
}

// TestBundleManifest_StripRestoresPreInstallShape: wrap + strip returns
// the manifest to its pre-wrap mcp_config + manifest_version, with no
// _meta.agentlock leakage.
func TestBundleManifest_StripRestoresPreInstallShape(t *testing.T) {
	wrapped, ok := mergeBundleManifest(sampleBundleManifest(t),
		"ant.dir.ant.anthropic.filesystem",
		"http://127.0.0.1:7878", "agentlock", nil)
	if !ok {
		t.Fatalf("merge returned ok=false")
	}
	stripped, removed, err := stripBundleManifest(wrapped)
	if err != nil {
		t.Fatalf("strip: %v", err)
	}
	if removed != 1 {
		t.Fatalf("expected 1 wrap undone, got %d", removed)
	}
	var manifest map[string]any
	_ = json.Unmarshal(stripped, &manifest)
	if manifest["manifest_version"] != "0.2" {
		t.Fatalf("strip didn't restore manifest_version: %v", manifest["manifest_version"])
	}
	mcp := manifest["server"].(map[string]any)["mcp_config"].(map[string]any)
	if mcp["command"] != "node" {
		t.Fatalf("strip didn't restore command: %v", mcp["command"])
	}
	if _, ok := manifest["_meta"]; ok {
		t.Fatalf("_meta leaked through strip: %+v", manifest)
	}
}

// TestBundleManifest_Idempotent: re-running merge on already-wrapped
// bytes produces byte-identical output. Drift-correcting too — a user
// who edited the wrapped command directly is reset to the canonical
// wrap on re-run because wrapManifest reads _meta.agentlock first to
// recover the real source state.
func TestBundleManifest_Idempotent(t *testing.T) {
	first, ok := mergeBundleManifest(sampleBundleManifest(t),
		"ant.dir.ant.anthropic.filesystem",
		"http://127.0.0.1:7878", "agentlock", nil)
	if !ok {
		t.Fatalf("first merge ok=false")
	}
	second, ok := mergeBundleManifest(first,
		"ant.dir.ant.anthropic.filesystem",
		"http://127.0.0.1:7878", "agentlock", nil)
	if !ok {
		t.Fatalf("second merge ok=false")
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("non-idempotent re-wrap:\nfirst:  %s\nsecond: %s", first, second)
	}
}

// TestBundleManifest_PreservesOtherMetaNamespaces: if the manifest
// already has _meta entries from another vendor, our wrap (and our
// strip) must leave them alone — _meta is a shared two-level
// namespace, so collisions would corrupt unrelated tooling state.
func TestBundleManifest_PreservesOtherMetaNamespaces(t *testing.T) {
	src := []byte(`{
	  "manifest_version": "0.3",
	  "name": "Filesystem",
	  "version": "0.2.2",
	  "description": "Read and write files.",
	  "author": {"name": "Anthropic"},
	  "_meta": {"some.other.tool": {"key": "value"}},
	  "server": {
	    "type": "node",
	    "entry_point": "dist/index.js",
	    "mcp_config": {
	      "command": "node",
	      "args": ["dist/index.js"]
	    }
	  }
	}`)
	wrapped, ok := mergeBundleManifest(src, "ext.id", "http://127.0.0.1:7878", "agentlock", nil)
	if !ok {
		t.Fatalf("merge ok=false")
	}
	var got map[string]any
	_ = json.Unmarshal(wrapped, &got)
	meta := got["_meta"].(map[string]any)
	if _, ok := meta["agentlock"]; !ok {
		t.Fatalf("our agentlock namespace missing")
	}
	other, _ := meta["some.other.tool"].(map[string]any)
	if other == nil || other["key"] != "value" {
		t.Fatalf("unrelated _meta namespace lost: %+v", meta)
	}

	stripped, _, err := stripBundleManifest(wrapped)
	if err != nil {
		t.Fatalf("strip: %v", err)
	}
	var after map[string]any
	_ = json.Unmarshal(stripped, &after)
	afterMeta, _ := after["_meta"].(map[string]any)
	if afterMeta == nil {
		t.Fatalf("strip removed entire _meta block (should keep other namespaces): %s", stripped)
	}
	if _, ok := afterMeta["agentlock"]; ok {
		t.Fatalf("strip left our agentlock namespace behind: %+v", afterMeta)
	}
	if afterMeta["some.other.tool"].(map[string]any)["key"] != "value" {
		t.Fatalf("strip mutated unrelated _meta namespace: %+v", afterMeta)
	}
}

// TestBundleManifest_PreservesAlreadyV03: a manifest already at v0.3
// must NOT have its manifest_version touched, and strip must NOT
// downgrade it (we only restore manifest_version when we bumped it).
func TestBundleManifest_PreservesAlreadyV03(t *testing.T) {
	src := []byte(`{
	  "manifest_version": "0.3",
	  "name": "X", "version": "1", "description": "x",
	  "author": {"name": "x"},
	  "server": {"type": "node", "entry_point": "i.js",
	    "mcp_config": {"command": "node", "args": ["i.js"]}}
	}`)
	wrapped, ok := mergeBundleManifest(src, "ext.id", "http://127.0.0.1:7878", "agentlock", nil)
	if !ok {
		t.Fatalf("merge ok=false")
	}
	var got map[string]any
	_ = json.Unmarshal(wrapped, &got)
	if got["manifest_version"] != "0.3" {
		t.Fatalf("manifest_version changed unnecessarily: %v", got["manifest_version"])
	}
	agentlockMeta := got["_meta"].(map[string]any)["agentlock"].(map[string]any)
	if _, ok := agentlockMeta["original_manifest_version"]; ok {
		t.Fatalf("stashed original_manifest_version when no bump happened: %+v", agentlockMeta)
	}

	stripped, _, _ := stripBundleManifest(wrapped)
	var after map[string]any
	_ = json.Unmarshal(stripped, &after)
	if after["manifest_version"] != "0.3" {
		t.Fatalf("strip downgraded a v0.3 manifest: %v", after["manifest_version"])
	}
}

// TestBundleManifest_BumpsLegacyDxtVersion: bundles that ship with the
// deprecated dxt_version field (e.g. Anthropic's own Control Chrome
// publishes dxt_version "0.1" with no manifest_version) must have it
// bumped in lockstep with manifest_version. The v0.3 schema pins
// dxt_version to const "0.3" when present, so leaving a stale value
// causes Claude Desktop to reject the whole manifest with
// `dxt_version: Invalid literal value`. Strip restores the original.
func TestBundleManifest_BumpsLegacyDxtVersion(t *testing.T) {
	src := []byte(`{
	  "dxt_version": "0.1",
	  "name": "Control Chrome", "version": "0.1.6", "description": "x",
	  "author": {"name": "Anthropic"},
	  "server": {"type": "node", "entry_point": "server/index.js",
	    "mcp_config": {"command": "node", "args": ["server/index.js"]}}
	}`)
	wrapped, ok := mergeBundleManifest(src, "ext.id", "http://127.0.0.1:7878", "agentlock", nil)
	if !ok {
		t.Fatalf("merge ok=false")
	}
	var got map[string]any
	_ = json.Unmarshal(wrapped, &got)
	if got["dxt_version"] != "0.3" {
		t.Fatalf("dxt_version not bumped: %v", got["dxt_version"])
	}
	if got["manifest_version"] != "0.3" {
		t.Fatalf("manifest_version not added on legacy-dxt bundle: %v", got["manifest_version"])
	}
	agentlockMeta := got["_meta"].(map[string]any)["agentlock"].(map[string]any)
	if agentlockMeta["original_dxt_version"] != "0.1" {
		t.Fatalf("original_dxt_version not stashed: %v", agentlockMeta["original_dxt_version"])
	}
	// manifest_version was originally absent on this bundle.
	if a, _ := agentlockMeta["original_manifest_version_absent"].(bool); !a {
		t.Fatalf("original_manifest_version_absent flag missing: %+v", agentlockMeta)
	}

	stripped, _, err := stripBundleManifest(wrapped)
	if err != nil {
		t.Fatalf("strip: %v", err)
	}
	var after map[string]any
	_ = json.Unmarshal(stripped, &after)
	if after["dxt_version"] != "0.1" {
		t.Fatalf("strip didn't restore dxt_version: %v", after["dxt_version"])
	}
	if _, ok := after["manifest_version"]; ok {
		t.Fatalf("strip left bumped manifest_version on a bundle that didn't have one: %+v", after)
	}
}

// TestBundleManifest_DisabledUnwindsWrap: an extension that's flipped
// to disabled in the settings sidecar should have its wrap unwound.
// An already-clean disabled extension should produce no write op.
func TestBundleManifest_DisabledUnwindsWrap(t *testing.T) {
	wrapped, ok := mergeBundleManifest(sampleBundleManifest(t),
		"ext.id", "http://127.0.0.1:7878", "agentlock", nil)
	if !ok {
		t.Fatalf("merge ok=false")
	}
	out, ok := mergeBundleManifest(wrapped, "ext.id",
		"http://127.0.0.1:7878", "agentlock",
		map[string]extensionSettings{"ext.id": {IsEnabled: false}})
	if !ok {
		t.Fatalf("disable-pass merge ok=false")
	}
	var got map[string]any
	_ = json.Unmarshal(out, &got)
	mcp := got["server"].(map[string]any)["mcp_config"].(map[string]any)
	if mcp["command"] != "node" {
		t.Fatalf("disable didn't restore command: %v", mcp["command"])
	}
	// Already-clean disabled = no-op (caller writes no file op).
	if _, ok := mergeBundleManifest(out, "ext.id", "http://127.0.0.1:7878",
		"agentlock", map[string]extensionSettings{"ext.id": {IsEnabled: false}}); ok {
		t.Fatalf("expected no-op for already-clean disabled extension")
	}
}
