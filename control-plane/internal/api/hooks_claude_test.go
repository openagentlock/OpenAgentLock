package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func postClaudePre(t *testing.T, fx gateFixture, body string) (*http.Response, map[string]any) {
	t.Helper()
	res, err := http.Post(fx.srv.URL+"/v1/hooks/claude-code/pre-tool-use", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	var out map[string]any
	if res.Header.Get("Content-Type") == "application/json" {
		_ = json.NewDecoder(res.Body).Decode(&out)
	}
	_ = res.Body.Close()
	return res, out
}

func TestClaudePreToolUse_AllowsBenignBash(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	body := `{
		"session_id": "claude-sess-001",
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_use_id": "toolu_01",
		"tool_input": {"command": "ls -la"}
	}`
	res, out := postClaudePre(t, fx, body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if out["continue"] != true {
		t.Fatalf("continue = %v", out["continue"])
	}
	spec, _ := out["hookSpecificOutput"].(map[string]any)
	if spec["permissionDecision"] != "allow" {
		t.Fatalf("decision = %v", spec)
	}
}

func TestClaudePreToolUse_DeniesDestructiveBash(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	body := `{
		"session_id": "claude-sess-002",
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_use_id": "toolu_02",
		"tool_input": {"command": "rm -rf /tmp/x"}
	}`
	res, out := postClaudePre(t, fx, body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if out["continue"] != false {
		t.Fatalf("continue should be false on deny: %v", out)
	}
	spec, _ := out["hookSpecificOutput"].(map[string]any)
	if spec["permissionDecision"] != "deny" {
		t.Fatalf("decision = %v", spec)
	}
	sr, ok := out["stopReason"].(string)
	if !ok || sr == "" {
		t.Fatalf("expected non-empty stopReason, got %v", out["stopReason"])
	}
}

func TestClaudePreToolUse_AutoCreatesUnattestedSession(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	// fx.sessionID exists; use a fresh Claude-side id instead.
	body := `{
		"session_id": "brand-new-claude-session",
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_use_id": "toolu_03",
		"tool_input": {"command": "echo hi"}
	}`
	_, _ = postClaudePre(t, fx, body)

	sess, err := fx.store.GetSession(context.Background(), "brand-new-claude-session")
	if err != nil {
		t.Fatalf("auto-session not created: %v", err)
	}
	if sess.Signer != "none" {
		t.Fatalf("auto-session should be unattested signer=none, got %q", sess.Signer)
	}
}

func TestClaudePreToolUse_MonitorModeSuppressesDeny(t *testing.T) {
	t.Setenv("AGENTLOCK_MODE", "monitor")
	fx := newGateFixture(t, enforcePolicyYAML)
	body := `{
		"session_id": "claude-sess-004",
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_use_id": "toolu_04",
		"tool_input": {"command": "rm -rf /tmp/x"}
	}`
	res, out := postClaudePre(t, fx, body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if out["continue"] != true {
		t.Fatalf("monitor mode must let deny through: %v", out)
	}
	spec, _ := out["hookSpecificOutput"].(map[string]any)
	if spec["permissionDecision"] != "allow" {
		t.Fatalf("monitor mode must flip decision to allow, got %v", spec)
	}

	// Ledger preserves the original deny verdict so audit trail survives.
	entries, _ := fx.store.ListLedger(context.Background())
	var hit bool
	for _, e := range entries {
		if e.ToolUseID == "toolu_04" && e.Verdict == "deny" && e.RuleID == "rogue.destructive-bash" {
			hit = true
			break
		}
	}
	if !hit {
		t.Fatalf("expected deny ledger entry despite monitor-mode allow response: %+v", entries)
	}
}

func TestClaudePreToolUse_MissingRequiredFields(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	res, _ := postClaudePre(t, fx, `{"session_id":"x"}`)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", res.StatusCode)
	}
}

func TestClaudeStop_EndsSession(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	// Auto-create via a pre-tool-use first.
	pre := `{
		"session_id": "claude-stop-test",
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_use_id": "toolu_05",
		"tool_input": {"command": "ls"}
	}`
	_, _ = postClaudePre(t, fx, pre)

	stop := `{"session_id":"claude-stop-test","hook_event_name":"Stop"}`
	res, err := http.Post(fx.srv.URL+"/v1/hooks/claude-code/stop", "application/json", strings.NewReader(stop))
	if err != nil {
		t.Fatalf("POST stop: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d body=%s", res.StatusCode, buf.String())
	}
	active, _ := fx.store.IsSessionActive(context.Background(), "claude-stop-test")
	if active {
		t.Fatalf("session should be ended")
	}
}

func TestClaudePostToolUse_RecordsOutcome(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	// tool_response as a plain string is the success shape Claude Code
	// emits for read-style tools and well-behaved Bash. No is_error
	// member, no error member -> verdict=complete.
	body := `{
		"session_id": "claude-post-001",
		"hook_event_name": "PostToolUse",
		"tool_name": "Bash",
		"tool_use_id": "toolu_post_001",
		"tool_input": {"command": "ls"},
		"tool_response": "total 0"
	}`
	res, err := http.Post(
		fx.srv.URL+"/v1/hooks/claude-code/post-tool-use",
		"application/json",
		strings.NewReader(body),
	)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d body=%s", res.StatusCode, buf.String())
	}

	entries, _ := fx.store.ListLedger(context.Background())
	hit := false
	for _, e := range entries {
		if e.ToolUseID == "toolu_post_001" && e.Source == "claude-code" && e.Verdict == "complete" {
			hit = true
			break
		}
	}
	if !hit {
		t.Fatalf("missing complete PostToolUse ledger entry: %+v", entries)
	}
}

func TestClaudePostToolUse_RecordsFailure(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	// Anthropic-canonical tool_result failure shape: is_error: true
	// inside tool_response. The handler reads it via summarizeToolResponse.
	body := `{
		"session_id": "claude-post-002",
		"hook_event_name": "PostToolUse",
		"tool_name": "Bash",
		"tool_use_id": "toolu_post_002",
		"tool_input": {"command": "false"},
		"tool_response": {"content": "exit 1", "is_error": true}
	}`
	res, err := http.Post(
		fx.srv.URL+"/v1/hooks/claude-code/post-tool-use",
		"application/json",
		strings.NewReader(body),
	)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	res.Body.Close()

	entries, _ := fx.store.ListLedger(context.Background())
	hit := false
	for _, e := range entries {
		if e.ToolUseID == "toolu_post_002" && e.Verdict == "failure" {
			hit = true
			break
		}
	}
	if !hit {
		t.Fatalf("expected failure verdict in ledger: %+v", entries)
	}
}

func TestClaudeSessionStart_CreatesSession(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	body := `{
		"session_id": "claude-session-start-001",
		"hook_event_name": "SessionStart",
		"source": "startup",
		"cwd": "/tmp",
		"transcript_path": "/tmp/transcript.jsonl"
	}`
	res, err := http.Post(fx.srv.URL+"/v1/hooks/claude-code/session-start", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST session-start: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d body=%s", res.StatusCode, buf.String())
	}
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	if out["continue"] != true {
		t.Fatalf("continue = %v", out["continue"])
	}

	// Session should now exist, tagged claude-code.
	sess, err := fx.store.GetSession(context.Background(), "claude-session-start-001")
	if err != nil {
		t.Fatalf("session not created: %v", err)
	}
	if sess.Harness != "claude-code" {
		t.Fatalf("harness = %q", sess.Harness)
	}

	// Ledger must carry a claude.session-start entry.
	entries, _ := fx.store.ListLedger(context.Background())
	hit := false
	for _, e := range entries {
		if e.ToolUseID == "claude.session-start" && e.Source == "claude-code" {
			hit = true
			break
		}
	}
	if !hit {
		t.Fatalf("missing claude.session-start ledger entry: %+v", entries)
	}
}

func TestGateCheck_MonitorMode_SuppressesDeny(t *testing.T) {
	t.Setenv("AGENTLOCK_MODE", "monitor")
	fx := newGateFixture(t, enforcePolicyYAML)
	body := `{
		"session_id": "` + fx.sessionID + `",
		"source": "claude-code",
		"tool": "Bash",
		"input": {"command": "rm -rf /x"}
	}`
	res, out := postGateCheck(t, fx.srv, body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if out["verdict"] != "allow" {
		t.Fatalf("verdict should be allow under monitor mode, got %v", out["verdict"])
	}
	if out["monitor"] != true {
		t.Fatalf("monitor flag missing: %v", out)
	}
}

// Default daemon policy is monitor mode. When the user toggles the
// runtime override to firewall, a destructive-bash command that the
// policy would have allow-with-MonitorMatch must escalate to deny.
// This is the bug the dashboard mode toggle exposed: switching back to
// firewall left the deny suppressed because the eval result was already
// allow + MonitorMatch and nothing re-applied the original verdict.
const monitorPolicyYAML = `
version: 1
mode: monitor
defaults:
  bash: allow
gates:
  - id: rogue.destructive-bash
    match:
      tool: Bash
      any_command_regex:
        - 'rm\s+-rf\b'
        - 'git\s+push\s+.*--force'
    evaluate:
      - kind: always
        action: deny
`

func TestGateCheck_FirewallEscalatesPolicyMonitorMatch(t *testing.T) {
	t.Setenv("AGENTLOCK_MODE", "")
	runtimeMode.Store("firewall")
	t.Cleanup(func() { runtimeMode.Store("") })

	fx := newGateFixture(t, monitorPolicyYAML)
	body := `{
		"session_id": "` + fx.sessionID + `",
		"source": "claude-code",
		"tool": "Bash",
		"input": {"command": "rm -rf /tmp/x"}
	}`
	res, out := postGateCheck(t, fx.srv, body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if out["verdict"] != "deny" {
		t.Fatalf("daemon firewall must escalate policy-monitor match to deny, got %v", out["verdict"])
	}
	if out["rule_id"] != "rogue.destructive-bash" {
		t.Fatalf("rule_id = %v, want rogue.destructive-bash", out["rule_id"])
	}
}

// TestClaudePreToolUse_DenyConcatenatesNudge verifies that when a policy
// rule fires with a `nudge:` clause, the daemon's deny response carries
// both the original "matched rule X (deny)" reason AND the literal
// "→ Suggested: <hint>" suffix in BOTH permissionDecisionReason AND
// stopReason — these are the only channels the harness uses to surface
// the explanation to the model. The exact "→ Suggested: " prefix is the
// stable contract downstream consumers (CLI shim, dashboard) match on.
func TestClaudePreToolUse_DenyConcatenatesNudge(t *testing.T) {
	fx := newGateFixture(t, nudgePolicyYAML)
	body := `{
		"session_id": "claude-sess-nudge",
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_use_id": "toolu_nudge",
		"tool_input": {"command": "rm -rf /tmp/x"}
	}`
	res, out := postClaudePre(t, fx, body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	spec, _ := out["hookSpecificOutput"].(map[string]any)
	if spec["permissionDecision"] != "deny" {
		t.Fatalf("decision = %v, want deny", spec)
	}
	reason, _ := spec["permissionDecisionReason"].(string)
	if !strings.Contains(reason, "matched rule safety.rm-suggest-trash (deny)") {
		t.Fatalf("permissionDecisionReason missing original reason: %q", reason)
	}
	if !strings.Contains(reason, "→ Suggested: use trash instead") {
		t.Fatalf("permissionDecisionReason missing nudge suffix: %q", reason)
	}
	stop, _ := out["stopReason"].(string)
	if !strings.Contains(stop, "→ Suggested: use trash instead") {
		t.Fatalf("stopReason missing nudge suffix: %q", stop)
	}

	// Allow path: a benign command must NOT carry the suggested-line.
	allowBody := `{
		"session_id": "claude-sess-nudge-allow",
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_use_id": "toolu_nudge_allow",
		"tool_input": {"command": "ls -la"}
	}`
	_, allowOut := postClaudePre(t, fx, allowBody)
	allowSpec, _ := allowOut["hookSpecificOutput"].(map[string]any)
	allowReason, _ := allowSpec["permissionDecisionReason"].(string)
	if strings.Contains(allowReason, "→ Suggested:") {
		t.Fatalf("allow reason must not carry nudge: %q", allowReason)
	}
}

func TestClaudePreToolUse_FirewallEscalatesPolicyMonitorMatch(t *testing.T) {
	t.Setenv("AGENTLOCK_MODE", "")
	runtimeMode.Store("firewall")
	t.Cleanup(func() { runtimeMode.Store("") })

	fx := newGateFixture(t, monitorPolicyYAML)
	body := `{
		"session_id": "claude-sess-escalate",
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_use_id": "toolu_escalate",
		"tool_input": {"command": "rm -rf /tmp/x"}
	}`
	res, out := postClaudePre(t, fx, body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if out["continue"] != false {
		t.Fatalf("daemon firewall must deny: continue=%v out=%v", out["continue"], out)
	}
	spec, _ := out["hookSpecificOutput"].(map[string]any)
	if spec["permissionDecision"] != "deny" {
		t.Fatalf("permissionDecision = %v, want deny", spec["permissionDecision"])
	}
}
