package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func postCodexPre(t *testing.T, fx gateFixture, body string) (*http.Response, map[string]any) {
	t.Helper()
	res, err := http.Post(fx.srv.URL+"/v1/hooks/codex/pre-tool-use", "application/json", strings.NewReader(body))
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

func TestCodexPreToolUse_AllowsBenignBash(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	body := `{
		"session_id": "codex-sess-001",
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_use_id": "t_01",
		"turn_id": "turn_01",
		"model": "gpt-5-codex",
		"tool_input": {"command": "ls -la"}
	}`
	res, out := postCodexPre(t, fx, body)
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

func TestCodexPreToolUse_DeniesDestructiveBash(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	body := `{
		"session_id": "codex-sess-002",
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_use_id": "t_02",
		"turn_id": "turn_02",
		"tool_input": {"command": "rm -rf /tmp/x"}
	}`
	res, out := postCodexPre(t, fx, body)
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

	// Ledger must record the deny tagged source=codex.
	entries, _ := fx.store.ListLedger(context.Background())
	hit := false
	for _, e := range entries {
		if e.ToolUseID == "t_02" && e.Source == "codex" && e.Verdict == "deny" && e.RuleID == "rogue.destructive-bash" {
			hit = true
			break
		}
	}
	if !hit {
		t.Fatalf("expected codex deny ledger entry: %+v", entries)
	}
}

func TestCodexPreToolUse_AutoCreatesUnattestedSession(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	body := `{
		"session_id": "brand-new-codex-session",
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_use_id": "t_03",
		"tool_input": {"command": "echo hi"}
	}`
	_, _ = postCodexPre(t, fx, body)

	sess, err := fx.store.GetSession(context.Background(), "brand-new-codex-session")
	if err != nil {
		t.Fatalf("auto-session not created: %v", err)
	}
	if sess.Signer != "none" {
		t.Fatalf("auto-session should be unattested signer=none, got %q", sess.Signer)
	}
	if sess.Harness != "codex" {
		t.Fatalf("auto-session should be tagged codex, got %q", sess.Harness)
	}
}

func TestCodexPreToolUse_MonitorModeSuppressesDeny(t *testing.T) {
	t.Setenv("AGENTLOCK_MODE", "monitor")
	fx := newGateFixture(t, enforcePolicyYAML)
	body := `{
		"session_id": "codex-sess-004",
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_use_id": "t_04",
		"tool_input": {"command": "rm -rf /tmp/x"}
	}`
	res, out := postCodexPre(t, fx, body)
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

	entries, _ := fx.store.ListLedger(context.Background())
	hit := false
	for _, e := range entries {
		if e.ToolUseID == "t_04" && e.Verdict == "deny" && e.RuleID == "rogue.destructive-bash" {
			hit = true
			break
		}
	}
	if !hit {
		t.Fatalf("expected deny ledger entry despite monitor allow response: %+v", entries)
	}
}

func TestCodexPreToolUse_MissingRequiredFields(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	res, _ := postCodexPre(t, fx, `{"session_id":"x"}`)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", res.StatusCode)
	}
}

func TestCodexStop_EndsSession(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	pre := `{
		"session_id": "codex-stop-test",
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_use_id": "t_05",
		"tool_input": {"command": "ls"}
	}`
	_, _ = postCodexPre(t, fx, pre)

	stop := `{"session_id":"codex-stop-test","hook_event_name":"Stop"}`
	res, err := http.Post(fx.srv.URL+"/v1/hooks/codex/stop", "application/json", strings.NewReader(stop))
	if err != nil {
		t.Fatalf("POST stop: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d body=%s", res.StatusCode, buf.String())
	}
	active, _ := fx.store.IsSessionActive(context.Background(), "codex-stop-test")
	if active {
		t.Fatalf("session should be ended")
	}
}

func TestCodexPostToolUse_RecordsOutcome(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	body := `{
		"session_id": "codex-post-001",
		"hook_event_name": "PostToolUse",
		"tool_name": "Bash",
		"tool_use_id": "t_post_001",
		"turn_id": "turn_p1",
		"tool_input": {"command": "ls"},
		"tool_response": "total 0"
	}`
	res, err := http.Post(
		fx.srv.URL+"/v1/hooks/codex/post-tool-use",
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
		if e.ToolUseID == "t_post_001" && e.Source == "codex" && e.Verdict == "complete" {
			hit = true
			break
		}
	}
	if !hit {
		t.Fatalf("missing complete PostToolUse ledger entry: %+v", entries)
	}
}

func TestCodexSessionStart_CreatesSession(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	body := `{
		"session_id": "codex-session-start-001",
		"hook_event_name": "SessionStart",
		"model": "gpt-5-codex",
		"cwd": "/tmp",
		"transcript_path": "/tmp/transcript.jsonl"
	}`
	res, err := http.Post(fx.srv.URL+"/v1/hooks/codex/session-start", "application/json", strings.NewReader(body))
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

	sess, err := fx.store.GetSession(context.Background(), "codex-session-start-001")
	if err != nil {
		t.Fatalf("session not created: %v", err)
	}
	if sess.Harness != "codex" {
		t.Fatalf("harness = %q", sess.Harness)
	}

	entries, _ := fx.store.ListLedger(context.Background())
	hit := false
	for _, e := range entries {
		if e.ToolUseID == "codex.session-start" && e.Source == "codex" {
			hit = true
			break
		}
	}
	if !hit {
		t.Fatalf("missing codex.session-start ledger entry: %+v", entries)
	}
}

// Mirror of TestClaudePreToolUse_DenyConcatenatesNudge for the Codex
// hook path. The daemon must inject the `→ Suggested: <hint>` suffix
// into the Codex reply's reason fields whenever the firing rule carries
// a nudge.
func TestCodexPreToolUse_DenyConcatenatesNudge(t *testing.T) {
	fx := newGateFixture(t, nudgePolicyYAML)
	body := `{
		"session_id": "codex-sess-nudge",
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_use_id": "codex_nudge",
		"turn_id": "turn_nudge",
		"tool_input": {"command": "rm -rf /tmp/x"}
	}`
	res, out := postCodexPre(t, fx, body)
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

	// Allow path stays untouched — no suggested-line on benign commands.
	allowBody := `{
		"session_id": "codex-sess-nudge-allow",
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_use_id": "codex_nudge_allow",
		"turn_id": "turn_nudge_allow",
		"tool_input": {"command": "ls -la"}
	}`
	_, allowOut := postCodexPre(t, fx, allowBody)
	allowSpec, _ := allowOut["hookSpecificOutput"].(map[string]any)
	allowReason, _ := allowSpec["permissionDecisionReason"].(string)
	if strings.Contains(allowReason, "→ Suggested:") {
		t.Fatalf("allow reason must not carry nudge: %q", allowReason)
	}
}

// Mirror of TestClaudePreToolUse_FirewallEscalatesPolicyMonitorMatch
// (hooks_claude_test.go) — daemon=firewall must re-escalate a
// policy-monitor match back to deny on the codex hook path too.
func TestCodexPreToolUse_FirewallEscalatesPolicyMonitorMatch(t *testing.T) {
	t.Setenv("AGENTLOCK_MODE", "")
	runtimeMode.Store("firewall")
	t.Cleanup(func() { runtimeMode.Store("") })

	fx := newGateFixture(t, monitorPolicyYAML)
	body := `{
		"session_id": "codex-sess-escalate",
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_use_id": "codex_escalate",
		"turn_id": "turn_escalate",
		"tool_input": {"command": "rm -rf /tmp/x"}
	}`
	res, out := postCodexPre(t, fx, body)
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

	entries, _ := fx.store.ListLedger(context.Background())
	hit := false
	for _, e := range entries {
		if e.ToolUseID == "codex_escalate" && e.Verdict == "deny" && e.RuleID == "rogue.destructive-bash" {
			hit = true
			break
		}
	}
	if !hit {
		t.Fatalf("expected codex deny ledger entry for escalated match: %+v", entries)
	}
}
