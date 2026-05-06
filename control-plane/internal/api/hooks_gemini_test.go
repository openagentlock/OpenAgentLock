package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func postGeminiPre(t *testing.T, fx gateFixture, body string) (*http.Response, map[string]any) {
	t.Helper()
	res, err := http.Post(fx.srv.URL+"/v1/hooks/gemini/pre-tool-use", "application/json", strings.NewReader(body))
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

func TestGeminiPreToolUse_AllowsBenignBash(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	body := `{
		"session_id": "gemini-sess-001",
		"hook_event_name": "BeforeTool",
		"tool_name": "Bash",
		"cwd": "/tmp",
		"tool_input": {"command": "ls -la"}
	}`
	res, out := postGeminiPre(t, fx, body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if out["continue"] != true {
		t.Fatalf("continue = %v", out["continue"])
	}
	if out["decision"] != "allow" {
		t.Fatalf("decision = %v, want allow", out["decision"])
	}
}

func TestGeminiPreToolUse_DeniesDestructiveBash(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	body := `{
		"session_id": "gemini-sess-002",
		"hook_event_name": "BeforeTool",
		"tool_name": "Bash",
		"tool_input": {"command": "rm -rf /tmp/x"}
	}`
	res, out := postGeminiPre(t, fx, body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if out["continue"] != false {
		t.Fatalf("continue should be false on deny: %v", out)
	}
	if out["decision"] != "deny" {
		t.Fatalf("decision = %v, want deny", out["decision"])
	}
	reason, _ := out["reason"].(string)
	if reason == "" {
		t.Fatalf("expected non-empty reason, got %v", out["reason"])
	}
	stop, _ := out["stopReason"].(string)
	if stop == "" {
		t.Fatalf("expected stopReason to mirror reason on deny: %v", out)
	}

	// Ledger must record the deny tagged source=gemini. Gemini doesn't
	// supply tool_use_id, so we look up by the synthesized id.
	entries, _ := fx.store.ListLedger(context.Background())
	hit := false
	for _, e := range entries {
		if e.ToolUseID == "gemini.pre-tool-use" && e.Source == "gemini" && e.Verdict == "deny" && e.RuleID == "rogue.destructive-bash" {
			hit = true
			break
		}
	}
	if !hit {
		t.Fatalf("expected gemini deny ledger entry: %+v", entries)
	}
}

func TestGeminiPreToolUse_AutoCreatesUnattestedSession(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	body := `{
		"session_id": "brand-new-gemini-session",
		"hook_event_name": "BeforeTool",
		"tool_name": "Bash",
		"tool_input": {"command": "echo hi"}
	}`
	_, _ = postGeminiPre(t, fx, body)

	sess, err := fx.store.GetSession(context.Background(), "brand-new-gemini-session")
	if err != nil {
		t.Fatalf("auto-session not created: %v", err)
	}
	if sess.Signer != "none" {
		t.Fatalf("auto-session should be unattested signer=none, got %q", sess.Signer)
	}
	if sess.Harness != "gemini" {
		t.Fatalf("auto-session should be tagged gemini, got %q", sess.Harness)
	}
}

func TestGeminiPreToolUse_MonitorModeSuppressesDeny(t *testing.T) {
	t.Setenv("AGENTLOCK_MODE", "monitor")
	fx := newGateFixture(t, enforcePolicyYAML)
	body := `{
		"session_id": "gemini-sess-004",
		"hook_event_name": "BeforeTool",
		"tool_name": "Bash",
		"tool_input": {"command": "rm -rf /tmp/x"}
	}`
	res, out := postGeminiPre(t, fx, body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if out["continue"] != true {
		t.Fatalf("monitor mode must let deny through: %v", out)
	}
	if out["decision"] != "allow" {
		t.Fatalf("monitor mode must flip decision to allow, got %v", out["decision"])
	}

	entries, _ := fx.store.ListLedger(context.Background())
	hit := false
	for _, e := range entries {
		if e.ToolUseID == "gemini.pre-tool-use" && e.Verdict == "deny" && e.RuleID == "rogue.destructive-bash" {
			hit = true
			break
		}
	}
	if !hit {
		t.Fatalf("expected deny ledger entry despite monitor allow response: %+v", entries)
	}
}

func TestGeminiPreToolUse_MissingRequiredFields(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	res, _ := postGeminiPre(t, fx, `{"session_id":"x"}`)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", res.StatusCode)
	}
}

func TestGeminiPreToolUse_NormalizesNestedMCPContextURLAndDeniesDisallowedHost(t *testing.T) {
	fx := newGateFixture(t, mcpNetEgressPolicyYAML)
	body := `{
		"session_id": "gemini-mcp-url-deny",
		"hook_event_name": "BeforeTool",
		"tool_name": "mcp_server_fetch",
		"tool_input": {"query": "x"},
		"mcp_context": {
			"server": {
				"transport_url": "https://evil.biz/mcp"
			}
		}
	}`

	res, out := postGeminiPre(t, fx, body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if out["continue"] != false {
		t.Fatalf("continue should be false on disallowed MCP URL: %v", out)
	}
	if out["decision"] != "deny" {
		t.Fatalf("decision = %v, want deny", out["decision"])
	}

	entries, _ := fx.store.ListLedger(context.Background())
	for _, e := range entries {
		if e.ToolUseID == "gemini.pre-tool-use" && e.Source == "gemini" {
			if e.RuleID != "rogue.net-egress" || e.Verdict != "deny" {
				t.Fatalf("ledger verdict = %s/%s, want rogue.net-egress/deny", e.RuleID, e.Verdict)
			}
			if e.Input["url"] != "https://evil.biz/mcp" {
				t.Fatalf("ledger matcher url = %q, want normalized URL", e.Input["url"])
			}
			return
		}
	}
	t.Fatalf("missing gemini pre-tool ledger entry: %+v", entries)
}

func TestGeminiStop_EndsSession(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	pre := `{
		"session_id": "gemini-stop-test",
		"hook_event_name": "BeforeTool",
		"tool_name": "Bash",
		"tool_input": {"command": "ls"}
	}`
	_, _ = postGeminiPre(t, fx, pre)

	stop := `{"session_id":"gemini-stop-test","hook_event_name":"SessionEnd","reason":"exit"}`
	res, err := http.Post(fx.srv.URL+"/v1/hooks/gemini/stop", "application/json", strings.NewReader(stop))
	if err != nil {
		t.Fatalf("POST stop: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d body=%s", res.StatusCode, buf.String())
	}
	active, _ := fx.store.IsSessionActive(context.Background(), "gemini-stop-test")
	if active {
		t.Fatalf("session should be ended")
	}
}

func TestGeminiPostToolUse_RecordsCompletion(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	body := `{
		"session_id": "gemini-post-001",
		"hook_event_name": "AfterTool",
		"tool_name": "Bash",
		"tool_input": {"command": "ls"},
		"tool_response": {"llmContent": "total 0", "returnDisplay": "total 0"}
	}`
	res, err := http.Post(
		fx.srv.URL+"/v1/hooks/gemini/post-tool-use",
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
		if e.ToolUseID == "gemini.post-tool-use" && e.Source == "gemini" && e.Verdict == "complete" {
			hit = true
			break
		}
	}
	if !hit {
		t.Fatalf("missing complete AfterTool ledger entry: %+v", entries)
	}
}

func TestGeminiPostToolUse_RecordsFailureWhenErrorField(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	body := `{
		"session_id": "gemini-post-fail",
		"hook_event_name": "AfterTool",
		"tool_name": "Bash",
		"tool_input": {"command": "false"},
		"tool_response": {"error": "command exited 1"}
	}`
	res, err := http.Post(
		fx.srv.URL+"/v1/hooks/gemini/post-tool-use",
		"application/json",
		strings.NewReader(body),
	)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}

	entries, _ := fx.store.ListLedger(context.Background())
	hit := false
	for _, e := range entries {
		if e.ToolUseID == "gemini.post-tool-use" && e.Verdict == "failure" {
			hit = true
			break
		}
	}
	if !hit {
		t.Fatalf("expected failure verdict on AfterTool with non-empty error: %+v", entries)
	}
}

func TestGeminiSessionStart_CreatesSession(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	body := `{
		"session_id": "gemini-session-start-001",
		"hook_event_name": "SessionStart",
		"source": "startup",
		"cwd": "/tmp",
		"transcript_path": "/tmp/transcript.jsonl"
	}`
	res, err := http.Post(fx.srv.URL+"/v1/hooks/gemini/session-start", "application/json", strings.NewReader(body))
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

	sess, err := fx.store.GetSession(context.Background(), "gemini-session-start-001")
	if err != nil {
		t.Fatalf("session not created: %v", err)
	}
	if sess.Harness != "gemini" {
		t.Fatalf("harness = %q", sess.Harness)
	}

	entries, _ := fx.store.ListLedger(context.Background())
	hit := false
	for _, e := range entries {
		if e.ToolUseID == "gemini.session-start" && e.Source == "gemini" {
			hit = true
			break
		}
	}
	if !hit {
		t.Fatalf("missing gemini.session-start ledger entry: %+v", entries)
	}
}

func TestGeminiPreToolUse_DenyConcatenatesNudge(t *testing.T) {
	fx := newGateFixture(t, nudgePolicyYAML)
	body := `{
		"session_id": "gemini-sess-nudge",
		"hook_event_name": "BeforeTool",
		"tool_name": "Bash",
		"tool_input": {"command": "rm -rf /tmp/x"}
	}`
	res, out := postGeminiPre(t, fx, body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if out["decision"] != "deny" {
		t.Fatalf("decision = %v, want deny", out["decision"])
	}
	reason, _ := out["reason"].(string)
	if !strings.Contains(reason, "matched rule safety.rm-suggest-trash (deny)") {
		t.Fatalf("reason missing original verdict: %q", reason)
	}
	if !strings.Contains(reason, "→ Suggested: use trash instead") {
		t.Fatalf("reason missing nudge suffix: %q", reason)
	}
	stop, _ := out["stopReason"].(string)
	if !strings.Contains(stop, "→ Suggested: use trash instead") {
		t.Fatalf("stopReason missing nudge suffix: %q", stop)
	}

	allowBody := `{
		"session_id": "gemini-sess-nudge-allow",
		"hook_event_name": "BeforeTool",
		"tool_name": "Bash",
		"tool_input": {"command": "ls -la"}
	}`
	_, allowOut := postGeminiPre(t, fx, allowBody)
	allowReason, _ := allowOut["reason"].(string)
	if strings.Contains(allowReason, "→ Suggested:") {
		t.Fatalf("allow reason must not carry nudge: %q", allowReason)
	}
}

func TestGeminiPreToolUse_FirewallEscalatesPolicyMonitorMatch(t *testing.T) {
	t.Setenv("AGENTLOCK_MODE", "")
	runtimeMode.Store("firewall")
	t.Cleanup(func() { runtimeMode.Store("") })

	fx := newGateFixture(t, monitorPolicyYAML)
	body := `{
		"session_id": "gemini-sess-escalate",
		"hook_event_name": "BeforeTool",
		"tool_name": "Bash",
		"tool_input": {"command": "rm -rf /tmp/x"}
	}`
	res, out := postGeminiPre(t, fx, body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if out["continue"] != false {
		t.Fatalf("daemon firewall must deny: continue=%v out=%v", out["continue"], out)
	}
	if out["decision"] != "deny" {
		t.Fatalf("decision = %v, want deny", out["decision"])
	}

	entries, _ := fx.store.ListLedger(context.Background())
	hit := false
	for _, e := range entries {
		if e.ToolUseID == "gemini.pre-tool-use" && e.Verdict == "deny" && e.RuleID == "rogue.destructive-bash" {
			hit = true
			break
		}
	}
	if !hit {
		t.Fatalf("expected gemini deny ledger entry for escalated match: %+v", entries)
	}
}
