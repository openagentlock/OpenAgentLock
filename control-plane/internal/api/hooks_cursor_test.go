package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func postCursorPre(t *testing.T, fx gateFixture, body string) (*http.Response, map[string]any) {
	t.Helper()
	res, err := http.Post(fx.srv.URL+"/v1/hooks/cursor/pre-tool-use", "application/json", strings.NewReader(body))
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

func postCursorBeforeMCP(t *testing.T, fx gateFixture, body string) (*http.Response, map[string]any) {
	t.Helper()
	res, err := http.Post(fx.srv.URL+"/v1/hooks/cursor/before-mcp-execution", "application/json", strings.NewReader(body))
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

func TestCursorPreToolUse_AllowsBenignBash(t *testing.T) {
	cursorResetDedupe()
	fx := newGateFixture(t, enforcePolicyYAML)
	body := `{
		"conversation_id": "cursor-sess-001",
		"generation_id": "gen-001",
		"hook_event_name": "preToolUse",
		"cursor_version": "1.7.0",
		"tool_name": "Shell",
		"tool_use_id": "ct_01",
		"tool_input": {"command": "ls -la"},
		"cwd": "/tmp"
	}`
	res, out := postCursorPre(t, fx, body)
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
	if spec["hookEventName"] != "PreToolUse" {
		t.Fatalf("event name = %v", spec["hookEventName"])
	}
}

func TestCursorPreToolUse_DeniesDestructiveBash(t *testing.T) {
	cursorResetDedupe()
	fx := newGateFixture(t, enforcePolicyYAML)
	// tool_name "Bash" is what the bundled enforce policy keys on.
	// Cursor itself uses "Shell" for shell tool calls — bridging the
	// two is a separate normalization concern (tracked outside this
	// PR); the integration plumbing is what's under test here.
	body := `{
		"conversation_id": "cursor-sess-002",
		"generation_id": "gen-002",
		"hook_event_name": "preToolUse",
		"tool_name": "Bash",
		"tool_use_id": "ct_02",
		"tool_input": {"command": "rm -rf /tmp/x"},
		"cwd": "/tmp"
	}`
	res, out := postCursorPre(t, fx, body)
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

	entries, _ := fx.store.ListLedger(context.Background())
	hit := false
	for _, e := range entries {
		if e.ToolUseID == "ct_02" && e.Source == "cursor" && e.Verdict == "deny" && e.RuleID == "rogue.destructive-bash" {
			hit = true
			break
		}
	}
	if !hit {
		t.Fatalf("expected cursor deny ledger entry: %+v", entries)
	}
}

func TestCursorPreToolUse_AutoCreatesUnattestedSession(t *testing.T) {
	cursorResetDedupe()
	fx := newGateFixture(t, enforcePolicyYAML)
	body := `{
		"conversation_id": "brand-new-cursor-session",
		"generation_id": "g1",
		"hook_event_name": "preToolUse",
		"tool_name": "Shell",
		"tool_use_id": "ct_03",
		"tool_input": {"command": "echo hi"}
	}`
	_, _ = postCursorPre(t, fx, body)

	sess, err := fx.store.GetSession(context.Background(), "brand-new-cursor-session")
	if err != nil {
		t.Fatalf("auto-session not created: %v", err)
	}
	if sess.Signer != "none" {
		t.Fatalf("auto-session should be unattested signer=none, got %q", sess.Signer)
	}
	if sess.Harness != "cursor" {
		t.Fatalf("auto-session should be tagged cursor, got %q", sess.Harness)
	}
}

func TestCursorPreToolUse_MonitorModeSuppressesDeny(t *testing.T) {
	cursorResetDedupe()
	t.Setenv("AGENTLOCK_MODE", "monitor")
	fx := newGateFixture(t, enforcePolicyYAML)
	body := `{
		"conversation_id": "cursor-sess-004",
		"generation_id": "g4",
		"hook_event_name": "preToolUse",
		"tool_name": "Bash",
		"tool_use_id": "ct_04",
		"tool_input": {"command": "rm -rf /tmp/x"}
	}`
	res, out := postCursorPre(t, fx, body)
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
		if e.ToolUseID == "ct_04" && e.Verdict == "deny" && e.RuleID == "rogue.destructive-bash" {
			hit = true
			break
		}
	}
	if !hit {
		t.Fatalf("expected deny ledger entry despite monitor allow response: %+v", entries)
	}
}

func TestCursorPreToolUse_MissingRequiredFields(t *testing.T) {
	cursorResetDedupe()
	fx := newGateFixture(t, enforcePolicyYAML)
	res, _ := postCursorPre(t, fx, `{"conversation_id":"x"}`)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", res.StatusCode)
	}
}

func TestCursorBeforeMCPExecution_DedupesAgainstPreToolUse(t *testing.T) {
	cursorResetDedupe()
	fx := newGateFixture(t, enforcePolicyYAML)
	// Same tool_use_id over both endpoints: pre-tool-use fires first
	// (the typical Cursor order for an MCP call) and before-mcp-
	// execution must short-circuit.
	body := `{
		"conversation_id": "cursor-mcp-001",
		"generation_id": "g_mcp1",
		"tool_name": "mcp__server__tool",
		"tool_use_id": "ct_mcp_1",
		"tool_input": {"foo": "bar"},
		"mcp_server_name": "server",
		"mcp_tool_name": "tool"
	}`

	preBefore, _ := fx.store.ListLedger(context.Background())
	preLen := len(preBefore)

	_, out1 := postCursorPre(t, fx, body)
	_, out2 := postCursorBeforeMCP(t, fx, body)

	// Both responses come back with the same verdict.
	spec1, _ := out1["hookSpecificOutput"].(map[string]any)
	spec2, _ := out2["hookSpecificOutput"].(map[string]any)
	if spec1["permissionDecision"] != spec2["permissionDecision"] {
		t.Fatalf("verdict drift across deduped events: %v vs %v",
			spec1["permissionDecision"], spec2["permissionDecision"])
	}
	// And the second one must be re-tagged with its own event name so
	// the shim can write Cursor's expected output cleanly.
	if spec2["hookEventName"] != "BeforeMCPExecution" {
		t.Fatalf("second event name = %v, want BeforeMCPExecution", spec2["hookEventName"])
	}

	entries, _ := fx.store.ListLedger(context.Background())
	count := 0
	for _, e := range entries {
		if e.ToolUseID == "ct_mcp_1" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 ledger entry for tool_use_id, got %d (total ledger grew by %d)",
			count, len(entries)-preLen)
	}
}

func TestCursorAfterMCPExecution_DedupesAgainstPostToolUse(t *testing.T) {
	cursorResetDedupe()
	fx := newGateFixture(t, enforcePolicyYAML)
	body := `{
		"conversation_id": "cursor-mcp-002",
		"generation_id": "g_mcp2",
		"tool_name": "mcp__server__tool",
		"tool_use_id": "ct_mcp_post_1",
		"tool_input": {"foo": "bar"},
		"tool_response": "ok",
		"success": true,
		"mcp_server_name": "server",
		"mcp_tool_name": "tool"
	}`
	_, err := http.Post(fx.srv.URL+"/v1/hooks/cursor/post-tool-use", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST post-tool-use: %v", err)
	}
	_, err = http.Post(fx.srv.URL+"/v1/hooks/cursor/after-mcp-execution", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST after-mcp-execution: %v", err)
	}

	entries, _ := fx.store.ListLedger(context.Background())
	count := 0
	for _, e := range entries {
		if e.ToolUseID == "ct_mcp_post_1" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 outcome ledger entry, got %d", count)
	}
}

func TestCursorStop_EndsSession(t *testing.T) {
	cursorResetDedupe()
	fx := newGateFixture(t, enforcePolicyYAML)
	pre := `{
		"conversation_id": "cursor-stop-test",
		"generation_id": "g_stop",
		"hook_event_name": "preToolUse",
		"tool_name": "Shell",
		"tool_use_id": "ct_05",
		"tool_input": {"command": "ls"}
	}`
	_, _ = postCursorPre(t, fx, pre)

	stop := `{"conversation_id":"cursor-stop-test","hook_event_name":"sessionEnd"}`
	res, err := http.Post(fx.srv.URL+"/v1/hooks/cursor/stop", "application/json", strings.NewReader(stop))
	if err != nil {
		t.Fatalf("POST stop: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d body=%s", res.StatusCode, buf.String())
	}
	active, _ := fx.store.IsSessionActive(context.Background(), "cursor-stop-test")
	if active {
		t.Fatalf("session should be ended")
	}
}

func TestCursorPostToolUse_RecordsOutcome(t *testing.T) {
	cursorResetDedupe()
	fx := newGateFixture(t, enforcePolicyYAML)
	body := `{
		"conversation_id": "cursor-post-001",
		"generation_id": "g_post",
		"hook_event_name": "postToolUse",
		"tool_name": "Shell",
		"tool_use_id": "ct_post_001",
		"tool_input": {"command": "ls"},
		"tool_response": "total 0",
		"success": true
	}`
	res, err := http.Post(
		fx.srv.URL+"/v1/hooks/cursor/post-tool-use",
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
		if e.ToolUseID == "ct_post_001" && e.Source == "cursor" && e.Verdict == "complete" {
			hit = true
			break
		}
	}
	if !hit {
		t.Fatalf("missing complete PostToolUse ledger entry: %+v", entries)
	}
}

func TestCursorSessionStart_CreatesSession(t *testing.T) {
	cursorResetDedupe()
	fx := newGateFixture(t, enforcePolicyYAML)
	body := `{
		"conversation_id": "cursor-session-start-001",
		"hook_event_name": "sessionStart",
		"cursor_version": "1.7.0",
		"model": "claude-sonnet-4-6",
		"workspace_roots": ["/tmp/proj"],
		"cwd": "/tmp"
	}`
	res, err := http.Post(fx.srv.URL+"/v1/hooks/cursor/session-start", "application/json", strings.NewReader(body))
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

	sess, err := fx.store.GetSession(context.Background(), "cursor-session-start-001")
	if err != nil {
		t.Fatalf("session not created: %v", err)
	}
	if sess.Harness != "cursor" {
		t.Fatalf("harness = %q", sess.Harness)
	}

	entries, _ := fx.store.ListLedger(context.Background())
	hit := false
	for _, e := range entries {
		if e.ToolUseID == "cursor.session-start" && e.Source == "cursor" {
			hit = true
			break
		}
	}
	if !hit {
		t.Fatalf("missing cursor.session-start ledger entry: %+v", entries)
	}
}
