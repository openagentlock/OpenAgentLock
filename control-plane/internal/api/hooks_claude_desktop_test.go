package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openagentlock/openagentlock/control-plane/internal/storage"
)

func postClaudeDesktopPre(t *testing.T, fx gateFixture, body string) (*http.Response, map[string]any) {
	t.Helper()
	res, err := http.Post(fx.srv.URL+"/v1/hooks/claude-desktop/pre-tool-use", "application/json", strings.NewReader(body))
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

// The proxy sends MCP-style tool names as `mcp__<server>__<tool>`. Most
// policy gates won't match them; the daemon responds with "allow" by
// default. This test verifies the wire shape only — actual policy
// matching is exercised by the existing claude-code tests.
func TestClaudeDesktopPreToolUse_AllowsByDefault(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	body := `{
		"session_id": "claude-desktop-filesystem",
		"hook_event_name": "PreToolUse",
		"tool_name": "mcp__filesystem__read_file",
		"tool_use_id": "5",
		"tool_input": {"path": "/tmp/safe"}
	}`
	res, out := postClaudeDesktopPre(t, fx, body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%v", res.StatusCode, out)
	}
	if out["continue"] != true {
		t.Fatalf("continue = %v", out["continue"])
	}
	spec, _ := out["hookSpecificOutput"].(map[string]any)
	if spec["permissionDecision"] != "allow" {
		t.Fatalf("decision = %v", spec)
	}
}

// Bash-tool destructive policy applies to ANY tool input matching its
// matcher — so a tools/call carrying a destructive bash command (even
// under an MCP tool name) gets denied. This validates the policy
// pathway shares the same gate-check as Claude Code's hooks.
func TestClaudeDesktopPreToolUse_DeniesDestructiveBashViaProxy(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	body := `{
		"session_id": "claude-desktop-shell",
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_use_id": "7",
		"tool_input": {"command": "rm -rf /tmp/x"}
	}`
	res, out := postClaudeDesktopPre(t, fx, body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if out["continue"] != false {
		t.Fatalf("expected continue=false on deny: %v", out)
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

// Auto-creates the daemon-side session on first hit, tagged
// Harness="claude-desktop" so dashboards distinguish proxy traffic.
func TestClaudeDesktopPreToolUse_AutoCreatesUnattestedSession(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	body := `{
		"session_id": "brand-new-desktop-session",
		"hook_event_name": "PreToolUse",
		"tool_name": "mcp__filesystem__read_file",
		"tool_use_id": "9",
		"tool_input": {"path": "/tmp/x"}
	}`
	_, _ = postClaudeDesktopPre(t, fx, body)
	sess, err := fx.store.GetSession(context.Background(), "brand-new-desktop-session")
	if err != nil {
		t.Fatalf("auto-session not created: %v", err)
	}
	if sess.Signer != "none" {
		t.Fatalf("auto-session should be unattested signer=none, got %q", sess.Signer)
	}
	if sess.Harness != "claude-desktop" {
		t.Fatalf("auto-session harness should be 'claude-desktop', got %q", sess.Harness)
	}
}

// TestRefreshUnattestedPolicyHash_RePinsUnattestedToLive is the
// positive case for the proxy's stable-session-id papercut: a long-
// lived auto-created session whose pinned hash is stale must get
// re-pinned to live so policy edits made AFTER the session was created
// still apply on the next call.
func TestRefreshUnattestedPolicyHash_RePinsUnattestedToLive(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	stale := storage.Session{
		ID:         "stale-id",
		Signer:     "none",
		PolicyHash: "sha256:stale-hash-from-prior-policy-version",
	}
	got := refreshUnattestedPolicyHash(Deps{Store: fx.store}, stale)
	if got.PolicyHash == stale.PolicyHash {
		t.Fatalf("unattested session not refreshed (still pinned to %q)", got.PolicyHash)
	}
	// The live policy hash lives in livePolicyRegistry; we just assert it
	// changed off the stale value. Existing tests cover the registry
	// itself, so we don't reach in to compare hashes directly here.
}

// TestRefreshUnattestedPolicyHash_LeavesAttestedSessionsAlone is the
// safety case: the fix must NOT mutate attested sessions. Their pinned
// hash is committed to by the signer's signature; re-pinning would
// silently invalidate the attestation.
func TestRefreshUnattestedPolicyHash_LeavesAttestedSessionsAlone(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	attested := storage.Session{
		ID:         "attested-id",
		Signer:     "totp",
		PolicyHash: "sha256:legacy-hash-attested-by-signer",
	}
	got := refreshUnattestedPolicyHash(Deps{Store: fx.store}, attested)
	if got.PolicyHash != attested.PolicyHash {
		t.Fatalf("attested session hash mutated: got %q want %q", got.PolicyHash, attested.PolicyHash)
	}
}

// TestRefreshUnattestedPolicyHash_AlreadyCurrentIsNoop: when an
// unattested session is already pinned to the live policy, refresh
// must be a no-op (don't churn the struct, don't allocate). Prevents a
// future regression where someone "fixes" the conditional and ends up
// always rewriting.
func TestRefreshUnattestedPolicyHash_AlreadyCurrentIsNoop(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	live := livePolicyFor(Deps{Store: fx.store})
	if live == nil {
		t.Skip("no live policy in registry; can't run this test")
	}
	current := storage.Session{
		ID:         "current-id",
		Signer:     "none",
		PolicyHash: live.Hash,
	}
	got := refreshUnattestedPolicyHash(Deps{Store: fx.store}, current)
	if got.PolicyHash != live.Hash {
		t.Fatalf("already-current session got rewritten: %q -> %q", live.Hash, got.PolicyHash)
	}
}

// TestClaudeDesktopPreToolUse_PolicyEditTakesEffectMidSession is the
// end-to-end version: confirms the regression doesn't reappear by
// driving a real HTTP roundtrip.  Session is created with permissive
// policy, policy is mutated to deny via the live API, next call from
// the same session id is denied. Without the re-pin, this hangs at
// allow because the session's pinned hash still resolves to the
// permissive snapshot.
func TestClaudeDesktopPreToolUse_PolicyEditTakesEffectMidSession(t *testing.T) {
	fx := newGateFixture(t, monitorPolicyYAML)

	allowBody := `{
		"session_id": "stable-proxy-session",
		"hook_event_name": "PreToolUse",
		"tool_name": "mcp__filesystem__read_text_file",
		"tool_use_id": "1",
		"tool_input": {"path": "/tmp/anything"}
	}`
	// First hit creates the session pinned to monitorPolicyYAML's hash.
	res, out := postClaudeDesktopPre(t, fx, allowBody)
	if res.StatusCode != http.StatusOK || out["continue"] != true {
		t.Fatalf("baseline allow failed: status=%d out=%v", res.StatusCode, out)
	}
	if _, err := fx.store.GetSession(context.Background(), "stable-proxy-session"); err != nil {
		t.Fatalf("session not created: %v", err)
	}

	// Add a deny gate for the path used above. This call mutates the
	// live policy and Swap()s a new hash into the registry.
	gateYAML := `id: dyn.block-tmp
match:
  tool: mcp__filesystem__read_text_file
  any_path_regex:
    - "/tmp/"
evaluate:
  - kind: always
    action: deny
nudge: blocked by mid-session policy edit`
	gateBody, _ := json.Marshal(map[string]any{"yaml": gateYAML, "replace": true})
	addRes, err := http.Post(fx.srv.URL+"/v1/policy/gates/yaml", "application/json", strings.NewReader(string(gateBody)))
	if err != nil {
		t.Fatalf("add gate: %v", err)
	}
	addRes.Body.Close()

	// Force-enforce so the gate's per-gate monitor mode escalates to deny.
	t.Setenv("AGENTLOCK_MODE", "firewall")

	// Re-issue the same call from the same session. With the fix:
	// re-pinned to live → deny. Without it: still pinned to the old
	// hash → no gate match → allow.
	res, out = postClaudeDesktopPre(t, fx, allowBody)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("second call status = %d", res.StatusCode)
	}
	if out["continue"] != false {
		t.Fatalf("policy edit did not take effect mid-session: out=%v", out)
	}
	spec, _ := out["hookSpecificOutput"].(map[string]any)
	if spec["permissionDecision"] != "deny" {
		t.Fatalf("expected deny, got %v", spec)
	}
}

func TestClaudeDesktopPostToolUse_RecordsCompletion(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	body := `{
		"session_id": "claude-desktop-fs",
		"hook_event_name": "PostToolUse",
		"tool_name": "mcp__filesystem__read_file",
		"tool_use_id": "5",
		"tool_input": {},
		"tool_response": {"content": [{"type":"text","text":"hello"}]}
	}`
	res, err := http.Post(fx.srv.URL+"/v1/hooks/claude-desktop/post-tool-use", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	if out["continue"] != true {
		t.Fatalf("continue = %v", out["continue"])
	}
}
