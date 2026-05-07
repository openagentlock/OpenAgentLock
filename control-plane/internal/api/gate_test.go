package api

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openagentlock/openagentlock/control-plane/internal/policy"
	"github.com/openagentlock/openagentlock/control-plane/internal/signer"
	"github.com/openagentlock/openagentlock/control-plane/internal/storage"
)

const enforcePolicyYAML = `
version: 1
mode: enforce
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

const mcpNetEgressPolicyYAML = `
version: 1
mode: enforce
gates:
  - id: rogue.net-egress
    match:
      any_of:
        - tool_prefix: "mcp__"
          any_url_regex:
            - '^https?://'
        - tool_prefix: "mcp_"
          any_url_regex:
            - '^https?://'
    evaluate:
      - kind: host-allowlist
        list: __INLINE__:api.openai.com,api.github.com
        on_hit: allow
        on_miss: deny
`

type gateFixture struct {
	srv       *httptest.Server
	store     *storage.Memory
	sessionID string
	home      string
}

func newGateFixture(t *testing.T, policyYAML string) gateFixture {
	t.Helper()
	pol, err := policy.LoadBytes([]byte(policyYAML))
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	home := t.TempDir()
	store, err := storage.NewMemory(home)
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	srv := httptest.NewServer(NewRouter(Deps{Store: store, Policy: pol, AgentlockHome: home}))
	t.Cleanup(srv.Close)

	// Create a real session via the handler path so session_id is authentic.
	pub, priv, _ := ed25519.GenerateKey(nil)
	payload := signer.AttestationPayload{
		PolicyHash:    pol.Hash,
		SessionPubKey: "ed25519:" + hex.EncodeToString(pub),
		Signer:        "software",
		SignerPubKey:  "ed25519:" + hex.EncodeToString(pub),
	}
	canon := signer.CanonicalAttestation(payload)
	sig := ed25519.Sign(priv, canon)
	body := fmt.Sprintf(`{"policy_hash":%q,"session_pubkey":%q,"signer":"software","signer_pubkey":%q,"attestation":"ed25519:%s"}`,
		payload.PolicyHash, payload.SessionPubKey, payload.SignerPubKey, hex.EncodeToString(sig))
	res, err := http.Post(srv.URL+"/v1/sessions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST sessions: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("session create: %d %s", res.StatusCode, buf.String())
	}
	var sess map[string]any
	_ = json.NewDecoder(res.Body).Decode(&sess)
	id, _ := sess["id"].(string)

	return gateFixture{srv: srv, store: store, sessionID: id, home: home}
}

func postGateCheck(t *testing.T, srv *httptest.Server, body string) (*http.Response, map[string]any) {
	t.Helper()
	res, err := http.Post(srv.URL+"/v1/gates/check", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST gates/check: %v", err)
	}
	var out map[string]any
	if res.Header.Get("Content-Type") == "application/json" {
		_ = json.NewDecoder(res.Body).Decode(&out)
	}
	_ = res.Body.Close()
	return res, out
}

func TestGateCheck_AllowsBenignBash(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)

	body := fmt.Sprintf(`{
		"session_id": %q,
		"source": "claude-code",
		"tool": "Bash",
		"input": {"command": "ls -la"}
	}`, fx.sessionID)
	res, out := postGateCheck(t, fx.srv, body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if out["verdict"] != "allow" {
		t.Fatalf("verdict = %v", out["verdict"])
	}
	if out["rule_id"] != "default" {
		t.Fatalf("rule_id = %v", out["rule_id"])
	}
}

func TestGateCheck_DeniesDestructiveBash(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)

	body := fmt.Sprintf(`{
		"session_id": %q,
		"source": "claude-code",
		"tool": "Bash",
		"input": {"command": "rm -rf /tmp/demo"}
	}`, fx.sessionID)
	res, out := postGateCheck(t, fx.srv, body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if out["verdict"] != "deny" {
		t.Fatalf("verdict = %v, want deny", out["verdict"])
	}
	if out["rule_id"] != "rogue.destructive-bash" {
		t.Fatalf("rule_id = %v", out["rule_id"])
	}
	// ledger_seq must be present and > 0 (session.create already used seq 0)
	seq, ok := out["ledger_seq"].(float64)
	if !ok || seq < 1 {
		t.Fatalf("ledger_seq = %v", out["ledger_seq"])
	}
}

func TestGateCheck_AppliesRepoAgentlockOnlyInsideCwdTree(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	repo := filepath.Join(fx.home, "repo")
	sibling := filepath.Join(fx.home, "sibling")
	if err := os.MkdirAll(filepath.Join(repo, "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sibling, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".agentlock.yaml"), []byte(`
version: 1
gates:
  - id: repo.block-secret-print
    match:
      tool: Bash
      any_command_regex:
        - 'cat\s+secrets\.txt'
    evaluate:
      - kind: always
        action: deny
`), 0o644); err != nil {
		t.Fatal(err)
	}

	inside := fmt.Sprintf(`{
		"session_id": %q,
		"source": "codex",
		"tool": "Bash",
		"cwd": %q,
		"input": {"command": "cat secrets.txt"}
	}`, fx.sessionID, filepath.Join(repo, "pkg"))
	res, out := postGateCheck(t, fx.srv, inside)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("inside status = %d", res.StatusCode)
	}
	if out["verdict"] != "deny" || out["rule_id"] != "repo.block-secret-print" {
		t.Fatalf("inside should hit repo rule, got %+v", out)
	}

	outside := fmt.Sprintf(`{
		"session_id": %q,
		"source": "codex",
		"tool": "Bash",
		"cwd": %q,
		"input": {"command": "cat secrets.txt"}
	}`, fx.sessionID, sibling)
	res, out = postGateCheck(t, fx.srv, outside)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("outside status = %d", res.StatusCode)
	}
	if out["verdict"] != "allow" || out["rule_id"] != "default" {
		t.Fatalf("sibling repo should not inherit repo rule, got %+v", out)
	}
}

func TestGateCheck_IgnoresPermissiveRepoAgentlockUntilApproved(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	repo := filepath.Join(fx.home, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".agentlock.yaml"), []byte(`
version: 1
gates:
  - id: rogue.destructive-bash
    disabled: true
    match:
      tool: Bash
      any_command_regex:
        - 'rm\s+-rf\b'
    evaluate:
      - kind: always
        action: allow
`), 0o644); err != nil {
		t.Fatal(err)
	}

	body := fmt.Sprintf(`{
		"session_id": %q,
		"source": "codex",
		"tool": "Bash",
		"cwd": %q,
		"input": {"command": "rm -rf /tmp/demo"}
	}`, fx.sessionID, repo)
	res, out := postGateCheck(t, fx.srv, body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if out["verdict"] != "deny" || out["rule_id"] != "rogue.destructive-bash" {
		t.Fatalf("permissive repo override must not weaken daemon policy, got %+v", out)
	}
}

func TestGateCheck_AppliesRepoGateWithConditionalDenyEvaluator(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	repo := filepath.Join(fx.home, "repo")
	allowlist := filepath.Join(repo, "allowed.txt")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(allowlist, []byte("safe-package\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".agentlock.yaml"), []byte(fmt.Sprintf(`
version: 1
gates:
  - id: repo.npm-allowlist
    match:
      tool: Bash
      any_command_regex:
        - '^npm\s+install\s+'
    evaluate:
      - kind: allowlist
        list: %q
        on_hit: allow
        on_miss: deny
      - kind: always
        action: allow
`, allowlist)), 0o644); err != nil {
		t.Fatal(err)
	}

	body := fmt.Sprintf(`{
		"session_id": %q,
		"source": "codex",
		"tool": "Bash",
		"cwd": %q,
		"input": {"command": "npm install evil-package"}
	}`, fx.sessionID, repo)
	res, out := postGateCheck(t, fx.srv, body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if out["verdict"] != "deny" || out["rule_id"] != "repo.npm-allowlist" {
		t.Fatalf("conditional deny repo gate should apply, got %+v", out)
	}
}

func TestGateCheck_GroupPoliciesBothApply(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	setSessionIdentity(t, fx, "alice", []string{"cloud", "secrets"})
	writeGroupPolicy(t, fx.home, `
version: 1
groups:
  cloud:
    gates:
      - id: group.cloud-delete
        match:
          tool: Bash
          command_regex: '^terraform destroy'
        evaluate:
          - kind: always
            action: deny
  secrets:
    gates:
      - id: group.secret-print
        match:
          tool: Bash
          command_regex: '^cat secret'
        evaluate:
          - kind: always
            action: deny
`)

	for _, tc := range []struct {
		cmd  string
		rule string
	}{
		{"terraform destroy -auto-approve", "group.cloud-delete"},
		{"cat secret.txt", "group.secret-print"},
	} {
		body := fmt.Sprintf(`{"session_id":%q,"source":"codex","tool":"Bash","input":{"command":%q}}`, fx.sessionID, tc.cmd)
		res, out := postGateCheck(t, fx.srv, body)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("status = %d", res.StatusCode)
		}
		if out["verdict"] != "deny" || out["rule_id"] != tc.rule {
			t.Fatalf("%q got %+v, want deny by %s", tc.cmd, out, tc.rule)
		}
	}
}

func TestGateCheck_GroupDenyBeatsPersonalAllow(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	setSessionIdentity(t, fx, "alice", []string{"compliance"})
	writeGroupPolicy(t, fx.home, `
version: 1
groups:
  compliance:
    gates:
      - id: shared.secret
        match:
          tool: Bash
          command_regex: '^cat secret'
        evaluate:
          - kind: always
            action: deny
users:
  alice:
    gates:
      - id: user.secret-allow
        match:
          tool: Bash
          command_regex: '^cat secret'
        evaluate:
          - kind: always
            action: allow
`)
	body := fmt.Sprintf(`{"session_id":%q,"source":"codex","tool":"Bash","input":{"command":"cat secret.txt"}}`, fx.sessionID)
	res, out := postGateCheck(t, fx.srv, body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if out["verdict"] != "deny" || out["rule_id"] != "shared.secret" {
		t.Fatalf("group deny should win, got %+v", out)
	}
	entries, err := fx.store.ListLedger(context.Background())
	if err != nil {
		t.Fatalf("ListLedger: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected ledger entries, got none")
	}
	last := entries[len(entries)-1]
	if len(last.PolicyTrace) != 2 {
		t.Fatalf("policy trace should include group deny + user allow, got %+v", last.PolicyTrace)
	}
}

func TestGateCheck_PriorityPrecedenceCanOverrideSameGateID(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	setSessionIdentity(t, fx, "alice", []string{"default", "red-team"})
	writeGroupPolicy(t, fx.home, `
version: 1
groups:
  default:
    gates:
      - id: shared.net
        precedence: priority
        priority: 10
        match:
          tool: Bash
          command_regex: '^curl '
        evaluate:
          - kind: always
            action: deny
  red-team:
    gates:
      - id: shared.net
        precedence: priority
        priority: 20
        match:
          tool: Bash
          command_regex: '^curl '
        evaluate:
          - kind: always
            action: allow
`)
	body := fmt.Sprintf(`{"session_id":%q,"source":"codex","tool":"Bash","input":{"command":"curl https://example.com"}}`, fx.sessionID)
	res, out := postGateCheck(t, fx.srv, body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if out["verdict"] != "allow" || out["rule_id"] != "shared.net" {
		t.Fatalf("priority allow should win, got %+v", out)
	}
}

func TestGateCheck_ZeroGroupsUsesBasePolicyOnly(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	setSessionIdentity(t, fx, "alice", nil)
	writeGroupPolicy(t, fx.home, `
version: 1
groups:
  compliance:
    gates:
      - id: group.secret-print
        match:
          tool: Bash
          command_regex: '^cat secret'
        evaluate:
          - kind: always
            action: deny
`)
	body := fmt.Sprintf(`{"session_id":%q,"source":"codex","tool":"Bash","input":{"command":"cat secret.txt"}}`, fx.sessionID)
	res, out := postGateCheck(t, fx.srv, body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if out["verdict"] != "allow" || out["rule_id"] != "default" {
		t.Fatalf("zero groups should not inherit group policy, got %+v", out)
	}
}

func setSessionIdentity(t *testing.T, fx gateFixture, userID string, groups []string) {
	t.Helper()
	sess, err := fx.store.GetSession(context.Background(), fx.sessionID)
	if err != nil {
		t.Fatal(err)
	}
	sess.UserID = userID
	sess.Groups = groups
	if err := fx.store.UpdateSession(context.Background(), sess); err != nil {
		t.Fatal(err)
	}
}

func writeGroupPolicy(t *testing.T, home string, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(home, groupPolicyFileName), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestGateCheck_WritesLedgerEntry(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)

	body := fmt.Sprintf(`{
		"session_id": %q,
		"source": "claude-code",
		"tool": "Bash",
		"input": {"command": "git push --force origin main"}
	}`, fx.sessionID)
	_, _ = postGateCheck(t, fx.srv, body)

	f, err := os.Open(filepath.Join(fx.home, "ledger.jsonl"))
	if err != nil {
		t.Fatalf("open ledger: %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	lines := 0
	var last map[string]any
	for sc.Scan() {
		lines++
		_ = json.Unmarshal(sc.Bytes(), &last)
	}
	if lines != 2 {
		t.Fatalf("want 2 ledger lines (session + gate), got %d", lines)
	}
	if last["source"] != "claude-code" {
		t.Fatalf("last source = %v", last["source"])
	}
	if last["tool_use_id"] != "gate.check" {
		t.Fatalf("last tool_use_id = %v", last["tool_use_id"])
	}
}

func TestGateCheck_UnknownSessionReturns404(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)

	body := `{
		"session_id": "does-not-exist",
		"source": "claude-code",
		"tool": "Bash",
		"input": {"command": "ls"}
	}`
	res, _ := postGateCheck(t, fx.srv, body)
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", res.StatusCode)
	}
}

func TestGateCheck_MalformedJSONReturns400(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)

	res, _ := postGateCheck(t, fx.srv, "{ not json")
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", res.StatusCode)
	}
}

func TestGateCheck_MissingRequiredFieldReturns400(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	body := fmt.Sprintf(`{"session_id":%q, "source":"claude-code"}`, fx.sessionID)
	res, _ := postGateCheck(t, fx.srv, body)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", res.StatusCode)
	}
}

const nudgePolicyYAML = `
version: 1
mode: enforce
defaults:
  bash: allow
gates:
  - id: safety.rm-suggest-trash
    match:
      tool: Bash
      any_command_regex:
        - '\brm\s+(-[rRfF]+\s+)+\S+'
    evaluate:
      - kind: always
        action: deny
        nudge: "use trash instead"
`

// A policy rule with `nudge:` must surface that hint in the JSON
// response from /v1/gates/check on a deny verdict, so harness shims and
// the dashboard can show concrete remediation guidance.
func TestGateCheck_DenyResponseCarriesNudge(t *testing.T) {
	fx := newGateFixture(t, nudgePolicyYAML)

	body := fmt.Sprintf(`{
		"session_id": %q,
		"source": "claude-code",
		"tool": "Bash",
		"input": {"command": "rm -rf /tmp/demo"}
	}`, fx.sessionID)
	res, out := postGateCheck(t, fx.srv, body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if out["verdict"] != "deny" {
		t.Fatalf("verdict = %v", out["verdict"])
	}
	if out["nudge"] != "use trash instead" {
		t.Fatalf("nudge = %v, want %q", out["nudge"], "use trash instead")
	}
}

// Backward compat: rules without a nudge produce a response that omits
// the field entirely (omitempty). Existing API consumers see no change.
func TestGateCheck_AllowResponseOmitsNudgeField(t *testing.T) {
	fx := newGateFixture(t, nudgePolicyYAML)

	body := fmt.Sprintf(`{
		"session_id": %q,
		"source": "claude-code",
		"tool": "Bash",
		"input": {"command": "ls -la"}
	}`, fx.sessionID)
	res, out := postGateCheck(t, fx.srv, body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if out["verdict"] != "allow" {
		t.Fatalf("verdict = %v", out["verdict"])
	}
	if _, present := out["nudge"]; present {
		t.Fatalf("nudge field present on allow response: %v", out["nudge"])
	}
}
