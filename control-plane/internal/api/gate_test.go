package api

import (
	"bufio"
	"bytes"
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
