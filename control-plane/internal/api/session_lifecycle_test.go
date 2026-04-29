package api

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openagentlock/openagentlock/control-plane/internal/policy"
	"github.com/openagentlock/openagentlock/control-plane/internal/signer"
)

func policyHashFrom(t *testing.T, src string) string {
	t.Helper()
	p, err := policy.LoadBytes([]byte(src))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	return p.Hash
}

func TestSessionEnd_Returns204AndWritesLedgerEntry(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)

	req, _ := http.NewRequest("POST", fx.srv.URL+"/v1/sessions/"+fx.sessionID+"/end", nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST end: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", res.StatusCode)
	}

	// ledger.jsonl should now have an entry with tool_use_id = session.end.
	f, err := os.Open(filepath.Join(fx.home, "ledger.jsonl"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	found := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e map[string]any
		_ = json.Unmarshal(sc.Bytes(), &e)
		if e["tool_use_id"] == "session.end" {
			found = true
		}
	}
	if !found {
		t.Fatal("no session.end ledger entry written")
	}
}

func TestSessionEnd_UnknownSessionReturns404(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	req, _ := http.NewRequest("POST", fx.srv.URL+"/v1/sessions/no-such-id/end", nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", res.StatusCode)
	}
}

func TestGateCheck_OnEndedSessionReturns410(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)

	req, _ := http.NewRequest("POST", fx.srv.URL+"/v1/sessions/"+fx.sessionID+"/end", nil)
	endRes, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer endRes.Body.Close()
	if endRes.StatusCode != http.StatusNoContent {
		t.Fatalf("end: %d", endRes.StatusCode)
	}

	body := fmt.Sprintf(`{"session_id":%q,"source":"claude-code","tool":"Bash","input":{"command":"ls"}}`, fx.sessionID)
	res, err := http.Post(fx.srv.URL+"/v1/gates/check", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST gate: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusGone {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d, want 410 Gone, body=%s", res.StatusCode, buf.String())
	}
}

func TestSessionRotate_UpdatesSignerPubkeyAndWritesLedger(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)

	// Build a new signed attestation with a fresh keypair. The policy hash
	// must still match the daemon's loaded policy.
	pol := policyHashFrom(t, enforcePolicyYAML)
	pub, priv, _ := ed25519.GenerateKey(nil)
	payload := signer.AttestationPayload{
		PolicyHash:    pol,
		SessionPubKey: "ed25519:" + hex.EncodeToString(pub),
		Signer:        "software",
		SignerPubKey:  "ed25519:" + hex.EncodeToString(pub),
	}
	canon := signer.CanonicalAttestation(payload)
	sig := ed25519.Sign(priv, canon)
	body := fmt.Sprintf(`{"policy_hash":%q,"session_pubkey":%q,"signer":"software","signer_pubkey":%q,"attestation":"ed25519:%s"}`,
		payload.PolicyHash, payload.SessionPubKey, payload.SignerPubKey, hex.EncodeToString(sig))

	res, err := http.Post(fx.srv.URL+"/v1/sessions/"+fx.sessionID+"/rotate", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST rotate: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d, body=%s", res.StatusCode, buf.String())
	}
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	if out["signer_pubkey"] != payload.SignerPubKey {
		t.Fatalf("rotated signer_pubkey = %v", out["signer_pubkey"])
	}

	// ledger.jsonl should have a session.rotate entry
	f, err := os.Open(filepath.Join(fx.home, "ledger.jsonl"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	found := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e map[string]any
		_ = json.Unmarshal(sc.Bytes(), &e)
		if e["tool_use_id"] == "session.rotate" {
			found = true
		}
	}
	if !found {
		t.Fatal("no session.rotate ledger entry written")
	}
}

func TestSessionRotate_UnknownSessionReturns404(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	pub, priv, _ := ed25519.GenerateKey(nil)
	p := signer.AttestationPayload{
		PolicyHash:    policyHashFrom(t, enforcePolicyYAML),
		SessionPubKey: "ed25519:" + hex.EncodeToString(pub),
		Signer:        "software",
		SignerPubKey:  "ed25519:" + hex.EncodeToString(pub),
	}
	canon := signer.CanonicalAttestation(p)
	sig := ed25519.Sign(priv, canon)
	body := fmt.Sprintf(`{"policy_hash":%q,"session_pubkey":%q,"signer":"software","signer_pubkey":%q,"attestation":"ed25519:%s"}`,
		p.PolicyHash, p.SessionPubKey, p.SignerPubKey, hex.EncodeToString(sig))
	res, err := http.Post(fx.srv.URL+"/v1/sessions/does-not-exist/rotate", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", res.StatusCode)
	}
}

