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

	"github.com/openagentlock/openagentlock/control-plane/internal/signer"
	"github.com/openagentlock/openagentlock/control-plane/internal/storage"
)

type signedFixture struct {
	body    string
	home    string
	pub     ed25519.PublicKey
	priv    ed25519.PrivateKey
	canonJS string
}

// newSignedFixture builds a fresh keypair + signed attestation + request body.
// Individual tests mutate `body` (e.g. strip a field, scramble the signature)
// before posting.
func newSignedFixture(t *testing.T) signedFixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	payload := signer.AttestationPayload{
		PolicyHash:    "sha256:aaaa",
		SessionPubKey: "ed25519:" + hex.EncodeToString(pub),
		Signer:        "software",
		SignerPubKey:  "ed25519:" + hex.EncodeToString(pub),
	}
	canon := signer.CanonicalAttestation(payload)
	sig := ed25519.Sign(priv, canon)
	body := fmt.Sprintf(`{
		"policy_hash": %q,
		"session_pubkey": %q,
		"signer": "software",
		"signer_pubkey": %q,
		"attestation": "ed25519:%s"
	}`, payload.PolicyHash, payload.SessionPubKey, payload.SignerPubKey, hex.EncodeToString(sig))

	return signedFixture{body: body, home: t.TempDir(), pub: pub, priv: priv, canonJS: string(canon)}
}

func newRouterWithStore(t *testing.T, home string) (http.Handler, *storage.Memory) {
	t.Helper()
	store, err := storage.NewMemory(home)
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return NewRouter(Deps{Store: store}), store
}

func TestCreateSession_201AndBodyShape(t *testing.T) {
	fx := newSignedFixture(t)
	r, _ := newRouterWithStore(t, fx.home)
	srv := httptest.NewServer(r)
	defer srv.Close()

	res, err := http.Post(srv.URL+"/v1/sessions", "application/json", strings.NewReader(fx.body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("status = %d, body = %s", res.StatusCode, buf.String())
	}
	var out map[string]any
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, want := range []string{"id", "started_at", "expires_at", "policy_hash", "session_pubkey", "signer", "signer_pubkey"} {
		if _, ok := out[want]; !ok {
			t.Fatalf("response missing %s: %+v", want, out)
		}
	}
	if out["signer"] != "software" {
		t.Fatalf("signer echo mismatch: %v", out["signer"])
	}
}

func TestCreateSession_WritesLedgerEntry(t *testing.T) {
	fx := newSignedFixture(t)
	r, _ := newRouterWithStore(t, fx.home)
	srv := httptest.NewServer(r)
	defer srv.Close()

	res, err := http.Post(srv.URL+"/v1/sessions", "application/json", strings.NewReader(fx.body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d", res.StatusCode)
	}

	f, err := os.Open(filepath.Join(fx.home, "ledger.jsonl"))
	if err != nil {
		t.Fatalf("open ledger: %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	lines := 0
	for sc.Scan() {
		lines++
		var entry map[string]any
		if err := json.Unmarshal(sc.Bytes(), &entry); err != nil {
			t.Fatalf("bad json: %v", err)
		}
		if entry["source"] != "system" {
			t.Fatalf("source = %v, want system", entry["source"])
		}
		if entry["tool_use_id"] != "session.create" {
			t.Fatalf("tool_use_id = %v, want session.create", entry["tool_use_id"])
		}
		if entry["signer"] != "software" {
			t.Fatalf("signer = %v", entry["signer"])
		}
	}
	if lines != 1 {
		t.Fatalf("want 1 ledger line, got %d", lines)
	}
}

func TestCreateSession_BadSignatureRejected(t *testing.T) {
	fx := newSignedFixture(t)
	// Replace the `ed25519:...` sig bytes with a fresh valid-length but wrong sig.
	bogus := make([]byte, ed25519.SignatureSize)
	bogus[0] = 0x01
	body := strings.Replace(fx.body, `"attestation": "ed25519:`,
		`"attestation": "ed25519:`+hex.EncodeToString(bogus)+`","_dead":"`, 1)
	// Simpler: rebuild with bogus sig.
	var m map[string]any
	_ = json.Unmarshal([]byte(fx.body), &m)
	m["attestation"] = "ed25519:" + hex.EncodeToString(bogus)
	b, _ := json.Marshal(m)
	body = string(b)

	r, _ := newRouterWithStore(t, fx.home)
	srv := httptest.NewServer(r)
	defer srv.Close()

	res, err := http.Post(srv.URL+"/v1/sessions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("want 401, got %d body=%s", res.StatusCode, buf.String())
	}
}

func TestCreateSession_MissingFieldRejected(t *testing.T) {
	fx := newSignedFixture(t)
	var m map[string]any
	_ = json.Unmarshal([]byte(fx.body), &m)
	delete(m, "policy_hash")
	b, _ := json.Marshal(m)

	r, _ := newRouterWithStore(t, fx.home)
	srv := httptest.NewServer(r)
	defer srv.Close()

	res, err := http.Post(srv.URL+"/v1/sessions", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", res.StatusCode)
	}
}

func TestCreateSession_UnknownSignerKindRejected(t *testing.T) {
	fx := newSignedFixture(t)
	var m map[string]any
	_ = json.Unmarshal([]byte(fx.body), &m)
	m["signer"] = "brain-waves"
	b, _ := json.Marshal(m)

	r, _ := newRouterWithStore(t, fx.home)
	srv := httptest.NewServer(r)
	defer srv.Close()

	res, err := http.Post(srv.URL+"/v1/sessions", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", res.StatusCode)
	}
}

func TestCreateSession_RequestWithBadHexRejected(t *testing.T) {
	fx := newSignedFixture(t)
	var m map[string]any
	_ = json.Unmarshal([]byte(fx.body), &m)
	m["signer_pubkey"] = "ed25519:notvalidhex"
	b, _ := json.Marshal(m)

	r, _ := newRouterWithStore(t, fx.home)
	srv := httptest.NewServer(r)
	defer srv.Close()

	res, err := http.Post(srv.URL+"/v1/sessions", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", res.StatusCode)
	}
}
