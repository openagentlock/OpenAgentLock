package api

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fireGateCheck(t *testing.T, fx gateFixture, cmd string) {
	t.Helper()
	body := fmt.Sprintf(`{
		"session_id": %q,
		"source": "claude-code",
		"tool": "Bash",
		"input": {"command": %q}
	}`, fx.sessionID, cmd)
	res, err := http.Post(fx.srv.URL+"/v1/gates/check", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST gate: %v", err)
	}
	_ = res.Body.Close()
}

func TestLedgerRoot_EmptyStoreReturnsSha256OfEmpty(t *testing.T) {
	// Bare store, no session, no gates. Merkle root of zero leaves = sha256("").
	home := t.TempDir()
	store := mustNewMemoryStore(t, home)
	srv := httptest.NewServer(NewRouter(Deps{Store: store}))
	defer srv.Close()

	res, err := http.Get(srv.URL + "/v1/ledger/root")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	// sha256 of empty byte string
	wantRoot := "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if out["root"] != wantRoot {
		t.Fatalf("root = %v, want %v", out["root"], wantRoot)
	}
	if got, _ := out["count"].(float64); got != 0 {
		t.Fatalf("count = %v", out["count"])
	}
}

func TestLedgerRoot_AfterOneGateCheck(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	fireGateCheck(t, fx, "ls -la")

	res, err := http.Get(fx.srv.URL + "/v1/ledger/root")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	// session.create seq 0 + gate.check seq 1
	if got := int(out["count"].(float64)); got != 2 {
		t.Fatalf("count = %d", got)
	}
	if got := int(out["seq"].(float64)); got != 1 {
		t.Fatalf("seq = %d", got)
	}
	root, _ := out["root"].(string)
	if !strings.HasPrefix(root, "sha256:") {
		t.Fatalf("root format: %q", root)
	}
	if len(root) != len("sha256:")+64 {
		t.Fatalf("root hex length: %q", root)
	}
}

func TestLedgerRoot_StableAcrossReads(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	fireGateCheck(t, fx, "ls")
	fireGateCheck(t, fx, "pwd")

	var roots []string
	for i := 0; i < 3; i++ {
		res, _ := http.Get(fx.srv.URL + "/v1/ledger/root")
		var out map[string]any
		_ = json.NewDecoder(res.Body).Decode(&out)
		_ = res.Body.Close()
		roots = append(roots, out["root"].(string))
	}
	if roots[0] != roots[1] || roots[1] != roots[2] {
		t.Fatalf("root changed between reads: %v", roots)
	}
}

func TestLedgerVerify_OKWhenUntampered(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	fireGateCheck(t, fx, "ls")

	res, err := http.Post(fx.srv.URL+"/v1/ledger/verify", "application/json", nil)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	if out["ok"] != true {
		t.Fatalf("ok = %v, reason = %v", out["ok"], out["reason"])
	}
	root, _ := out["root"].(string)
	if !strings.HasPrefix(root, "sha256:") {
		t.Fatalf("root: %q", root)
	}
}

func TestLedgerVerify_FailsOnTamperedLeafHash(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)
	fireGateCheck(t, fx, "ls")

	// Edit ledger.jsonl on disk: flip a byte in the last leaf's stored sig.
	// That re-derives to a different leaf, which no longer matches the stored
	// leaf_hash — verify must flag it.
	p := filepath.Join(fx.home, "ledger.jsonl")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected >=2 lines, got %d", len(lines))
	}
	var entry map[string]any
	_ = json.Unmarshal([]byte(lines[1]), &entry)
	oldPH, _ := entry["payload_hash"].(string)
	// Corrupt by prepending "dead"; decoded length changes too, which is fine:
	// verifyEntry will refuse to match the stored leaf_hash regardless.
	entry["payload_hash"] = "dead" + oldPH
	bad, _ := json.Marshal(entry)
	lines[1] = string(bad)
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	res, err := http.Post(fx.srv.URL+"/v1/ledger/verify", "application/json", nil)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	if out["ok"] != false {
		t.Fatalf("want ok=false, got %v", out)
	}
	if out["first_bad_at"] == nil {
		t.Fatalf("first_bad_at missing: %v", out)
	}
}

// Helper that opens a *storage.Memory without importing it everywhere.
func mustNewMemoryStore(t *testing.T, home string) *memoryStoreShim {
	t.Helper()
	s, err := newMemoryForTest(home)
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// Quick sanity: the Merkle root of one session-less test returns sha256("")
// via Rust FFI — useful isolation from the gate fixture.
func TestLedgerRoot_ResponseHeaderIsJSON(t *testing.T) {
	home := t.TempDir()
	store := mustNewMemoryStore(t, home)
	srv := httptest.NewServer(NewRouter(Deps{Store: store}))
	defer srv.Close()

	res, err := http.Get(srv.URL + "/v1/ledger/root")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer res.Body.Close()
	if ct := res.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("content-type = %q", ct)
	}
	// Silence unused imports if compiler optimizes.
	_ = hex.EncodeToString
}
