package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newMCPFixture(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	home := t.TempDir()
	pinPath := filepath.Join(home, "pinned-mcp.json")
	store := mustNewMemoryStore(t, home)
	srv := httptest.NewServer(NewRouter(Deps{
		Store:       store,
		PinStorePath: pinPath,
	}))
	t.Cleanup(srv.Close)
	return srv, pinPath
}

func TestMCPPin_Check_UnknownOnFirstQuery(t *testing.T) {
	srv, _ := newMCPFixture(t)
	body := `{"server":"filesystem","fingerprint":"sha256:aaaa"}`
	res, err := http.Post(srv.URL+"/v1/mcp/pin/check", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	if out["status"] != "unknown" {
		t.Fatalf("status = %v", out["status"])
	}
}

func TestMCPPin_Accept_PersistsToFile(t *testing.T) {
	srv, pinPath := newMCPFixture(t)
	body := `{"server":"github","fingerprint":"sha256:bbbb"}`
	res, err := http.Post(srv.URL+"/v1/mcp/pin/accept", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	raw, err := os.ReadFile(pinPath)
	if err != nil {
		t.Fatalf("read pin file: %v", err)
	}
	if !strings.Contains(string(raw), "github") || !strings.Contains(string(raw), "sha256:bbbb") {
		t.Fatalf("pin file: %q", raw)
	}
}

func TestMCPPin_CheckAfterAccept_Known(t *testing.T) {
	srv, _ := newMCPFixture(t)
	accept := `{"server":"slack","fingerprint":"sha256:cccc"}`
	aRes, err := http.Post(srv.URL+"/v1/mcp/pin/accept", "application/json", strings.NewReader(accept))
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	_ = aRes.Body.Close()

	check := `{"server":"slack","fingerprint":"sha256:cccc"}`
	res, err := http.Post(srv.URL+"/v1/mcp/pin/check", "application/json", strings.NewReader(check))
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	defer res.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out["status"] != "known" {
		t.Fatalf("status = %v", out["status"])
	}
}

func TestMCPPin_CheckAfterAccept_ChangedFingerprint(t *testing.T) {
	srv, _ := newMCPFixture(t)
	accept := `{"server":"notion","fingerprint":"sha256:dddd"}`
	aRes, err := http.Post(srv.URL+"/v1/mcp/pin/accept", "application/json", strings.NewReader(accept))
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	_ = aRes.Body.Close()

	check := `{"server":"notion","fingerprint":"sha256:ffff"}`
	res, err := http.Post(srv.URL+"/v1/mcp/pin/check", "application/json", strings.NewReader(check))
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	defer res.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out["status"] != "changed" {
		t.Fatalf("status = %v", out["status"])
	}
	if out["known_fingerprint"] != "sha256:dddd" {
		t.Fatalf("known_fingerprint = %v", out["known_fingerprint"])
	}
}

func TestMCPPin_BadBody400(t *testing.T) {
	srv, _ := newMCPFixture(t)
	cases := []string{`{}`, `{"server":""}`, `{"fingerprint":"x"}`}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			res, err := http.Post(srv.URL+"/v1/mcp/pin/check", "application/json", strings.NewReader(c))
			if err != nil {
				t.Fatalf("Post: %v", err)
			}
			defer res.Body.Close()
			if res.StatusCode != http.StatusBadRequest {
				t.Fatalf("body=%s got %d", c, res.StatusCode)
			}
		})
	}
}
