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
		Store:        store,
		PinStorePath: pinPath,
	}))
	t.Cleanup(srv.Close)
	return srv, pinPath
}

func TestMCPPin_Check_UnknownOnFirstQuery(t *testing.T) {
	srv, _ := newMCPFixture(t)
	body := `{"server":"filesystem","fingerprint":"sha256:aaaa","server_info":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem"]}}`
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

	pending := listPendingMCPPins(t, srv)
	if len(pending) != 1 {
		t.Fatalf("pending len = %d", len(pending))
	}
	if pending[0].Server != "filesystem" || pending[0].Fingerprint != "sha256:aaaa" || pending[0].Status != "unknown" {
		t.Fatalf("pending row = %+v", pending[0])
	}
	if pending[0].ID == "" || pending[0].CreatedAt == "" || pending[0].UpdatedAt == "" {
		t.Fatalf("pending timestamps/id not set: %+v", pending[0])
	}
	if pending[0].ServerInfo["command"] != "npx" {
		t.Fatalf("server_info = %+v", pending[0].ServerInfo)
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
	checkPending := `{"server":"slack","fingerprint":"sha256:cccc"}`
	pRes, err := http.Post(srv.URL+"/v1/mcp/pin/check", "application/json", strings.NewReader(checkPending))
	if err != nil {
		t.Fatalf("pending check: %v", err)
	}
	_ = pRes.Body.Close()

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
	if pending := listPendingMCPPins(t, srv); len(pending) != 0 {
		t.Fatalf("pending len after known check = %d: %+v", len(pending), pending)
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

	pending := listPendingMCPPins(t, srv)
	if len(pending) != 1 {
		t.Fatalf("pending len = %d", len(pending))
	}
	if pending[0].Status != "changed" || pending[0].KnownFingerprint != "sha256:dddd" {
		t.Fatalf("pending changed row = %+v", pending[0])
	}
}

func TestMCPPin_Accept_RemovesMatchingPendingPin(t *testing.T) {
	srv, _ := newMCPFixture(t)
	check := `{"server":"linear","fingerprint":"sha256:pending"}`
	cRes, err := http.Post(srv.URL+"/v1/mcp/pin/check", "application/json", strings.NewReader(check))
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	_ = cRes.Body.Close()

	accept := `{"server":"linear","fingerprint":"sha256:pending"}`
	aRes, err := http.Post(srv.URL+"/v1/mcp/pin/accept", "application/json", strings.NewReader(accept))
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	_ = aRes.Body.Close()

	if pending := listPendingMCPPins(t, srv); len(pending) != 0 {
		t.Fatalf("pending len after accept = %d: %+v", len(pending), pending)
	}
}

func TestMCPPin_Refuse_RemovesPendingPin(t *testing.T) {
	srv, _ := newMCPFixture(t)
	check := `{"server":"notion","fingerprint":"sha256:refuse"}`
	cRes, err := http.Post(srv.URL+"/v1/mcp/pin/check", "application/json", strings.NewReader(check))
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	_ = cRes.Body.Close()

	refuse := `{"server":"notion","fingerprint":"sha256:refuse"}`
	res, err := http.Post(srv.URL+"/v1/mcp/pin/refuse", "application/json", strings.NewReader(refuse))
	if err != nil {
		t.Fatalf("refuse: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out["refused"] != true || out["server"] != "notion" {
		t.Fatalf("refuse response = %+v", out)
	}
	if pending := listPendingMCPPins(t, srv); len(pending) != 0 {
		t.Fatalf("pending len after refuse = %d: %+v", len(pending), pending)
	}
}

func TestMCPPin_List_ReturnsCurrentPinsSortedByServer(t *testing.T) {
	srv, pinPath := newMCPFixture(t)
	raw := []byte(`{"slack":"sha256:cccc","github":"sha256:bbbb"}`)
	if err := os.WriteFile(pinPath, raw, 0o600); err != nil {
		t.Fatalf("write pin file: %v", err)
	}

	res, err := http.Get(srv.URL + "/v1/mcp/pins")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	var out struct {
		Pins []struct {
			Server      string `json:"server"`
			Fingerprint string `json:"fingerprint"`
		} `json:"pins"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Pins) != 2 {
		t.Fatalf("pins len = %d", len(out.Pins))
	}
	if out.Pins[0].Server != "github" || out.Pins[0].Fingerprint != "sha256:bbbb" {
		t.Fatalf("first pin = %+v", out.Pins[0])
	}
	if out.Pins[1].Server != "slack" || out.Pins[1].Fingerprint != "sha256:cccc" {
		t.Fatalf("second pin = %+v", out.Pins[1])
	}
}

func TestMCPPin_List_MissingFileReturnsEmptyPins(t *testing.T) {
	srv, _ := newMCPFixture(t)

	res, err := http.Get(srv.URL + "/v1/mcp/pins")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	var out struct {
		Pins []struct {
			Server      string `json:"server"`
			Fingerprint string `json:"fingerprint"`
		} `json:"pins"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Pins) != 0 {
		t.Fatalf("pins len = %d", len(out.Pins))
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

type pendingMCPPinForTest struct {
	ID               string         `json:"id"`
	Server           string         `json:"server"`
	Fingerprint      string         `json:"fingerprint"`
	KnownFingerprint string         `json:"known_fingerprint,omitempty"`
	Status           string         `json:"status"`
	ServerInfo       map[string]any `json:"server_info,omitempty"`
	CreatedAt        string         `json:"created_at"`
	UpdatedAt        string         `json:"updated_at"`
}

func listPendingMCPPins(t *testing.T, srv *httptest.Server) []pendingMCPPinForTest {
	t.Helper()
	res, err := http.Get(srv.URL + "/v1/mcp/pins")
	if err != nil {
		t.Fatalf("GET pins: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	var out struct {
		Pending []pendingMCPPinForTest `json:"pending"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out.Pending
}
