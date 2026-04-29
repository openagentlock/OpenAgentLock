// End-to-end tests for the optional auth surface. Spin up a router
// wired with a real password authenticator, drive /v1/auth/* plus one
// gated endpoint to confirm the 401/200 switch works.

package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openagentlock/openagentlock/control-plane/internal/auth"
	"github.com/openagentlock/openagentlock/control-plane/internal/storage"
)

// newAuthFixture spins up a router with AGENTLOCK_AUTH=password. The
// Deps includes a real Store so the gated paths (/v1/sessions,
// /v1/ledger/root, …) actually work end-to-end; the test only exercises
// the auth gate and doesn't care about their body shape.
type authFixture struct {
	srv       *httptest.Server
	homeDir   string
	authz     auth.Authenticator
	basicPass string
	basicUser string
}

func newAuthFixture(t *testing.T) authFixture {
	t.Helper()
	home := t.TempDir()
	store, err := storage.NewMemory(home)
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	cfg := auth.Config{
		Mode:            auth.ModePassword,
		HomeDir:         home,
		UsersDir:        filepath.Join(home, "auth"),
		TokenTTLSeconds: 60,
	}
	authz, err := auth.Build(cfg)
	if err != nil {
		t.Fatalf("auth.Build: %v", err)
	}

	srv := httptest.NewServer(NewRouter(Deps{
		Store:         store,
		Auth:          authz,
		AgentlockHome: home,
	}))
	t.Cleanup(srv.Close)

	return authFixture{srv: srv, homeDir: home, authz: authz,
		basicUser: "admin", basicPass: "correct-horse-battery"}
}

func postJSON(t *testing.T, url string, body string, headers http.Header) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return res
}

func TestAuthMode_ReportsPasswordBeforeBootstrap(t *testing.T) {
	fx := newAuthFixture(t)
	res, err := http.Get(fx.srv.URL + "/v1/auth/mode")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("code=%d", res.StatusCode)
	}
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	if out["mode"] != "password" {
		t.Fatalf("mode=%v, want password", out["mode"])
	}
	if out["users_configured"] != false {
		t.Fatalf("users_configured=%v, want false", out["users_configured"])
	}
}

func TestAuthBootstrap_HappyPath(t *testing.T) {
	fx := newAuthFixture(t)
	body := `{"username":"admin","password":"correct-horse-battery"}`
	res := postJSON(t, fx.srv.URL+"/v1/auth/bootstrap", body, nil)
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		buf, _ := io.ReadAll(res.Body)
		t.Fatalf("bootstrap code=%d body=%s", res.StatusCode, buf)
	}
	if fx.authz.UsersCount() != 1 {
		t.Fatalf("users count=%d, want 1", fx.authz.UsersCount())
	}
}

func TestAuthBootstrap_SecondCallReturns409(t *testing.T) {
	fx := newAuthFixture(t)
	body := `{"username":"admin","password":"correct-horse-battery"}`
	res := postJSON(t, fx.srv.URL+"/v1/auth/bootstrap", body, nil)
	res.Body.Close()
	res2 := postJSON(t, fx.srv.URL+"/v1/auth/bootstrap",
		`{"username":"other","password":"differentpasswordlongenough"}`, nil)
	defer res2.Body.Close()
	if res2.StatusCode != http.StatusConflict {
		t.Fatalf("second bootstrap code=%d, want 409", res2.StatusCode)
	}
}

func TestAuthLogin_IssuesBearerAndGatedEndpointsAccept(t *testing.T) {
	fx := newAuthFixture(t)
	boot := `{"username":"admin","password":"correct-horse-battery"}`
	_ = postJSON(t, fx.srv.URL+"/v1/auth/bootstrap", boot, nil).Body.Close()

	// Without a bearer, /v1/sessions must 401.
	res, err := http.Get(fx.srv.URL + "/v1/sessions")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth /v1/sessions code=%d, want 401", res.StatusCode)
	}
	res.Body.Close()

	// Login.
	loginRes := postJSON(t, fx.srv.URL+"/v1/auth/login", boot, nil)
	if loginRes.StatusCode != http.StatusOK {
		buf, _ := io.ReadAll(loginRes.Body)
		loginRes.Body.Close()
		t.Fatalf("login code=%d body=%s", loginRes.StatusCode, buf)
	}
	var lr map[string]any
	_ = json.NewDecoder(loginRes.Body).Decode(&lr)
	loginRes.Body.Close()
	tok, _ := lr["token"].(string)
	if tok == "" {
		t.Fatalf("login returned no token: %+v", lr)
	}

	// Now the same endpoint accepts the bearer.
	req, _ := http.NewRequest(http.MethodGet, fx.srv.URL+"/v1/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	r2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusOK {
		buf, _ := io.ReadAll(r2.Body)
		t.Fatalf("authed /v1/sessions code=%d body=%s", r2.StatusCode, buf)
	}
}

func TestAuthLogin_WrongPasswordReturns401(t *testing.T) {
	fx := newAuthFixture(t)
	boot := `{"username":"admin","password":"correct-horse-battery"}`
	_ = postJSON(t, fx.srv.URL+"/v1/auth/bootstrap", boot, nil).Body.Close()
	res := postJSON(t, fx.srv.URL+"/v1/auth/login",
		`{"username":"admin","password":"wrong-password-here"}`, nil)
	defer res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		buf, _ := io.ReadAll(res.Body)
		t.Fatalf("wrong pw code=%d body=%s", res.StatusCode, buf)
	}
}

func TestAuthHealthAlwaysAccessible(t *testing.T) {
	fx := newAuthFixture(t)
	// Even before bootstrap, /v1/health must respond.
	res, err := http.Get(fx.srv.URL + "/v1/health")
	if err != nil {
		t.Fatalf("GET /v1/health: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		buf, _ := io.ReadAll(res.Body)
		t.Fatalf("health code=%d body=%s", res.StatusCode, buf)
	}
}

func TestAuthLogout_RevokesToken(t *testing.T) {
	fx := newAuthFixture(t)
	boot := `{"username":"admin","password":"correct-horse-battery"}`
	_ = postJSON(t, fx.srv.URL+"/v1/auth/bootstrap", boot, nil).Body.Close()

	loginRes := postJSON(t, fx.srv.URL+"/v1/auth/login", boot, nil)
	var lr map[string]any
	_ = json.NewDecoder(loginRes.Body).Decode(&lr)
	loginRes.Body.Close()
	tok, _ := lr["token"].(string)

	logoutReq, _ := http.NewRequest(http.MethodPost, fx.srv.URL+"/v1/auth/logout", bytes.NewReader(nil))
	logoutReq.Header.Set("Authorization", "Bearer "+tok)
	lo, err := http.DefaultClient.Do(logoutReq)
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	lo.Body.Close()

	req, _ := http.NewRequest(http.MethodGet, fx.srv.URL+"/v1/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	r2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("after logout code=%d, want 401", r2.StatusCode)
	}
}

func TestAuthDisabled_LoginReturns501(t *testing.T) {
	// With auth.ModeNone (default) the endpoints still exist but login
	// returns 501 so the TUI can detect "no auth, no prompt needed".
	home := t.TempDir()
	store, _ := storage.NewMemory(home)
	t.Cleanup(func() { _ = store.Close() })
	authz, _ := auth.Build(auth.Config{Mode: auth.ModeNone})
	srv := httptest.NewServer(NewRouter(Deps{
		Store: store, Auth: authz, AgentlockHome: home,
	}))
	t.Cleanup(srv.Close)

	res := postJSON(t, srv.URL+"/v1/auth/login",
		`{"username":"a","password":"b"}`, nil)
	defer res.Body.Close()
	if res.StatusCode != http.StatusNotImplemented {
		t.Fatalf("auth=none login code=%d, want 501", res.StatusCode)
	}

	// mode endpoint still reports 'none'.
	r2, err := http.Get(srv.URL + "/v1/auth/mode")
	if err != nil {
		t.Fatalf("get mode: %v", err)
	}
	defer r2.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(r2.Body).Decode(&out)
	if out["mode"] != "none" {
		t.Fatalf("mode=%v, want none", out["mode"])
	}

	// And /v1/sessions works without any bearer (auth gate is off).
	r3, err := http.Get(srv.URL + "/v1/sessions")
	if err != nil {
		t.Fatalf("get sessions: %v", err)
	}
	defer r3.Body.Close()
	if r3.StatusCode != http.StatusOK {
		t.Fatalf("auth=none /v1/sessions code=%d, want 200", r3.StatusCode)
	}
}
