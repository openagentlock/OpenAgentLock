package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Argon2 hashes from a known password, so tests don't spend real CPU
// hashing on every run. We still exercise the hash/verify round-trip
// once in TestHashArgon2id_Roundtrip — the rest of the tests bootstrap
// via Bootstrap (which does hash) but that's only one per test.

func newTestAuth(t *testing.T) (*passwordAuth, Config) {
	t.Helper()
	home := t.TempDir()
	cfg := Config{
		Mode:            ModePassword,
		HomeDir:         home,
		UsersDir:        filepath.Join(home, "auth"),
		TokenTTLSeconds: 60,
	}
	p, err := newPasswordAuth(cfg)
	if err != nil {
		t.Fatalf("newPasswordAuth: %v", err)
	}
	return p, cfg
}

func TestBootstrap_CreatesFirstUser(t *testing.T) {
	p, cfg := newTestAuth(t)
	if err := p.Bootstrap("admin", "hunter2hunter"); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if p.UsersCount() != 1 {
		t.Fatalf("UsersCount after bootstrap = %d, want 1", p.UsersCount())
	}
	// File exists with 0600.
	info, err := os.Stat(filepath.Join(cfg.UsersDir, "users.json"))
	if err != nil {
		t.Fatalf("stat users.json: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("users.json mode = %v, want 0600", info.Mode().Perm())
	}
	// Stored hash is serialized argon2id, not plaintext.
	b, _ := os.ReadFile(filepath.Join(cfg.UsersDir, "users.json"))
	if !strings.Contains(string(b), "$argon2id$") {
		t.Fatalf("users.json doesn't contain argon2id hash; got: %s", b)
	}
	if strings.Contains(string(b), "hunter2hunter") {
		t.Fatalf("users.json contains plaintext password")
	}
}

func TestBootstrap_RefusesSecondUser(t *testing.T) {
	p, _ := newTestAuth(t)
	if err := p.Bootstrap("admin", "passwordpassword"); err != nil {
		t.Fatalf("bootstrap 1: %v", err)
	}
	err := p.Bootstrap("second", "differentpw123")
	if !errors.Is(err, ErrBootstrapDisabled) {
		t.Fatalf("bootstrap 2 err = %v, want ErrBootstrapDisabled", err)
	}
}

func TestBootstrap_RejectsShortPassword(t *testing.T) {
	p, _ := newTestAuth(t)
	err := p.Bootstrap("admin", "short")
	if !errors.Is(err, ErrPasswordTooShort) {
		t.Fatalf("err = %v, want ErrPasswordTooShort", err)
	}
}

func TestBootstrap_RejectsBadUsername(t *testing.T) {
	p, _ := newTestAuth(t)
	err := p.Bootstrap("bad user!", "longenoughpassword")
	if !errors.Is(err, ErrUsernameInvalid) {
		t.Fatalf("err = %v, want ErrUsernameInvalid", err)
	}
}

func TestLogin_IssuesBearerAndMiddlewareAccepts(t *testing.T) {
	p, _ := newTestAuth(t)
	if err := p.Bootstrap("admin", "correct-horse-battery"); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	res, err := p.Login("admin", "correct-horse-battery")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if res.Token == "" || res.Username != "admin" || res.ExpiresAt == 0 {
		t.Fatalf("login result incomplete: %+v", res)
	}

	// Middleware should allow a request with this bearer.
	handlerHit := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerHit = true
		w.WriteHeader(http.StatusOK)
	})
	h := p.Middleware(inner)

	r := httptest.NewRequest(http.MethodGet, "/v1/sessions", nil)
	r.Header.Set("Authorization", "Bearer "+res.Token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !handlerHit {
		t.Fatalf("middleware blocked valid bearer: code=%d hit=%v", w.Code, handlerHit)
	}
}

func TestMiddleware_AllowsPublicPaths(t *testing.T) {
	p, _ := newTestAuth(t)
	if err := p.Bootstrap("admin", "correct-horse-battery"); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	h := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for _, path := range []string{"/v1/health", "/v1/auth/login", "/v1/auth/mode", "/v1/auth/bootstrap"} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("public path %s blocked: %d", path, w.Code)
		}
	}
}

func TestMiddleware_RejectsMissingAndBadBearer(t *testing.T) {
	p, _ := newTestAuth(t)
	if err := p.Bootstrap("admin", "correct-horse-battery"); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	h := p.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	cases := []struct {
		name   string
		header string
		want   string
	}{
		{"missing", "", "missing_bearer"},
		{"not-bearer", "Basic abc", "missing_bearer"},
		{"junk-token", "Bearer not-a-real-token", "invalid_bearer"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/v1/sessions", nil)
			if c.header != "" {
				r.Header.Set("Authorization", c.header)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("%s: code = %d, want 401", c.name, w.Code)
			}
			if auth := w.Header().Get("WWW-Authenticate"); auth == "" {
				t.Fatalf("%s: missing WWW-Authenticate header", c.name)
			}
			var body map[string]string
			_ = json.NewDecoder(w.Body).Decode(&body)
			if body["error"] != c.want {
				t.Fatalf("%s: error = %q, want %q", c.name, body["error"], c.want)
			}
		})
	}
}

func TestLogin_BadCredentials(t *testing.T) {
	p, _ := newTestAuth(t)
	if err := p.Bootstrap("admin", "correct-horse-battery"); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	_, err := p.Login("admin", "wrong-password-value")
	if !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("err = %v, want ErrBadCredentials", err)
	}
	_, err = p.Login("unknown-user", "any-password-here")
	if !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("unknown user err = %v, want ErrBadCredentials", err)
	}
}

func TestLogout_InvalidatesToken(t *testing.T) {
	p, _ := newTestAuth(t)
	if err := p.Bootstrap("admin", "correct-horse-battery"); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	res, _ := p.Login("admin", "correct-horse-battery")
	p.Logout(res.Token)
	if p.validate(res.Token) {
		t.Fatalf("token still valid after logout")
	}
}

func TestLoadConfig_ModeDefault(t *testing.T) {
	t.Setenv("AGENTLOCK_AUTH", "")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Mode != ModeNone {
		t.Fatalf("default mode = %q, want %q", cfg.Mode, ModeNone)
	}
}

func TestLoadConfig_UnknownMode(t *testing.T) {
	t.Setenv("AGENTLOCK_AUTH", "magic")
	if _, err := LoadConfig(); err == nil {
		t.Fatalf("LoadConfig accepted bogus mode")
	}
}

func TestBuild_NoneReturnsAllowAll(t *testing.T) {
	a, err := Build(Config{Mode: ModeNone})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if a.Mode() != ModeNone {
		t.Fatalf("mode = %q, want none", a.Mode())
	}
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := a.Middleware(inner)
	r := httptest.NewRequest(http.MethodGet, "/v1/sessions", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("none middleware blocked request: %d", w.Code)
	}
}

func TestBuild_OIDCStubReturns501(t *testing.T) {
	a, err := Build(Config{Mode: ModeOIDC})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	h := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodGet, "/v1/sessions", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("oidc stub middleware code = %d, want 501", w.Code)
	}
}

func TestHashArgon2id_Roundtrip(t *testing.T) {
	h, err := hashArgon2id("plaintext-password-example")
	if err != nil {
		t.Fatalf("hashArgon2id: %v", err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$") {
		t.Fatalf("encoded hash has wrong prefix: %q", h)
	}
	if err := verifyArgon2id("plaintext-password-example", h); err != nil {
		t.Fatalf("verifyArgon2id (correct): %v", err)
	}
	if err := verifyArgon2id("nope-wrong-password", h); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("verifyArgon2id (wrong) = %v, want ErrBadCredentials", err)
	}
}

func TestPersistence_SurvivesReopen(t *testing.T) {
	home := t.TempDir()
	cfg := Config{
		Mode:            ModePassword,
		HomeDir:         home,
		UsersDir:        filepath.Join(home, "auth"),
		TokenTTLSeconds: 60,
	}
	p, err := newPasswordAuth(cfg)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	if err := p.Bootstrap("admin", "correct-horse-battery"); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	// Reopen using the same home.
	p2, err := newPasswordAuth(cfg)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if p2.UsersCount() != 1 {
		t.Fatalf("reopened instance has %d users, want 1", p2.UsersCount())
	}
	// Wrong password still rejected; correct password still works.
	if _, err := p2.Login("admin", "wrong-password-value"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("wrong password on reopen err = %v, want ErrBadCredentials", err)
	}
	if _, err := p2.Login("admin", "correct-horse-battery"); err != nil {
		t.Fatalf("correct password on reopen err = %v", err)
	}
}
