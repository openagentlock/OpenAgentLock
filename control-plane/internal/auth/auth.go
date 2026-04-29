// Optional auth for the control-plane. Default: `none` — loopback is the
// trust boundary (the existing v1 contract). Operators who run the
// daemon on a shared host flip it on via AGENTLOCK_AUTH=<mode>.
//
// Supported modes (as of this slice):
//   - none      ← default; every request is admitted
//   - password  ← file-backed argon2id users + bearer-token sessions
//   - oidc      ← stub; handler refuses at startup with a plan pointer
//   - ldap      ← stub; same
//
// The Authenticator returned by Build is always safe to call. When auth
// is disabled it short-circuits to Allow so callers don't need a nil
// check on every request.

package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type Mode string

const (
	ModeNone     Mode = "none"
	ModePassword Mode = "password"
	ModeOIDC     Mode = "oidc"
	ModeLDAP     Mode = "ldap"
)

// Config is the parsed authoritative view of AGENTLOCK_AUTH*.
type Config struct {
	Mode     Mode
	HomeDir  string // $AGENTLOCK_HOME; required when Mode != None
	UsersDir string // derived: filepath.Join(HomeDir, "auth")
	// TokenTTLSeconds caps how long a bearer is valid. 0 = use default.
	TokenTTLSeconds int64
}

// Authenticator handles two jobs: gate incoming requests (Middleware)
// and mint / revoke bearer tokens for the /v1/auth/* endpoints. An
// implementation MUST be safe for concurrent use.
type Authenticator interface {
	// Mode returns the configured mode so handlers can branch on it.
	Mode() Mode

	// Middleware wraps an inner handler with auth enforcement. It MUST
	// pass-through requests to paths returned by PublicPaths unchanged.
	Middleware(next http.Handler) http.Handler

	// PublicPaths lists paths that must not be auth-gated (health,
	// login). The router consults this before auth wrapping. Exact
	// match, case-sensitive.
	PublicPaths() map[string]struct{}

	// Login issues a bearer token for correct (username, password).
	// Returns ErrUnsupported when Mode != password.
	Login(username, password string) (LoginResult, error)

	// Logout revokes a bearer token. No-op for unknown tokens.
	Logout(token string)

	// Bootstrap creates the first user when users.json doesn't exist.
	// Returns ErrBootstrapDisabled when users.json already has entries
	// so a running daemon can't be silently reseeded.
	Bootstrap(username, password string) error

	// UsersCount returns the number of configured users (0 in none mode).
	UsersCount() int
}

// LoginResult is what /v1/auth/login returns on success.
type LoginResult struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"` // unix seconds
	Username  string `json:"username"`
}

var (
	ErrUnsupported       = errors.New("auth: operation not supported in this mode")
	ErrBadCredentials    = errors.New("auth: invalid username or password")
	ErrBootstrapDisabled = errors.New("auth: users already bootstrapped")
	ErrUsernameInvalid   = errors.New("auth: username must be 1-64 chars, alnum + _-.")
	ErrPasswordTooShort  = errors.New("auth: password must be at least 10 characters")
)

// LoadConfig builds a Config from the process environment. Returns a
// validated Config or a descriptive error. Does NOT touch the
// filesystem; that happens lazily in Build when the Authenticator boots.
func LoadConfig() (Config, error) {
	mode := Mode(strings.ToLower(strings.TrimSpace(os.Getenv("AGENTLOCK_AUTH"))))
	if mode == "" {
		mode = ModeNone
	}
	switch mode {
	case ModeNone, ModePassword, ModeOIDC, ModeLDAP:
	default:
		return Config{}, fmt.Errorf("auth: unknown AGENTLOCK_AUTH=%q (want none|password|oidc|ldap)", mode)
	}
	home := os.Getenv("AGENTLOCK_HOME")
	if home == "" {
		if mode == ModePassword {
			// Refuse to store real password hashes inside a volatile
			// tempdir that the OS will wipe on reboot. Force the
			// operator to pick a stable location.
			return Config{}, fmt.Errorf("auth: AGENTLOCK_HOME must be set when AGENTLOCK_AUTH=password (credentials would otherwise live in os.TempDir())")
		}
		home = filepath.Join(os.TempDir(), "agentlock-home")
	}
	return Config{
		Mode:            mode,
		HomeDir:         home,
		UsersDir:        filepath.Join(home, "auth"),
		TokenTTLSeconds: 24 * 60 * 60,
	}, nil
}

// Build returns an Authenticator matching the config. The returned
// instance is always non-nil and safe to call. When Mode is oidc or
// ldap, Build returns a stub that refuses every login with a helpful
// pointer to the tracking issue — the daemon starts up so ops can still
// hit /v1/health, but gated endpoints return 501.
func Build(cfg Config) (Authenticator, error) {
	switch cfg.Mode {
	case ModeNone, "":
		return &noneAuth{}, nil
	case ModePassword:
		return newPasswordAuth(cfg)
	case ModeOIDC:
		return &stubAuth{mode: ModeOIDC, hint: "OIDC auth is not wired yet; see docs/guide/auth.md"}, nil
	case ModeLDAP:
		return &stubAuth{mode: ModeLDAP, hint: "LDAP auth is not wired yet; see docs/guide/auth.md"}, nil
	}
	return nil, fmt.Errorf("auth: unreachable mode %q", cfg.Mode)
}

// -- none: allow-all ---------------------------------------------------

type noneAuth struct{}

func (n *noneAuth) Mode() Mode                         { return ModeNone }
func (n *noneAuth) Middleware(h http.Handler) http.Handler { return h }
func (n *noneAuth) PublicPaths() map[string]struct{}    { return map[string]struct{}{} }
func (n *noneAuth) Login(string, string) (LoginResult, error) {
	return LoginResult{}, ErrUnsupported
}
func (n *noneAuth) Logout(string)                       {}
func (n *noneAuth) Bootstrap(string, string) error      { return ErrUnsupported }
func (n *noneAuth) UsersCount() int                     { return 0 }

// -- oidc / ldap: 501-until-implemented --------------------------------

type stubAuth struct {
	mode Mode
	hint string
}

func (s *stubAuth) Mode() Mode { return s.mode }
func (s *stubAuth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/health" {
			next.ServeHTTP(w, r)
			return
		}
		// Use the encoding/json path so escaping is correct for any
		// mode / hint that might contain quotes or control characters.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": "auth_mode_not_implemented",
			"mode":  string(s.mode),
			"hint":  s.hint,
		})
	})
}
func (s *stubAuth) PublicPaths() map[string]struct{} {
	return map[string]struct{}{"/v1/health": {}}
}
func (s *stubAuth) Login(string, string) (LoginResult, error) { return LoginResult{}, ErrUnsupported }
func (s *stubAuth) Logout(string)                              {}
func (s *stubAuth) Bootstrap(string, string) error             { return ErrUnsupported }
func (s *stubAuth) UsersCount() int                            { return 0 }
