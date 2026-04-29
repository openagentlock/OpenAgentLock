// Password-backed auth. Users live in $AGENTLOCK_HOME/auth/users.json,
// passwords are hashed with argon2id, and successful logins get an
// in-memory bearer token with a TTL. Tokens are random 32-byte values
// encoded as URL-safe base64 — no JWT, no HMAC secret to manage.

package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// argon2 params roughly matching OWASP 2024 guidance for interactive
// login. Tuned to ~50-100ms on a modern laptop; runs once per login.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

var usernameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

type user struct {
	Username string `json:"username"`
	Hash     string `json:"hash"` // argon2id serialized form
}

type usersFile struct {
	Users []user `json:"users"`
}

type tokenEntry struct {
	username string
	expires  time.Time
}

type passwordAuth struct {
	mu        sync.RWMutex
	usersPath string
	users     map[string]user
	tokens    map[string]tokenEntry
	ttl       time.Duration
}

func newPasswordAuth(cfg Config) (*passwordAuth, error) {
	if cfg.HomeDir == "" {
		return nil, fmt.Errorf("auth: AGENTLOCK_HOME must be set for password mode")
	}
	p := &passwordAuth{
		usersPath: filepath.Join(cfg.UsersDir, "users.json"),
		users:     map[string]user{},
		tokens:    map[string]tokenEntry{},
		ttl:       time.Duration(cfg.TokenTTLSeconds) * time.Second,
	}
	if err := os.MkdirAll(cfg.UsersDir, 0o700); err != nil {
		return nil, fmt.Errorf("auth: mkdir %s: %w", cfg.UsersDir, err)
	}
	if err := p.load(); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *passwordAuth) Mode() Mode { return ModePassword }

func (p *passwordAuth) PublicPaths() map[string]struct{} {
	return map[string]struct{}{
		"/v1/health":          {},
		"/v1/auth/login":      {},
		"/v1/auth/bootstrap":  {},
		"/v1/auth/mode":       {}, // exposes whether auth is on so the TUI knows to show the login screen
	}
}

func (p *passwordAuth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := p.PublicPaths()[r.URL.Path]; ok {
			next.ServeHTTP(w, r)
			return
		}
		tok := extractBearer(r.Header.Get("Authorization"))
		if tok == "" {
			p.respond401(w, "missing_bearer", "Authorization: Bearer <token> required")
			return
		}
		if !p.validate(tok) {
			p.respond401(w, "invalid_bearer", "token unknown or expired; re-login via /v1/auth/login")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (p *passwordAuth) Login(username, password string) (LoginResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	u, ok := p.users[strings.ToLower(username)]
	if !ok {
		// Constant-time compare against a dummy hash to mask user enum.
		_ = verifyArgon2id("dummy", "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
		return LoginResult{}, ErrBadCredentials
	}
	if err := verifyArgon2id(password, u.Hash); err != nil {
		return LoginResult{}, ErrBadCredentials
	}
	tok, err := randomToken()
	if err != nil {
		return LoginResult{}, fmt.Errorf("auth: random: %w", err)
	}
	expires := time.Now().Add(p.ttl)
	p.tokens[tok] = tokenEntry{username: u.Username, expires: expires}
	return LoginResult{
		Token:     tok,
		ExpiresAt: expires.Unix(),
		Username:  u.Username,
	}, nil
}

func (p *passwordAuth) Logout(token string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.tokens, token)
}

func (p *passwordAuth) Bootstrap(username, password string) error {
	if !usernameRE.MatchString(username) {
		return ErrUsernameInvalid
	}
	if len(password) < 10 {
		return ErrPasswordTooShort
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.users) > 0 {
		return ErrBootstrapDisabled
	}
	hash, err := hashArgon2id(password)
	if err != nil {
		return err
	}
	p.users[strings.ToLower(username)] = user{Username: username, Hash: hash}
	return p.save()
}

func (p *passwordAuth) UsersCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.users)
}

// -- persistence --------------------------------------------------------

func (p *passwordAuth) load() error {
	b, err := os.ReadFile(p.usersPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // empty file; bootstrap will create
		}
		return fmt.Errorf("auth: read %s: %w", p.usersPath, err)
	}
	var uf usersFile
	if err := json.Unmarshal(b, &uf); err != nil {
		return fmt.Errorf("auth: parse %s: %w", p.usersPath, err)
	}
	for _, u := range uf.Users {
		p.users[strings.ToLower(u.Username)] = u
	}
	return nil
}

func (p *passwordAuth) save() error {
	list := make([]user, 0, len(p.users))
	for _, u := range p.users {
		list = append(list, u)
	}
	b, err := json.MarshalIndent(usersFile{Users: list}, "", "  ")
	if err != nil {
		return err
	}
	tmp := p.usersPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p.usersPath)
}

// -- tokens -------------------------------------------------------------

func (p *passwordAuth) validate(token string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	entry, ok := p.tokens[token]
	if !ok {
		return false
	}
	if time.Now().After(entry.expires) {
		delete(p.tokens, token)
		return false
	}
	return true
}

func (p *passwordAuth) respond401(w http.ResponseWriter, code, hint string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", `Bearer realm="openagentlock"`)
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": code,
		"hint":  hint,
	})
}

func extractBearer(h string) string {
	if h == "" {
		return ""
	}
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func randomToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// -- argon2id --------------------------------------------------------------

func hashArgon2id(pw string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return encodeArgon2id(salt, key), nil
}

func encodeArgon2id(salt, key []byte) string {
	return fmt.Sprintf(
		"$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
}

func verifyArgon2id(pw, encoded string) error {
	// Expected:
	//   $argon2id$v=19$m=65536,t=3,p=4$<b64salt>$<b64hash>
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return fmt.Errorf("auth: unsupported argon2 format")
	}
	var mem, tm, par int
	// Using fmt.Sscanf is tolerable here — one allocation, tiny input.
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &tm, &par); err != nil {
		return fmt.Errorf("auth: unsupported argon2 params: %w", err)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return fmt.Errorf("auth: bad argon2 salt: %w", err)
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return fmt.Errorf("auth: bad argon2 hash: %w", err)
	}
	got := argon2.IDKey([]byte(pw), salt, uint32(tm), uint32(mem), uint8(par), uint32(len(want)))
	if subtle.ConstantTimeCompare(want, got) != 1 {
		return ErrBadCredentials
	}
	return nil
}

// FingerprintToken returns a short, non-sensitive string for logging.
// Use this instead of the raw token in server logs.
func FingerprintToken(token string) string {
	if len(token) < 8 {
		return "<short>"
	}
	// First 4 bytes of the base64 is enough to disambiguate in logs
	// without revealing the token — attackers still need the full 32-byte
	// random to forge one.
	return hex.EncodeToString([]byte(token[:4])) + "…"
}
