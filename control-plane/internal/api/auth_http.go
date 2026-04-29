// HTTP endpoints for optional auth.
//   GET  /v1/auth/mode       → {"mode":"password","users_configured":true}
//   POST /v1/auth/bootstrap  → one-shot first-user creator (refuses when
//                              users already exist; 409)
//   POST /v1/auth/login      → {username, password} → {token, expires_at}
//   POST /v1/auth/logout     → revokes the caller's bearer (requires auth)
//
// When AGENTLOCK_AUTH=none the endpoints still exist so a TUI can probe
// mode, but login/bootstrap return 501. The TUI reads /v1/auth/mode to
// decide whether to show the password prompt.

package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/openagentlock/openagentlock/control-plane/internal/auth"
)

type authLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type authBootstrapRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func authModeHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		mode := auth.Mode(auth.ModeNone)
		users := 0
		if d.Auth != nil {
			mode = d.Auth.Mode()
			users = d.Auth.UsersCount()
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"mode":             string(mode),
			"users_configured": users > 0,
			"users_count":      users,
		})
	}
}

func authLoginHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Auth == nil || d.Auth.Mode() == auth.ModeNone {
			writeError(w, http.StatusNotImplemented, "auth_disabled",
				"AGENTLOCK_AUTH is not set to password; login not required")
			return
		}
		var req authLoginRequest
		// Cap at 4 KiB — username + password easily fit. Prevents a
		// client from streaming GBs into the decoder.
		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		if req.Username == "" || req.Password == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "username and password required")
			return
		}
		res, err := d.Auth.Login(req.Username, req.Password)
		if err != nil {
			if errors.Is(err, auth.ErrBadCredentials) {
				writeError(w, http.StatusUnauthorized, "bad_credentials", "invalid username or password")
				return
			}
			if errors.Is(err, auth.ErrUnsupported) {
				writeError(w, http.StatusNotImplemented, "auth_mode_unsupported",
					"login not supported in this auth mode")
				return
			}
			log.Printf("auth.login: %v", err)
			writeError(w, http.StatusInternalServerError, "auth_error",
				"internal error; check daemon logs")
			return
		}
		writeJSON(w, http.StatusOK, res)
	}
}

func authBootstrapHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Auth == nil || d.Auth.Mode() == auth.ModeNone {
			writeError(w, http.StatusNotImplemented, "auth_disabled",
				"AGENTLOCK_AUTH is not set to password; bootstrap not applicable")
			return
		}
		if d.Auth.UsersCount() > 0 {
			writeError(w, http.StatusConflict, "already_bootstrapped",
				"users already exist; use the existing account or edit users.json")
			return
		}
		var req authBootstrapRequest
		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		if err := d.Auth.Bootstrap(req.Username, req.Password); err != nil {
			if errors.Is(err, auth.ErrUsernameInvalid) ||
				errors.Is(err, auth.ErrPasswordTooShort) {
				// These are safe to echo back — the message describes
				// the policy the caller violated, not internal state.
				writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
				return
			}
			if errors.Is(err, auth.ErrBootstrapDisabled) {
				writeError(w, http.StatusConflict, "already_bootstrapped",
					"users already exist; bootstrap is disabled")
				return
			}
			log.Printf("auth.bootstrap: %v", err)
			writeError(w, http.StatusInternalServerError, "auth_error",
				"internal error; check daemon logs")
			return
		}
		// Bootstrap does NOT auto-login — caller issues /v1/auth/login
		// afterwards. Keeps the flow symmetrical between bootstrap and
		// later user additions.
		writeJSON(w, http.StatusCreated, map[string]string{
			"username": req.Username,
			"hint":     "now POST /v1/auth/login with these credentials to get a bearer token",
		})
	}
}

func authLogoutHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Auth == nil || d.Auth.Mode() == auth.ModeNone {
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
			return
		}
		tok := extractBearerHeader(r.Header.Get("Authorization"))
		if tok != "" {
			d.Auth.Logout(tok)
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// extractBearerHeader duplicates a bit of auth.extractBearer because the
// auth package doesn't export it. Kept here so the API package doesn't
// need to leak implementation details back out.
func extractBearerHeader(h string) string {
	const prefix = "Bearer "
	if len(h) < len(prefix) {
		return ""
	}
	if !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}
