// Router stitches handlers onto the canonical paths from api/openapi.yaml.
// Handler bodies return 501 until the OpenAgentLock API is signed off.
//
// Intentionally written for Go 1.21 (no method-in-pattern syntax). We
// dispatch on method inside each handler and return 405 on mismatch.

package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/openagentlock/openagentlock/control-plane/internal/auth"
	"github.com/openagentlock/openagentlock/control-plane/internal/policy"
	"github.com/openagentlock/openagentlock/control-plane/internal/storage"
)

type route struct {
	method  string
	pattern string   // plain path, exact unless it contains {param}
	handler http.HandlerFunc
}

// Deps carries handler dependencies. Nil fields are tolerated so router_test
// can build a bare router for the 501 contract check.
type Deps struct {
	Store         storage.Storage
	Policy        *policy.Policy
	PinStorePath  string
	AgentlockHome string
	// PolicyPath is the on-disk YAML the daemon loaded at startup. When
	// set, policy CRUD endpoints persist changes back to it; when empty
	// (ephemeral / test) changes stay in memory only.
	PolicyPath string
	// Auth gates every /v1/* request when its Mode() != none. nil is
	// treated as none (no gate). See internal/auth for the modes.
	Auth auth.Authenticator
}

func NewRouter(deps ...Deps) http.Handler {
	var d Deps
	if len(deps) > 0 {
		d = deps[0]
	}
	// Seed the live-policy registry the first time we see a Deps with a
	// policy attached. Tests run many routers per process so this is
	// idempotent — Swap always promotes the latest policy and keeps the
	// previous one pinned by hash.
	if d.Policy != nil {
		bootstrapPolicy(d.Policy)
	}

	routes := []route{
		{"GET", "/v1/health", health},

		// Sessions.
		{"POST", "/v1/sessions", createSessionHandler(d)},
		{"POST", "/v1/sessions/unattested", unattestedSessionHandler(d)},
		{"POST", "/v1/sessions/{id}/rotate", sessionRotateHandler(d)},
		{"POST", "/v1/sessions/{id}/end", sessionEndHandler(d)},

		// Gates.
		{"POST", "/v1/gates/check", gateCheckHandler(d)},
		{"POST", "/v1/approvals/{id}/approve", todo("approval.approve")},
		{"POST", "/v1/approvals/{id}/refuse", todo("approval.refuse")},
		{"GET", "/v1/approvals/pending", todo("approval.pending")},

		// Harness-native hook endpoints (accept harness JSON shape, emit
		// harness JSON shape). Auto-create unattested session on first hit.
		{"POST", "/v1/hooks/claude-code/session-start", claudeSessionStartHandler(d)},
		{"POST", "/v1/hooks/claude-code/pre-tool-use", claudePreToolUseHandler(d)},
		{"POST", "/v1/hooks/claude-code/post-tool-use", claudePostToolUseHandler(d)},
		{"POST", "/v1/hooks/claude-code/stop", claudeStopHandler(d)},
		{"POST", "/v1/hooks/codex/session-start", codexSessionStartHandler(d)},
		{"POST", "/v1/hooks/codex/pre-tool-use", codexPreToolUseHandler(d)},
		{"POST", "/v1/hooks/codex/post-tool-use", codexPostToolUseHandler(d)},
		{"POST", "/v1/hooks/codex/stop", codexStopHandler(d)},
		{"POST", "/v1/hooks/cursor/session-start", cursorSessionStartHandler(d)},
		{"POST", "/v1/hooks/cursor/pre-tool-use", cursorPreToolUseHandler(d)},
		{"POST", "/v1/hooks/cursor/before-shell-execution", cursorBeforeShellHandler(d)},
		{"POST", "/v1/hooks/cursor/before-mcp-execution", cursorBeforeMCPHandler(d)},
		{"POST", "/v1/hooks/cursor/after-mcp-execution", cursorAfterMCPHandler(d)},
		{"POST", "/v1/hooks/cursor/post-tool-use", cursorPostToolUseHandler(d)},
		{"POST", "/v1/hooks/cursor/stop", cursorStopHandler(d)},

		// MCP TOFU pinning.
		{"POST", "/v1/mcp/pin/check", mcpPinCheckHandler(d)},
		{"POST", "/v1/mcp/pin/accept", mcpPinAcceptHandler(d)},

		// Daemon mode + policy (read + CRUD for the dashboard Rules tab).
		{"GET", "/v1/mode", modeGetHandler(d)},
		{"PATCH", "/v1/mode", modePatchHandler(d)},
		{"GET", "/v1/policy/view", policyViewHandler(d)},
		{"POST", "/v1/policy/gates", policyAddGateHandler(d)},
		{"POST", "/v1/policy/gates/yaml", policyAddGateYAMLHandler(d)},
		{"PATCH", "/v1/policy/gates/{id}", policyPatchGateHandler(d)},
		{"DELETE", "/v1/policy/gates/{id}", policyDeleteGateHandler(d)},
		{"GET", "/v1/sessions", sessionsListHandler(d)},

		// Ledger.
		{"GET", "/v1/ledger/tail", ledgerTailHandler(d)},
		{"GET", "/v1/ledger/root", ledgerRootHandler(d)},
		{"GET", "/v1/ledger/proof/{seq}", todo("ledger.proof")},
		{"POST", "/v1/ledger/verify", ledgerVerifyHandler(d)},

		// Detection / install plumbing.
		{"POST", "/v1/detect/report", detectReportHandler(d)},
		{"GET", "/v1/install/capabilities", installCapabilitiesHandler()},
		{"POST", "/v1/install/plan", installPlanHandler(d)},
		{"POST", "/v1/install/apply", installApplyHandler(d)},
		{"POST", "/v1/install/uninstall", installUninstallHandler(d)},
		{"POST", "/v1/install/uninstall-harnesses", installUninstallHarnessesHandler(d)},

		// Auth (always mounted; behaviour depends on Deps.Auth.Mode()).
		{"GET", "/v1/auth/mode", authModeHandler(d)},
		{"POST", "/v1/auth/bootstrap", authBootstrapHandler(d)},
		{"POST", "/v1/auth/login", authLoginHandler(d)},
		{"POST", "/v1/auth/logout", authLogoutHandler(d)},

		// Insights / report export.
		{"GET", "/v1/sessions/{id}/insights", insightsHandler(d)},
		{"GET", "/v1/sessions/{id}/report", todo("report")},
	}

	dispatch := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Loopback-only CORS. Dashboard lives on 127.0.0.1:7879 and needs to
		// fetch from :7878. Whitelist loopback Origins; reject everything else.
		origin := r.Header.Get("Origin")
		if isLoopbackOrigin(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Vary", "Origin")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		// Scan: prefer an exact (method, path) match. If no method matches
		// but some path does, return 405 with Allow listing every method
		// registered for that path. Only 404 when no path matches at all.
		var allowed []string
		for _, rt := range routes {
			if !pathMatches(rt.pattern, r.URL.Path) {
				continue
			}
			if rt.method == r.Method {
				rt.handler(w, r)
				return
			}
			allowed = append(allowed, rt.method)
		}
		if len(allowed) > 0 {
			w.Header().Set("Allow", strings.Join(allowed, ", "))
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{
				"error":  "method_not_allowed",
				"method": r.Method,
				"path":   r.URL.Path,
			})
			return
		}
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "not_found",
			"path":  r.URL.Path,
		})
	})

	if d.Auth != nil && d.Auth.Mode() != auth.ModeNone {
		return d.Auth.Middleware(dispatch)
	}
	return dispatch
}

func isLoopbackOrigin(origin string) bool {
	if origin == "" {
		return false
	}
	// Cheap prefix check; covers the dashboard and any local dev tool.
	return strings.HasPrefix(origin, "http://127.0.0.1:") ||
		strings.HasPrefix(origin, "http://localhost:") ||
		strings.HasPrefix(origin, "http://[::1]:")
}

// pathMatches returns true when `path` matches `pattern`. Pattern supports
// `{name}` segments which match any non-empty string between slashes.
func pathMatches(pattern, path string) bool {
	ps := strings.Split(strings.Trim(pattern, "/"), "/")
	xs := strings.Split(strings.Trim(path, "/"), "/")
	if len(ps) != len(xs) {
		return false
	}
	for i, p := range ps {
		if strings.HasPrefix(p, "{") && strings.HasSuffix(p, "}") {
			if xs[i] == "" {
				return false
			}
			continue
		}
		if p != xs[i] {
			return false
		}
	}
	return true
}

func health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func todo(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusNotImplemented, map[string]string{
			"error":  "not_implemented",
			"method": name,
			"hint":   "see api/openapi.yaml; handler scaffolded, body pending API sign-off",
		})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
