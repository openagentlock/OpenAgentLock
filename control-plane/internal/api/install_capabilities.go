package api

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// InstallCapabilities is the response shape for GET /v1/install/capabilities.
//
// Read-only view of runtime gates and environment so the CLI can fail fast
// before asking for a TOTP code. No auth and no daemon mutation here — this
// is a probe, not a control surface.
//
// File-writing happens on the host (in the CLI), not inside the daemon, so
// there are no apply / real-home gates to advertise. `container` is kept for
// the dashboard, but the CLI no longer warns on it: daemons in containers
// do not need bind mounts because the daemon never touches host paths.
type InstallCapabilities struct {
	UnattestedAllowed bool `json:"unattested_allowed"`
	Container         bool `json:"container"`
}

func installCapabilitiesHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, InstallCapabilities{
			UnattestedAllowed: os.Getenv("AGENTLOCK_ALLOW_UNATTESTED") == "1",
			Container:         inContainer(),
		})
	}
}

// inContainer returns true when the daemon is running inside a container so
// the CLI can warn that host paths won't be visible without a same-path bind
// mount. /.dockerenv is the canonical Docker marker; AGENTLOCK_IN_CONTAINER
// is set by the published Dockerfile so non-Docker container runtimes still
// surface correctly.
func inContainer() bool {
	if os.Getenv("AGENTLOCK_IN_CONTAINER") == "1" {
		return true
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	return false
}

// validateHarnessConfigDirs sanity-checks the per-harness config dir map
// the CLI sends in install plan/apply/uninstall requests. Empty values are
// ignored — the daemon falls back to the legacy resolution path. Non-empty
// values must be:
//   - absolute (so the daemon doesn't resolve them against its own CWD), and
//   - in canonical form (no `..` or `.` segments), and
//   - outside AGENTLOCK_HOME (so the CLI can't trick the daemon into
//     writing into its own state dir).
//
// Returns ("", nil) on success; ("<key>", error) on failure so the caller
// can include the offending harness id in the response.
func validateHarnessConfigDirs(m map[string]string, agentlockHome string) (string, error) {
	if len(m) == 0 {
		return "", nil
	}
	var resolvedHome string
	if agentlockHome != "" {
		if h, err := filepath.Abs(agentlockHome); err == nil {
			resolvedHome = filepath.Clean(h)
		}
	}
	for k, v := range m {
		if v == "" {
			continue
		}
		if !filepath.IsAbs(v) {
			return k, fmt.Errorf("harness_config_dirs[%q]: must be absolute, got %q", k, v)
		}
		if filepath.Clean(v) != v {
			return k, fmt.Errorf("harness_config_dirs[%q]: must be canonical (no `..`, `.`, double slashes), got %q", k, v)
		}
		if resolvedHome != "" {
			rel, err := filepath.Rel(resolvedHome, v)
			if err == nil && rel == "." {
				return k, fmt.Errorf("harness_config_dirs[%q]: equals AGENTLOCK_HOME", k)
			}
			if err == nil && !strings.HasPrefix(rel, "..") && !strings.HasPrefix(rel, string(os.PathSeparator)) {
				return k, fmt.Errorf("harness_config_dirs[%q]: resolves under AGENTLOCK_HOME", k)
			}
		}
	}
	return "", nil
}
