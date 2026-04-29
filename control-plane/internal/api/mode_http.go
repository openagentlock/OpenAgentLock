// HTTP surface for the daemon-level mode switch. GET reads the effective
// mode; PATCH hot-swaps the runtime override without a restart. Intended
// to back the dashboard's Rules tab toggle button.

package api

import (
	"encoding/json"
	"net/http"
	"os"
)

func modeGetHandler(_ Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"mode":       daemonMode(),
			"env":        os.Getenv("AGENTLOCK_MODE"),
			"runtime_override": func() string {
				v, _ := runtimeMode.Load().(string)
				return v
			}(),
		})
	}
}

func modePatchHandler(_ Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Mode string `json:"mode"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<10)
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		if !setRuntimeMode(body.Mode) {
			writeError(w, http.StatusBadRequest, "invalid_mode",
				"mode must be one of: \"monitor\", \"firewall\", or \"\" to clear override")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"mode":             daemonMode(),
			"runtime_override": body.Mode,
		})
	}
}
