package api

import (
	"errors"
	"net/http"

	"github.com/openagentlock/openagentlock/control-plane/internal/storage"
)

// insightsHandler returns a per-session aggregate of the ledger: counts
// by rule_id, by source, by tool_use_id. The ledger entries don't carry
// rule_id directly (yet) — we extract it from tool_use_id for now and
// wire richer per-entry metadata in a later slice.
func insightsHandler(d Deps) http.HandlerFunc {
	if d.Store == nil {
		return todo("insights")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		id := routeParam("/v1/sessions/{id}/insights", r.URL.Path, "id")
		if _, err := d.Store.GetSession(r.Context(), id); err != nil {
			if errors.Is(err, storage.ErrSessionNotFound) {
				writeError(w, http.StatusNotFound, "session_not_found", id)
				return
			}
			writeError(w, http.StatusInternalServerError, "storage_error", err.Error())
			return
		}

		entries, err := d.Store.ListLedger(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "storage_error", err.Error())
			return
		}

		byRule := map[string]int{}
		byVerdict := map[string]int{}
		bySource := map[string]int{}
		byTool := map[string]int{}
		total := 0
		for _, e := range entries {
			if e.RuleID != "" {
				byRule[e.RuleID]++
			}
			if e.Verdict != "" {
				byVerdict[e.Verdict]++
			}
			if e.ToolUseID != "" {
				byTool[e.ToolUseID]++
			}
			if e.Source != "" {
				bySource[e.Source]++
			}
			total++
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"session_id": id,
			"counts": map[string]any{
				"total":      total,
				"by_rule":    byRule,
				"by_verdict": byVerdict,
				"by_source":  bySource,
				"by_tool":    byTool,
			},
		})
	}
}
