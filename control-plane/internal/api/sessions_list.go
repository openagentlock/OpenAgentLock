// Sessions list endpoint. Returns every session the daemon knows about
// (active + ended) along with harness tag, pinned policy hash, and a
// needs_reload flag computed against the current live policy. Dashboard
// Sessions tab polls this to show which agents are running which policy.

package api

import (
	"log"
	"net/http"
	"sort"
	"time"
)

type sessionListItem struct {
	ID          string    `json:"id"`
	Harness     string    `json:"harness"`
	Signer      string    `json:"signer"`
	PolicyHash  string    `json:"policy_hash"`
	StartedAt   time.Time `json:"started_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Active      bool      `json:"active"`
	NeedsReload bool      `json:"needs_reload"`
}

func sessionsListHandler(d Deps) http.HandlerFunc {
	if d.Store == nil {
		return todo("sessions.list")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		list, err := d.Store.ListSessions(r.Context())
		if err != nil {
			log.Printf("sessions.list: ListSessions: %v", err)
			writeError(w, http.StatusInternalServerError, "storage_error", "failed to list sessions")
			return
		}
		liveHash := ""
		if live := livePolicyFor(d); live != nil {
			liveHash = live.Hash
		}
		items := make([]sessionListItem, 0, len(list))
		for _, s := range list {
			harness := s.Harness
			if harness == "" {
				harness = "unknown"
			}
			items = append(items, sessionListItem{
				ID:          s.ID,
				Harness:     harness,
				Signer:      s.Signer,
				PolicyHash:  s.PolicyHash,
				StartedAt:   s.StartedAt,
				ExpiresAt:   s.ExpiresAt,
				Active:      s.Active,
				NeedsReload: s.Active && liveHash != "" && s.PolicyHash != liveHash,
			})
		}
		// Stable order: active first, then most-recently started.
		sort.SliceStable(items, func(i, j int) bool {
			if items[i].Active != items[j].Active {
				return items[i].Active
			}
			return items[i].StartedAt.After(items[j].StartedAt)
		})
		writeJSON(w, http.StatusOK, map[string]any{
			"live_policy_hash": liveHash,
			"sessions":         items,
		})
	}
}
