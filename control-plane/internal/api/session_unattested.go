// Unattested (signer="none") session bootstrap. Used for manual / e2e
// testing where the full session.create attestation ceremony is too much
// friction. Guarded by AGENTLOCK_ALLOW_UNATTESTED=1 and tagged red in the
// dashboard so it can never be confused for a real signed session.

package api

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/openagentlock/openagentlock/control-plane/internal/storage"
)

func unattestedSessionHandler(d Deps) http.HandlerFunc {
	if d.Store == nil {
		return todo("session.unattested")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		// State-mutating; the router handles method dispatch but be
		// defensive in case this handler is mounted directly.
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST required")
			return
		}
		if os.Getenv("AGENTLOCK_ALLOW_UNATTESTED") != "1" {
			writeError(w, http.StatusForbidden, "unattested_disabled",
				"set AGENTLOCK_ALLOW_UNATTESTED=1 to mint signer=\"none\" sessions (dev only)")
			return
		}
		now := time.Now().UTC()
		id := newSessionID(now)
		policyHash := ""
		if live := livePolicyFor(d); live != nil {
			policyHash = live.Hash
		}
		s := storage.Session{
			ID:            id,
			StartedAt:     now,
			ExpiresAt:     now.Add(24 * time.Hour),
			PolicyHash:    policyHash,
			SessionPubKey: "none",
			Signer:        "none",
			SignerPubKey:  "none",
			// Not an agent-harness session. "installer" distinguishes
			// setup-time sessions from real agent runtimes (claude-code
			// / cursor / codex / ...) so the dashboard can filter them
			// out of the Sessions tab by default.
			Harness: "installer",
		}
		if err := d.Store.CreateSession(r.Context(), s); err != nil {
			writeError(w, http.StatusInternalServerError, "storage_error", err.Error())
			return
		}
		payloadBytes, err := json.Marshal(map[string]any{
			"session_id": id,
			"signer":     "none",
			"reason":     "unattested session via /v1/sessions/unattested",
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "marshal_error", err.Error())
			return
		}
		payloadHash := sha256.Sum256(payloadBytes)
		if _, err := d.Store.AppendLedger(r.Context(), storage.AppendInput{
			TS:          now,
			Source:      "system",
			ToolUseID:   "session.unattested",
			Signer:      "none",
			PayloadHash: payloadHash[:],
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "ledger_error", err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"id":         id,
			"signer":     "none",
			"started_at": now,
			"expires_at": s.ExpiresAt,
			"banner":     "UNATTESTED — LEDGER NOT SIGNED",
		})
	}
}
