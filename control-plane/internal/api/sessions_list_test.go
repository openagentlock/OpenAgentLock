package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/openagentlock/openagentlock/control-plane/internal/storage"
)

// GET /v1/sessions lists every session the daemon knows about plus
// the current live policy hash. needs_reload is true when a session
// is pinned to an older policy hash than what's live right now.
func TestSessionsList_ShapeAndNeedsReload(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)

	// Add a second session pinned to a stale policy hash so we can
	// verify needs_reload flips correctly.
	stale := storage.Session{
		ID:            "SESS-STALE",
		PolicyHash:    "sha256:stale-hash-placeholder",
		SessionPubKey: "none",
		Signer:        "none",
		SignerPubKey:  "none",
		Harness:       "claude-code",
	}
	if err := fx.store.CreateSession(context.Background(), stale); err != nil {
		t.Fatalf("seed stale session: %v", err)
	}

	res, err := http.Get(fx.srv.URL + "/v1/sessions")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}

	var out map[string]any
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := out["live_policy_hash"].(string); !ok {
		t.Fatalf("missing live_policy_hash in response: %+v", out)
	}
	sessions, ok := out["sessions"].([]any)
	if !ok || len(sessions) == 0 {
		t.Fatalf("sessions array missing / empty: %+v", out["sessions"])
	}

	// Every session entry must have the required fields.
	for _, raw := range sessions {
		s, _ := raw.(map[string]any)
		for _, f := range []string{"id", "harness", "signer", "policy_hash", "active", "needs_reload"} {
			if _, ok := s[f]; !ok {
				t.Fatalf("session entry missing field %q: %+v", f, s)
			}
		}
	}

	// The stale session we seeded must show needs_reload=true; the
	// gate-fixture session (created via /v1/sessions with the real
	// policy hash) must show needs_reload=false.
	var staleReload, freshReload bool
	for _, raw := range sessions {
		s := raw.(map[string]any)
		id := s["id"].(string)
		switch id {
		case "SESS-STALE":
			staleReload = s["needs_reload"].(bool)
		case fx.sessionID:
			freshReload = s["needs_reload"].(bool)
		}
	}
	if !staleReload {
		t.Fatalf("stale session should need reload")
	}
	if freshReload {
		t.Fatalf("fresh session should not need reload")
	}
}

// Harness is the projection the dashboard Sessions tab shows. Empty
// harness is rendered as "unknown" in the API response so the UI can
// render a chip even for legacy sessions.
func TestSessionsList_UnknownHarnessProjected(t *testing.T) {
	fx := newGateFixture(t, enforcePolicyYAML)

	// A session with no harness field set.
	legacy := storage.Session{
		ID:            "SESS-LEGACY",
		PolicyHash:    "sha256:any",
		SessionPubKey: "none",
		Signer:        "none",
		SignerPubKey:  "none",
		// Harness intentionally blank.
	}
	if err := fx.store.CreateSession(context.Background(), legacy); err != nil {
		t.Fatalf("seed: %v", err)
	}

	res, err := http.Get(fx.srv.URL + "/v1/sessions")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	sessions := out["sessions"].([]any)
	seen := false
	for _, raw := range sessions {
		s := raw.(map[string]any)
		if s["id"] == "SESS-LEGACY" {
			seen = true
			if s["harness"] != "unknown" {
				t.Fatalf("legacy session harness = %v, want unknown", s["harness"])
			}
		}
	}
	if !seen {
		t.Fatal("legacy session not returned by list")
	}
}
