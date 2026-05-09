package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/openagentlock/openagentlock/control-plane/internal/guardrails"
)

type guardrailsEnabledRequest struct {
	Entries []guardrails.EnabledEntry `json:"entries"`
}

func guardrailsProvidersHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Guardrails == nil || d.Store == nil {
			writeError(w, http.StatusServiceUnavailable, "guardrails_unavailable", "guardrails service is not configured")
			return
		}
		views := make([]GuardrailProviderView, 0, len(d.Guardrails.ProviderIDs()))
		for _, id := range d.Guardrails.ProviderIDs() {
			_, configured, err := d.Store.GetGuardrailProviderConfig(r.Context(), id)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "storage_error", err.Error())
				return
			}
			status := "available"
			if configured {
				status = "configured"
			}
			views = append(views, GuardrailProviderView{
				ID:           id,
				Name:         d.Guardrails.ProviderName(id),
				Status:       status,
				Capabilities: d.Guardrails.ProviderCapabilities(id),
				Configured:   configured,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"providers": views})
	}
}

func guardrailsProviderTestHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Guardrails == nil || d.Store == nil {
			writeError(w, http.StatusServiceUnavailable, "guardrails_unavailable", "guardrails service is not configured")
			return
		}
		providerID := routeParam("/v1/guardrails/providers/{id}/test", r.URL.Path, "id")
		cfg, ok, err := d.Store.GetGuardrailProviderConfig(r.Context(), providerID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "storage_error", err.Error())
			return
		}
		if !ok {
			writeError(w, http.StatusNotFound, "provider_not_configured", providerID)
			return
		}
		if err := d.Guardrails.TestCredentials(r.Context(), cfg); err != nil {
			writeError(w, http.StatusBadGateway, "guardrails_provider_test_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "provider_id": providerID})
	}
}

func guardrailsCatalogHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Guardrails == nil {
			writeError(w, http.StatusServiceUnavailable, "guardrails_unavailable", "guardrails service is not configured")
			return
		}
		entries, providerErrors, err := d.Guardrails.ListCatalogStatus(r.Context())
		if err != nil {
			writeError(w, http.StatusBadGateway, "guardrails_catalog_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, GuardrailCatalogResponse{
			Entries:        entries,
			ProviderErrors: providerErrors,
		})
	}
}

func guardrailsEnabledGetHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Store == nil {
			writeError(w, http.StatusServiceUnavailable, "guardrails_unavailable", "guardrails storage is not configured")
			return
		}
		enabled, err := d.Store.ListGuardrailEnabled(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "storage_error", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"entries": enabled})
	}
}

func guardrailsEnabledHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Store == nil {
			writeError(w, http.StatusServiceUnavailable, "guardrails_unavailable", "guardrails storage is not configured")
			return
		}
		var body guardrailsEnabledRequest
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		enabled, err := d.Store.SaveGuardrailEnabled(r.Context(), body.Entries)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "storage_error", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"entries": enabled})
	}
}

func guardrailsTraceHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Guardrails == nil {
			writeError(w, http.StatusServiceUnavailable, "guardrails_unavailable", "guardrails service is not configured")
			return
		}
		rawSeq := routeParam("/v1/guardrails/traces/{seq}", r.URL.Path, "seq")
		seq, err := strconv.ParseUint(rawSeq, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_seq", "guardrail trace seq must be an unsigned integer")
			return
		}
		trace, ok := d.Guardrails.Trace(seq)
		if !ok {
			writeError(w, http.StatusNotFound, "trace_not_found", rawSeq)
			return
		}
		writeJSON(w, http.StatusOK, GuardrailTraceResponse{LedgerSeq: seq, Trace: trace})
	}
}
