package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openagentlock/openagentlock/control-plane/internal/guardrails"
	"github.com/openagentlock/openagentlock/control-plane/internal/storage"
)

type guardrailsHTTPFixture struct {
	srv   *httptest.Server
	home  string
	store *storage.Memory
	svc   *guardrails.Service
}

func newGuardrailsHTTPFixture(t *testing.T) guardrailsHTTPFixture {
	t.Helper()

	home := t.TempDir()
	store, err := storage.NewMemory(home)
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if err := store.SaveGuardrailProviderConfig(context.Background(), guardrails.ProviderConfig{
		ProviderID: "nvidia",
	}); err != nil {
		t.Fatalf("SaveGuardrailProviderConfig: %v", err)
	}

	svc := guardrails.NewService(store, guardrailsHTTPFakeProvider{
		id: "nvidia",
		catalog: []guardrails.CatalogEntry{
			{
				EntryID:                    "nemo-content-safety",
				Name:                       "NeMo Content Safety",
				Kind:                       guardrails.CatalogEntryClassifierModel,
				SupportsRuntimeEnforcement: true,
			},
			{
				EntryID:                    "topic-control",
				Name:                       "Topic Control",
				Kind:                       guardrails.CatalogEntryClassifierModel,
				SupportsRuntimeEnforcement: true,
			},
		},
	})

	svc.RecordTrace(7, guardrails.Trace{
		LocalPolicyVerdict: "allow",
		GuardrailVerdict:   "deny",
		FinalVerdict:       "deny",
		Stages: []guardrails.RuntimeStage{{
			ProviderID: "nvidia",
			EntryID:    "nemo-content-safety",
			Verdict:    "deny",
			LatencyMS:  180,
		}},
	})

	srv := httptest.NewServer(NewRouter(Deps{Store: store, Guardrails: svc}))
	t.Cleanup(srv.Close)

	return guardrailsHTTPFixture{
		srv:   srv,
		home:  home,
		store: store,
		svc:   svc,
	}
}

type guardrailsHTTPFakeProvider struct {
	id            string
	catalog       []guardrails.CatalogEntry
	catalogError  error
	testError     error
	runtimeResult guardrails.RuntimeResult
	runtimeError  error
}

func (p guardrailsHTTPFakeProvider) ID() string {
	return p.id
}

func (p guardrailsHTTPFakeProvider) Name() string {
	if p.id == "nvidia" {
		return "NVIDIA"
	}
	return p.id
}

func (p guardrailsHTTPFakeProvider) Capabilities() []string {
	return []string{"catalog"}
}

func (p guardrailsHTTPFakeProvider) TestCredentials(context.Context, guardrails.ProviderConfig) error {
	return p.testError
}

func (p guardrailsHTTPFakeProvider) ListCatalog(context.Context, guardrails.ProviderConfig) ([]guardrails.CatalogEntry, error) {
	if p.catalogError != nil {
		return nil, p.catalogError
	}
	return append([]guardrails.CatalogEntry(nil), p.catalog...), nil
}

func (p guardrailsHTTPFakeProvider) RunRuntime(context.Context, guardrails.ProviderConfig, guardrails.CatalogEntry, guardrails.EvaluateRequest) (guardrails.RuntimeResult, error) {
	if p.runtimeResult.Verdict == "" && p.runtimeError == nil {
		return guardrails.RuntimeResult{Verdict: "allow"}, nil
	}
	return p.runtimeResult, p.runtimeError
}

func TestGuardrailsCatalogHandler_ReturnsNormalizedEntries(t *testing.T) {
	fx := newGuardrailsHTTPFixture(t)

	res, err := http.Get(fx.srv.URL + "/v1/guardrails/catalog")
	if err != nil {
		t.Fatalf("GET catalog: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}

	var body struct {
		Entries []guardrails.CatalogEntry `json:"entries"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(body.Entries))
	}
}

func TestGuardrailsCatalogHandler_ReturnsPartialEntriesAndProviderErrors(t *testing.T) {
	home := t.TempDir()
	store, err := storage.NewMemory(home)
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	for _, providerID := range []string{"nvidia", "openrouter"} {
		if err := store.SaveGuardrailProviderConfig(context.Background(), guardrails.ProviderConfig{
			ProviderID: providerID,
		}); err != nil {
			t.Fatalf("SaveGuardrailProviderConfig(%s): %v", providerID, err)
		}
	}

	svc := guardrails.NewService(
		store,
		guardrailsHTTPFakeProvider{
			id: "nvidia",
			catalog: []guardrails.CatalogEntry{{
				EntryID:                    "nemo-content-safety",
				Name:                       "NeMo Content Safety",
				Kind:                       guardrails.CatalogEntryClassifierModel,
				SupportsRuntimeEnforcement: true,
			}},
		},
		guardrailsHTTPFakeProvider{
			id:           "openrouter",
			catalogError: context.DeadlineExceeded,
		},
	)

	srv := httptest.NewServer(NewRouter(Deps{Store: store, Guardrails: svc}))
	t.Cleanup(srv.Close)

	res, err := http.Get(srv.URL + "/v1/guardrails/catalog")
	if err != nil {
		t.Fatalf("GET catalog: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}

	var body GuardrailCatalogResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Entries) != 1 || body.Entries[0].ProviderID != "nvidia" {
		t.Fatalf("entries = %+v", body.Entries)
	}
	if len(body.ProviderErrors) != 1 || body.ProviderErrors[0].ProviderID != "openrouter" {
		t.Fatalf("provider errors = %+v", body.ProviderErrors)
	}
}

func TestGuardrailsProvidersHandler_ReturnsProviderStatus(t *testing.T) {
	fx := newGuardrailsHTTPFixture(t)

	res, err := http.Get(fx.srv.URL + "/v1/guardrails/providers")
	if err != nil {
		t.Fatalf("GET providers: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	var body struct {
		Providers []GuardrailProviderView `json:"providers"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Providers) != 1 || body.Providers[0].ID != "nvidia" || !body.Providers[0].Configured {
		t.Fatalf("providers = %+v", body.Providers)
	}
}

func TestGuardrailsEnabledHandler_RoundTripsEnabledEntries(t *testing.T) {
	fx := newGuardrailsHTTPFixture(t)
	req, err := http.NewRequest(http.MethodPut, fx.srv.URL+"/v1/guardrails/enabled", strings.NewReader(`{
		"entries": [{"provider_id": "nvidia", "entry_id": "nemo-content-safety"}]
	}`))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT enabled: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	got, err := fx.store.ListGuardrailEnabled(context.Background())
	if err != nil {
		t.Fatalf("ListGuardrailEnabled: %v", err)
	}
	if len(got) != 1 || got[0].ProviderID != "nvidia" || got[0].EntryID != "nemo-content-safety" {
		t.Fatalf("enabled = %+v", got)
	}

	res, err = http.Get(fx.srv.URL + "/v1/guardrails/enabled")
	if err != nil {
		t.Fatalf("GET enabled: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d", res.StatusCode)
	}
}

func TestGuardrailsTraceHandler_ReturnsRecordedTrace(t *testing.T) {
	fx := newGuardrailsHTTPFixture(t)
	res, err := http.Get(fx.srv.URL + "/v1/guardrails/traces/7")
	if err != nil {
		t.Fatalf("GET trace: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	var body GuardrailTraceResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.LedgerSeq != 7 || body.Trace.FinalVerdict != "deny" {
		t.Fatalf("trace response = %+v", body)
	}
}
