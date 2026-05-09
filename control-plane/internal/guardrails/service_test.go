package guardrails

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

type guardrailStoreForTest struct {
	configs      []ProviderConfig
	configsError error
	enableds     []EnabledEntry
	enabledError error
}

func (s guardrailStoreForTest) ListGuardrailProviderConfigs(context.Context) ([]ProviderConfig, error) {
	if s.configsError != nil {
		return nil, s.configsError
	}
	return append([]ProviderConfig(nil), s.configs...), nil
}

func (s guardrailStoreForTest) GetGuardrailProviderConfig(_ context.Context, providerID string) (ProviderConfig, bool, error) {
	for _, cfg := range s.configs {
		if cfg.ProviderID == providerID {
			return cfg, true, nil
		}
	}
	return ProviderConfig{}, false, nil
}

func (s guardrailStoreForTest) ListGuardrailEnabled(context.Context) ([]EnabledEntry, error) {
	if s.enabledError != nil {
		return nil, s.enabledError
	}
	return append([]EnabledEntry(nil), s.enableds...), nil
}

type fakeProvider struct {
	id            string
	testError     error
	catalog       []CatalogEntry
	catalogError  error
	runtimeResult RuntimeResult
	runtimeError  error
}

func (p fakeProvider) ID() string { return p.id }

func (p fakeProvider) Name() string { return p.id }

func (p fakeProvider) Capabilities() []string { return []string{"catalog"} }

func (p fakeProvider) TestCredentials(context.Context, ProviderConfig) error { return p.testError }

func (p fakeProvider) ListCatalog(context.Context, ProviderConfig) ([]CatalogEntry, error) {
	if p.catalogError != nil {
		return nil, p.catalogError
	}
	return append([]CatalogEntry(nil), p.catalog...), nil
}

func (p fakeProvider) RunRuntime(context.Context, ProviderConfig, CatalogEntry, EvaluateRequest) (RuntimeResult, error) {
	return p.runtimeResult, p.runtimeError
}

func newServiceForTest(provider fakeProvider) *Service {
	catalog := provider.catalog
	if len(catalog) == 0 {
		entryID := provider.runtimeResult.EntryID
		if entryID == "" {
			entryID = "default-entry"
		}
		catalog = []CatalogEntry{{
			ProviderID:                 provider.id,
			EntryID:                    entryID,
			Name:                       entryID,
			Kind:                       CatalogEntryClassifierModel,
			SupportsRuntimeEnforcement: true,
		}}
	}
	enabled := make([]EnabledEntry, 0, len(catalog))
	for _, entry := range catalog {
		enabled = append(enabled, EnabledEntry{ProviderID: entry.ProviderID, EntryID: entry.EntryID})
	}
	svc := NewService(guardrailStoreForTest{
		configs:  []ProviderConfig{{ProviderID: provider.id}},
		enableds: enabled,
	}, provider)
	svc.setCachedCatalog(provider.id, catalog)
	return svc
}

func TestService_EvaluateAfterLocalAllow(t *testing.T) {
	svc := newServiceForTest(fakeProvider{
		id: "nvidia",
		catalog: []CatalogEntry{{
			ProviderID:                 "nvidia",
			EntryID:                    "nemo-content-safety",
			Kind:                       CatalogEntryClassifierModel,
			SupportsRuntimeEnforcement: true,
		}},
		runtimeResult: RuntimeResult{
			Verdict:    "deny",
			LatencyMS:  180,
			ProviderID: "nvidia",
			EntryID:    "nemo-content-safety",
		},
	})
	trace, final := svc.EvaluatePostPolicy(context.Background(), EvaluateRequest{
		LocalPolicyVerdict: "allow",
		Tool:               "Bash",
		Input:              map[string]any{"command": "cat secrets.txt"},
	})
	if final != "deny" {
		t.Fatalf("final verdict = %q, want deny", final)
	}
	if len(trace.Stages) != 1 || trace.Stages[0].Verdict != "deny" {
		t.Fatalf("trace = %+v", trace)
	}
}

func TestService_AbstainsOnProviderError(t *testing.T) {
	svc := newServiceForTest(fakeProvider{
		id:           "nvidia",
		runtimeError: errors.New("timeout"),
	})
	trace, final := svc.EvaluatePostPolicy(context.Background(), EvaluateRequest{
		LocalPolicyVerdict: "allow",
		Tool:               "Read",
		Input:              map[string]any{"file_path": ".env"},
	})
	if final != "allow" {
		t.Fatalf("final verdict = %q, want allow", final)
	}
	if got := trace.Stages[0].Verdict; got != "abstain" {
		t.Fatalf("stage verdict = %q, want abstain", got)
	}
}

func TestService_RecordTraceEvictsOldest(t *testing.T) {
	svc := NewService(nil, fakeProvider{id: "nvidia"})
	for i := uint64(1); i <= maxTraceEntries+1; i++ {
		svc.RecordTrace(i, Trace{LocalPolicyVerdict: "allow", FinalVerdict: "allow"})
	}
	if _, ok := svc.Trace(1); ok {
		t.Fatalf("oldest trace was not evicted")
	}
	if _, ok := svc.Trace(maxTraceEntries + 1); !ok {
		t.Fatalf("newest trace missing")
	}
}

func TestService_EvaluateIncludesStorageErrorDetails(t *testing.T) {
	svc := NewService(guardrailStoreForTest{configsError: errors.New("boom")}, fakeProvider{id: "nvidia"})
	trace, final := svc.EvaluatePostPolicy(context.Background(), EvaluateRequest{LocalPolicyVerdict: "allow"})
	if final != "allow" || trace.GuardrailVerdict != "abstain" {
		t.Fatalf("trace=%+v final=%q", trace, final)
	}
	if len(trace.Stages) != 1 || trace.Stages[0].Details["reason"] != "provider_config_load_failed" {
		t.Fatalf("trace stages = %+v", trace.Stages)
	}
}

func TestService_RuntimeEntryDoesNotMutateProviderCatalog(t *testing.T) {
	catalog := []CatalogEntry{{EntryID: "entry", Kind: CatalogEntryClassifierModel, SupportsRuntimeEnforcement: true}}
	provider := fakeProvider{id: "nvidia", catalog: catalog, runtimeResult: RuntimeResult{Verdict: "allow"}}
	svc := NewService(guardrailStoreForTest{
		configs:  []ProviderConfig{{ProviderID: "nvidia"}},
		enableds: []EnabledEntry{{ProviderID: "nvidia", EntryID: "entry"}},
	}, provider)
	_, _ = svc.EvaluatePostPolicy(context.Background(), EvaluateRequest{
		LocalPolicyVerdict: "allow",
		Tool:               "Bash",
		Input:              map[string]any{"command": "pwd"},
	})
	if catalog[0].ProviderID != "" {
		t.Fatalf("provider catalog mutated: %+v", catalog)
	}
}

func TestService_EvaluatePostPolicySkipsWhenLocalVerdictIsNotAllow(t *testing.T) {
	svc := newServiceForTest(fakeProvider{id: "nvidia", runtimeResult: RuntimeResult{Verdict: "deny"}})
	trace, final := svc.EvaluatePostPolicy(context.Background(), EvaluateRequest{
		LocalPolicyVerdict: "deny",
		Tool:               "Bash",
		Input:              map[string]any{"command": "cat secrets.txt"},
	})
	if final != "deny" {
		t.Fatalf("final verdict = %q, want deny", final)
	}
	if trace.GuardrailVerdict != "skipped" || len(trace.Stages) != 0 {
		t.Fatalf("trace = %+v", trace)
	}
}

func TestService_EvaluatePostPolicyRecordsOpenRouterAbstainStage(t *testing.T) {
	svc := NewService(
		guardrailStoreForTest{
			configs:  []ProviderConfig{{ProviderID: "openrouter"}},
			enableds: []EnabledEntry{{ProviderID: "openrouter", EntryID: "policy-prod"}},
		},
		fakeProvider{
			id: "openrouter",
			catalog: []CatalogEntry{{
				ProviderID: "openrouter",
				EntryID:    "policy-prod",
				Name:       "Production Guardrail",
				Kind:       CatalogEntryAccountPolicy,
			}},
			runtimeResult: RuntimeResult{Verdict: "abstain"},
			runtimeError:  ErrRuntimeUnsupported,
		},
	)
	trace, final := svc.EvaluatePostPolicy(context.Background(), EvaluateRequest{
		LocalPolicyVerdict: "allow",
		Tool:               "Bash",
		Input:              map[string]any{"command": "pwd"},
	})
	if final != "allow" || trace.GuardrailVerdict != "abstain" {
		t.Fatalf("trace=%+v final=%q", trace, final)
	}
	if len(trace.Stages) != 1 || trace.Stages[0].Verdict != "abstain" {
		t.Fatalf("stages = %+v", trace.Stages)
	}
}

func TestService_ListCatalogAggregatesConfiguredProviders(t *testing.T) {
	svc := NewService(
		guardrailStoreForTest{configs: []ProviderConfig{{ProviderID: "nvidia"}, {ProviderID: "openrouter"}}},
		fakeProvider{
			id: "nvidia",
			catalog: []CatalogEntry{{
				ProviderID:                 "nvidia",
				EntryID:                    "nemo-content-safety",
				Name:                       "NeMo Content Safety",
				Kind:                       CatalogEntryClassifierModel,
				SupportsRuntimeEnforcement: true,
			}},
		},
		fakeProvider{
			id: "openrouter",
			catalog: []CatalogEntry{{
				ProviderID: "openrouter",
				EntryID:    "policy-prod",
				Name:       "Production Guardrail",
				Kind:       CatalogEntryAccountPolicy,
			}},
		},
	)
	got, err := svc.ListCatalog(context.Background())
	if err != nil {
		t.Fatalf("ListCatalog: %v", err)
	}
	if len(got) != 2 || got[0].ProviderID != "nvidia" || got[1].ProviderID != "openrouter" {
		t.Fatalf("catalog = %+v", got)
	}
}

func TestService_ListCatalogStatus_ReturnsPartialEntriesAndProviderErrors(t *testing.T) {
	svc := NewService(
		guardrailStoreForTest{configs: []ProviderConfig{{ProviderID: "nvidia"}, {ProviderID: "openrouter"}}},
		fakeProvider{
			id: "nvidia",
			catalog: []CatalogEntry{{
				ProviderID:                 "nvidia",
				EntryID:                    "nemo-content-safety",
				Name:                       "NeMo Content Safety",
				Kind:                       CatalogEntryClassifierModel,
				SupportsRuntimeEnforcement: true,
			}},
		},
		fakeProvider{
			id:           "openrouter",
			catalogError: errors.New("openrouter catalog status 401"),
		},
	)
	got, providerErrors, err := svc.ListCatalogStatus(context.Background())
	if err != nil {
		t.Fatalf("ListCatalogStatus: %v", err)
	}
	if len(got) != 1 || got[0].ProviderID != "nvidia" {
		t.Fatalf("catalog = %+v", got)
	}
	if len(providerErrors) != 1 || providerErrors[0].ProviderID != "openrouter" {
		t.Fatalf("providerErrors = %+v", providerErrors)
	}
}

func TestNVIDIAProvider_ListCatalogNormalizesSafetyModels(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Fatalf("path = %q, want /v1/models", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer nvapi-test" {
			t.Fatalf("authorization = %q", got)
		}
		_, _ = w.Write([]byte(`{"data":[
			{"id":"nvidia/llama-3.1-nemoguard-8b-content-safety","name":"Llama 3.1 NeMoGuard 8B Content Safety"},
			{"id":"meta/llama-3.1-8b-instruct","name":"General LLM"},
			{"id":"nvidia/llama-3_1-nemotron-safety-guard-8b-v3","name":"Nemotron Safety Guard 8B"}
		]}`))
	}))
	defer srv.Close()
	provider := &NVIDIAProvider{BaseURL: srv.URL, HTTPClient: srv.Client()}
	got, err := provider.ListCatalog(context.Background(), ProviderConfig{
		ProviderID: "nvidia",
		APIKey:     SecretString("nvapi-test"),
	})
	if err != nil {
		t.Fatalf("ListCatalog: %v", err)
	}
	if len(got) != 2 || got[0].Kind != CatalogEntryClassifierModel || !got[0].SupportsRuntimeEnforcement {
		t.Fatalf("catalog = %+v", got)
	}
}

func TestNVIDIAProvider_RunRuntimeParsesDenyVerdict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" || r.Method != http.MethodPost {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		text := string(body)
		if !strings.Contains(text, `"model":"nvidia/llama-3.1-nemoguard-8b-content-safety"`) ||
			!strings.Contains(text, `\"tool\":\"Bash\"`) {
			t.Fatalf("request body missing expected payload: %s", text)
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"User Safety\":\"unsafe\",\"Safety Categories\":\"PII/Privacy\"}"}}]}`))
	}))
	defer srv.Close()
	provider := &NVIDIAProvider{BaseURL: srv.URL, HTTPClient: srv.Client()}
	got, err := provider.RunRuntime(context.Background(), ProviderConfig{
		ProviderID: "nvidia",
		APIKey:     SecretString("nvapi-test"),
	}, CatalogEntry{
		ProviderID:                 "nvidia",
		EntryID:                    "nvidia/llama-3.1-nemoguard-8b-content-safety",
		Kind:                       CatalogEntryClassifierModel,
		SupportsRuntimeEnforcement: true,
	}, EvaluateRequest{
		LocalPolicyVerdict: "allow",
		Tool:               "Bash",
		Input:              map[string]any{"command": "cat secrets.txt"},
	})
	if err != nil {
		t.Fatalf("RunRuntime: %v", err)
	}
	want := RuntimeResult{
		ProviderID: "nvidia",
		EntryID:    "nvidia/llama-3.1-nemoguard-8b-content-safety",
		Verdict:    "deny",
		Details: map[string]string{
			"safety_categories": "PII/Privacy",
			"user_safety":       "unsafe",
		},
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("runtime mismatch: want %+v got %+v", want, got)
	}
}

func TestNVIDIAProvider_RunRuntimeRejectsSchemaInvalidVerdictJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"User Safety\":\"maybe\",\"Safety Categories\":\"PII\"}"}}]}`))
	}))
	defer srv.Close()
	provider := &NVIDIAProvider{BaseURL: srv.URL, HTTPClient: srv.Client()}
	_, err := provider.RunRuntime(context.Background(), ProviderConfig{
		ProviderID: "nvidia",
		APIKey:     SecretString("nvapi-test"),
	}, CatalogEntry{
		ProviderID: "nvidia",
		EntryID:    "nvidia/llama-3.1-nemoguard-8b-content-safety",
	}, EvaluateRequest{
		LocalPolicyVerdict: "allow",
		Tool:               "Bash",
		Input:              map[string]any{"command": "cat secrets.txt"},
	})
	if err == nil {
		t.Fatalf("expected schema validation error")
	}
}

func TestOpenRouterProvider_ListCatalogNormalizesPolicies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/guardrails" {
			t.Fatalf("path = %q, want /api/v1/guardrails", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer sk-or-test" {
			t.Fatalf("authorization = %q", got)
		}
		_, _ = w.Write([]byte(`{"data":[{
			"id":"550e8400-e29b-41d4-a716-446655440000",
			"name":"Production Guardrail",
			"description":"Restrict providers and enforce budget",
			"limit_usd":100,
			"reset_interval":"monthly",
			"enforce_zdr":true
		}]}`))
	}))
	defer srv.Close()
	provider := &OpenRouterProvider{BaseURL: srv.URL, HTTPClient: srv.Client()}
	got, err := provider.ListCatalog(context.Background(), ProviderConfig{
		ProviderID: "openrouter",
		APIKey:     SecretString("sk-or-test"),
	})
	if err != nil {
		t.Fatalf("ListCatalog: %v", err)
	}
	if len(got) != 1 || got[0].Kind != CatalogEntryAccountPolicy || got[0].SupportsRuntimeEnforcement {
		t.Fatalf("catalog = %+v", got)
	}
	if got[0].Metadata["limit_usd"] != "100.00" {
		t.Fatalf("limit_usd = %q", got[0].Metadata["limit_usd"])
	}
}

func TestOpenRouterProvider_RunRuntimeReturnsUnsupported(t *testing.T) {
	provider := &OpenRouterProvider{}
	got, err := provider.RunRuntime(context.Background(), ProviderConfig{}, CatalogEntry{
		ProviderID: "openrouter",
		EntryID:    "policy-prod",
		Kind:       CatalogEntryAccountPolicy,
	}, EvaluateRequest{
		LocalPolicyVerdict: "allow",
		Tool:               "Bash",
		Input:              map[string]any{"command": "pwd"},
	})
	if !errors.Is(err, ErrRuntimeUnsupported) {
		t.Fatalf("err = %v, want ErrRuntimeUnsupported", err)
	}
	if got.Verdict != "abstain" {
		t.Fatalf("verdict = %q, want abstain", got.Verdict)
	}
}
