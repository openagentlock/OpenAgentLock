package guardrails

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

var (
	ErrProviderNotRegistered = errors.New("guardrails provider not registered")
	ErrRuntimeUnsupported    = errors.New("guardrail runtime unsupported")
)

const (
	defaultCatalogCacheTTL = 5 * time.Minute
	maxTraceEntries        = 1024
)

type CatalogEntry struct {
	ProviderID                 string            `json:"provider_id"`
	EntryID                    string            `json:"entry_id"`
	Name                       string            `json:"name"`
	Kind                       CatalogEntryKind  `json:"kind"`
	Description                string            `json:"description,omitempty"`
	SupportsRuntimeEnforcement bool              `json:"supports_runtime_enforcement"`
	Metadata                   map[string]string `json:"metadata,omitempty"`
}

type CatalogProviderError struct {
	ProviderID string `json:"provider_id"`
	Detail     string `json:"detail"`
}

type RuntimeResult struct {
	ProviderID string            `json:"provider_id"`
	EntryID    string            `json:"entry_id"`
	Verdict    string            `json:"verdict"`
	LatencyMS  int               `json:"latency_ms"`
	Details    map[string]string `json:"details,omitempty"`
}

type RuntimeStage struct {
	ProviderID string            `json:"provider_id"`
	EntryID    string            `json:"entry_id"`
	Verdict    string            `json:"verdict"`
	LatencyMS  int               `json:"latency_ms"`
	Details    map[string]string `json:"details,omitempty"`
}

type Trace struct {
	LocalPolicyVerdict string         `json:"local_policy_verdict"`
	GuardrailVerdict   string         `json:"guardrail_verdict"`
	FinalVerdict       string         `json:"final_verdict"`
	Stages             []RuntimeStage `json:"stages"`
}

type EvaluateRequest struct {
	LocalPolicyVerdict string         `json:"local_policy_verdict"`
	Source             string         `json:"source,omitempty"`
	Tool               string         `json:"tool"`
	Input              map[string]any `json:"input"`
}

type Provider interface {
	ID() string
	Name() string
	Capabilities() []string
	TestCredentials(ctx context.Context, cfg ProviderConfig) error
	ListCatalog(ctx context.Context, cfg ProviderConfig) ([]CatalogEntry, error)
	RunRuntime(ctx context.Context, cfg ProviderConfig, entry CatalogEntry, req EvaluateRequest) (RuntimeResult, error)
}

type Store interface {
	ListGuardrailProviderConfigs(ctx context.Context) ([]ProviderConfig, error)
	GetGuardrailProviderConfig(ctx context.Context, providerID string) (ProviderConfig, bool, error)
	ListGuardrailEnabled(ctx context.Context) ([]EnabledEntry, error)
}

type Service struct {
	store Store

	mu           sync.RWMutex
	providers    map[string]Provider
	catalogCache map[string]catalogCacheEntry
	traces       map[uint64]Trace
	traceOrder   []uint64
	now          func() time.Time
}

type catalogCacheEntry struct {
	entries   []CatalogEntry
	expiresAt time.Time
}

func NewService(store Store, providers ...Provider) *Service {
	svc := &Service{
		store:        store,
		providers:    make(map[string]Provider, len(providers)),
		catalogCache: make(map[string]catalogCacheEntry),
		traces:       map[uint64]Trace{},
		now:          time.Now,
	}
	for _, provider := range providers {
		svc.Register(provider)
	}
	return svc
}

func NewDefaultService(store Store) *Service {
	return NewService(store, &NVIDIAProvider{}, &OpenRouterProvider{})
}

func (s *Service) Register(provider Provider) {
	if provider == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.providers[provider.ID()] = provider
}

func (s *Service) ProviderIDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.providers))
	for id := range s.providers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (s *Service) IsSupported(providerID string) bool {
	_, ok := s.provider(providerID)
	return ok
}

func (s *Service) ProviderName(providerID string) string {
	provider, ok := s.provider(providerID)
	if !ok {
		return providerID
	}
	return provider.Name()
}

func (s *Service) ProviderCapabilities(providerID string) []string {
	provider, ok := s.provider(providerID)
	if !ok {
		return []string{}
	}
	return append([]string(nil), provider.Capabilities()...)
}

func (s *Service) TestCredentials(ctx context.Context, cfg ProviderConfig) error {
	provider, ok := s.provider(cfg.ProviderID)
	if !ok {
		return fmt.Errorf("%w: %s", ErrProviderNotRegistered, cfg.ProviderID)
	}
	return provider.TestCredentials(ctx, cfg)
}

func (s *Service) ListCatalog(ctx context.Context) ([]CatalogEntry, error) {
	entries, providerErrors, err := s.ListCatalogStatus(ctx)
	if err != nil {
		return nil, err
	}
	if len(providerErrors) > 0 {
		return nil, fmt.Errorf("list catalog for %s: %s", providerErrors[0].ProviderID, providerErrors[0].Detail)
	}
	return entries, nil
}

func (s *Service) ListCatalogStatus(ctx context.Context) ([]CatalogEntry, []CatalogProviderError, error) {
	if s.store == nil {
		return nil, nil, nil
	}
	cfgs, err := s.store.ListGuardrailProviderConfigs(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("list provider configs: %w", err)
	}
	sort.Slice(cfgs, func(i, j int) bool {
		return cfgs[i].ProviderID < cfgs[j].ProviderID
	})

	out := make([]CatalogEntry, 0)
	providerErrors := make([]CatalogProviderError, 0)
	for _, cfg := range cfgs {
		provider, ok := s.provider(cfg.ProviderID)
		if !ok {
			return nil, nil, fmt.Errorf("%w: %s", ErrProviderNotRegistered, cfg.ProviderID)
		}
		entries, err := provider.ListCatalog(ctx, cfg)
		if err != nil {
			providerErrors = append(providerErrors, CatalogProviderError{
				ProviderID: cfg.ProviderID,
				Detail:     err.Error(),
			})
			continue
		}
		normalized := cloneCatalogEntries(entries)
		for i := range normalized {
			if normalized[i].ProviderID == "" {
				normalized[i].ProviderID = cfg.ProviderID
			}
		}
		s.setCachedCatalog(cfg.ProviderID, normalized)
		out = append(out, normalized...)
	}
	sortCatalogEntries(out)
	return out, providerErrors, nil
}

func (s *Service) EvaluatePostPolicy(ctx context.Context, req EvaluateRequest) (Trace, string) {
	trace := Trace{
		LocalPolicyVerdict: req.LocalPolicyVerdict,
		GuardrailVerdict:   "allow",
		FinalVerdict:       req.LocalPolicyVerdict,
	}
	if req.LocalPolicyVerdict != "allow" {
		trace.GuardrailVerdict = "skipped"
		return trace, trace.FinalVerdict
	}
	if s.store == nil {
		trace.FinalVerdict = "allow"
		return trace, trace.FinalVerdict
	}

	cfgs, err := s.store.ListGuardrailProviderConfigs(ctx)
	if err != nil {
		trace.GuardrailVerdict = "abstain"
		trace.FinalVerdict = "allow"
		trace.Stages = append(trace.Stages, RuntimeStage{
			Verdict: "abstain",
			Details: map[string]string{
				"reason": "provider_config_load_failed",
				"error":  err.Error(),
			},
		})
		return trace, trace.FinalVerdict
	}
	cfgByProvider := make(map[string]ProviderConfig, len(cfgs))
	for _, cfg := range cfgs {
		cfgByProvider[cfg.ProviderID] = cfg
	}

	enabled, err := s.store.ListGuardrailEnabled(ctx)
	if err != nil {
		trace.GuardrailVerdict = "abstain"
		trace.FinalVerdict = "allow"
		trace.Stages = append(trace.Stages, RuntimeStage{
			Verdict: "abstain",
			Details: map[string]string{
				"reason": "enabled_guardrails_load_failed",
				"error":  err.Error(),
			},
		})
		return trace, trace.FinalVerdict
	}

	finalVerdict := "allow"
	guardrailVerdict := "allow"
	for _, enabledEntry := range enabled {
		cfg, ok := cfgByProvider[enabledEntry.ProviderID]
		if !ok {
			trace.Stages = append(trace.Stages, RuntimeStage{
				ProviderID: enabledEntry.ProviderID,
				EntryID:    enabledEntry.EntryID,
				Verdict:    "abstain",
				Details:    map[string]string{"reason": "provider_not_configured"},
			})
			guardrailVerdict = "abstain"
			continue
		}
		provider, ok := s.provider(enabledEntry.ProviderID)
		if !ok {
			trace.Stages = append(trace.Stages, RuntimeStage{
				ProviderID: enabledEntry.ProviderID,
				EntryID:    enabledEntry.EntryID,
				Verdict:    "abstain",
				Details:    map[string]string{"reason": "provider_not_registered"},
			})
			guardrailVerdict = "abstain"
			continue
		}
		entry, ok, err := s.runtimeEntry(ctx, cfg, enabledEntry)
		if err != nil {
			trace.Stages = append(trace.Stages, RuntimeStage{
				ProviderID: enabledEntry.ProviderID,
				EntryID:    enabledEntry.EntryID,
				Verdict:    "abstain",
				Details: map[string]string{
					"reason": "catalog_lookup_failed",
					"error":  err.Error(),
				},
			})
			guardrailVerdict = "abstain"
			continue
		}
		if !ok {
			trace.Stages = append(trace.Stages, RuntimeStage{
				ProviderID: enabledEntry.ProviderID,
				EntryID:    enabledEntry.EntryID,
				Verdict:    "abstain",
				Details:    map[string]string{"reason": "catalog_entry_not_found"},
			})
			guardrailVerdict = "abstain"
			continue
		}

		result, err := provider.RunRuntime(ctx, cfg, entry, req)
		if err != nil {
			trace.Stages = append(trace.Stages, RuntimeStage{
				ProviderID: enabledEntry.ProviderID,
				EntryID:    enabledEntry.EntryID,
				Verdict:    "abstain",
				LatencyMS:  result.LatencyMS,
				Details:    runtimeErrorDetails(entry, err),
			})
			guardrailVerdict = "abstain"
			continue
		}

		stage := RuntimeStage{
			ProviderID: firstNonEmpty(result.ProviderID, enabledEntry.ProviderID),
			EntryID:    firstNonEmpty(result.EntryID, enabledEntry.EntryID),
			Verdict:    normalizeVerdict(result.Verdict),
			LatencyMS:  result.LatencyMS,
			Details:    cloneStringMap(result.Details),
		}
		trace.Stages = append(trace.Stages, stage)
		if stage.Verdict == "deny" {
			trace.GuardrailVerdict = "deny"
			trace.FinalVerdict = "deny"
			return trace, "deny"
		}
		if stage.Verdict == "abstain" {
			guardrailVerdict = "abstain"
		}
	}
	trace.GuardrailVerdict = guardrailVerdict
	trace.FinalVerdict = finalVerdict
	return trace, finalVerdict
}

func (s *Service) RecordTrace(seq uint64, trace Trace) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.traces[seq]; !exists {
		s.traceOrder = append(s.traceOrder, seq)
	}
	s.traces[seq] = cloneTrace(trace)
	for len(s.traceOrder) > maxTraceEntries {
		oldest := s.traceOrder[0]
		s.traceOrder = s.traceOrder[1:]
		delete(s.traces, oldest)
	}
}

func (s *Service) Trace(seq uint64) (Trace, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	trace, ok := s.traces[seq]
	return cloneTrace(trace), ok
}

func (s *Service) runtimeEntry(ctx context.Context, cfg ProviderConfig, enabled EnabledEntry) (CatalogEntry, bool, error) {
	entries, ok := s.cachedCatalog(enabled.ProviderID)
	if !ok {
		provider, exists := s.provider(enabled.ProviderID)
		if !exists {
			return CatalogEntry{}, false, fmt.Errorf("%w: %s", ErrProviderNotRegistered, enabled.ProviderID)
		}
		var err error
		rawEntries, err := provider.ListCatalog(ctx, cfg)
		if err != nil {
			return CatalogEntry{}, false, err
		}
		entries = cloneCatalogEntries(rawEntries)
		for i := range entries {
			if entries[i].ProviderID == "" {
				entries[i].ProviderID = enabled.ProviderID
			}
		}
		s.setCachedCatalog(enabled.ProviderID, entries)
	}
	for _, entry := range entries {
		if entry.EntryID == enabled.EntryID {
			return cloneCatalogEntry(entry), true, nil
		}
	}
	return CatalogEntry{}, false, nil
}

func (s *Service) provider(providerID string) (Provider, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	provider, ok := s.providers[providerID]
	return provider, ok
}

func (s *Service) cachedCatalog(providerID string) ([]CatalogEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entries, ok := s.catalogCache[providerID]
	if !ok {
		return nil, false
	}
	if !entries.expiresAt.IsZero() && s.now().After(entries.expiresAt) {
		return nil, false
	}
	return cloneCatalogEntries(entries.entries), true
}

func (s *Service) setCachedCatalog(providerID string, entries []CatalogEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.catalogCache[providerID] = catalogCacheEntry{
		entries:   cloneCatalogEntries(entries),
		expiresAt: s.now().Add(defaultCatalogCacheTTL),
	}
}

func sortCatalogEntries(entries []CatalogEntry) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].ProviderID != entries[j].ProviderID {
			return entries[i].ProviderID < entries[j].ProviderID
		}
		return entries[i].EntryID < entries[j].EntryID
	})
}

func cloneCatalogEntries(entries []CatalogEntry) []CatalogEntry {
	out := make([]CatalogEntry, 0, len(entries))
	for _, entry := range entries {
		out = append(out, cloneCatalogEntry(entry))
	}
	return out
}

func cloneCatalogEntry(entry CatalogEntry) CatalogEntry {
	entry.Metadata = cloneStringMap(entry.Metadata)
	return entry
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneTrace(trace Trace) Trace {
	trace.Stages = append([]RuntimeStage(nil), trace.Stages...)
	for i := range trace.Stages {
		trace.Stages[i].Details = cloneStringMap(trace.Stages[i].Details)
	}
	return trace
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func normalizeVerdict(verdict string) string {
	switch verdict {
	case "allow", "deny", "abstain":
		return verdict
	default:
		return "abstain"
	}
}

func runtimeErrorDetails(entry CatalogEntry, err error) map[string]string {
	details := map[string]string{"error": err.Error()}
	switch {
	case errors.Is(err, ErrRuntimeUnsupported):
		details["reason"] = "runtime_unsupported"
	case entry.Kind != CatalogEntryClassifierModel:
		details["reason"] = "entry_not_classifier_model"
	case !entry.SupportsRuntimeEnforcement:
		details["reason"] = "entry_not_runtime_capable"
	default:
		details["reason"] = "runtime_error"
	}
	return details
}
