package guardrails

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

const defaultOpenRouterBaseURL = "https://openrouter.ai"

type OpenRouterProvider struct {
	BaseURL    string
	HTTPClient *http.Client
}

func (p *OpenRouterProvider) ID() string {
	return "openrouter"
}

func (p *OpenRouterProvider) Name() string {
	return "OpenRouter"
}

func (p *OpenRouterProvider) Capabilities() []string {
	return []string{"catalog", "catalog_only"}
}

func (p *OpenRouterProvider) TestCredentials(ctx context.Context, cfg ProviderConfig) error {
	_, err := p.ListCatalog(ctx, cfg)
	return err
}

func (p *OpenRouterProvider) ListCatalog(ctx context.Context, cfg ProviderConfig) ([]CatalogEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(p.baseURL(), "/")+"/api/v1/guardrails", nil)
	if err != nil {
		return nil, err
	}
	applyBearer(req, cfg.APIKey)

	res, err := p.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("openrouter catalog status %d", res.StatusCode)
	}

	var payload struct {
		Data []struct {
			ID               string   `json:"id"`
			Name             string   `json:"name"`
			Description      string   `json:"description"`
			WorkspaceID      string   `json:"workspace_id"`
			AllowedModels    []string `json:"allowed_models"`
			AllowedProviders []string `json:"allowed_providers"`
			IgnoredModels    []string `json:"ignored_models"`
			IgnoredProviders []string `json:"ignored_providers"`
			LimitUSD         float64  `json:"limit_usd"`
			ResetInterval    string   `json:"reset_interval"`
			EnforceZDR       bool     `json:"enforce_zdr"`
		} `json:"data"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode openrouter catalog: %w", err)
	}

	out := make([]CatalogEntry, 0, len(payload.Data))
	for _, guardrail := range payload.Data {
		metadata := map[string]string{"enforce_zdr": strconv.FormatBool(guardrail.EnforceZDR)}
		if guardrail.WorkspaceID != "" {
			metadata["workspace_id"] = guardrail.WorkspaceID
		}
		if len(guardrail.AllowedModels) > 0 {
			metadata["allowed_models"] = strings.Join(guardrail.AllowedModels, ",")
		}
		if len(guardrail.AllowedProviders) > 0 {
			metadata["allowed_providers"] = strings.Join(guardrail.AllowedProviders, ",")
		}
		if len(guardrail.IgnoredModels) > 0 {
			metadata["ignored_models"] = strings.Join(guardrail.IgnoredModels, ",")
		}
		if len(guardrail.IgnoredProviders) > 0 {
			metadata["ignored_providers"] = strings.Join(guardrail.IgnoredProviders, ",")
		}
		if guardrail.LimitUSD != 0 {
			metadata["limit_usd"] = strconv.FormatFloat(guardrail.LimitUSD, 'f', 2, 64)
		}
		if guardrail.ResetInterval != "" {
			metadata["reset_interval"] = guardrail.ResetInterval
		}
		out = append(out, CatalogEntry{
			ProviderID:  p.ID(),
			EntryID:     guardrail.ID,
			Name:        firstNonEmpty(guardrail.Name, guardrail.ID),
			Kind:        CatalogEntryAccountPolicy,
			Description: guardrail.Description,
			Metadata:    metadata,
		})
	}
	sortCatalogEntries(out)
	return out, nil
}

func (p *OpenRouterProvider) RunRuntime(context.Context, ProviderConfig, CatalogEntry, EvaluateRequest) (RuntimeResult, error) {
	return RuntimeResult{Verdict: "abstain"}, ErrRuntimeUnsupported
}

func (p *OpenRouterProvider) client() *http.Client {
	if p != nil && p.HTTPClient != nil {
		return p.HTTPClient
	}
	return http.DefaultClient
}

func (p *OpenRouterProvider) baseURL() string {
	if p != nil && p.BaseURL != "" {
		return p.BaseURL
	}
	return defaultOpenRouterBaseURL
}

func applyBearer(req *http.Request, apiKey SecretString) {
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey.Value())
	}
}
