package guardrails

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const defaultNVIDIABaseURL = "https://integrate.api.nvidia.com"

type NVIDIAProvider struct {
	BaseURL    string
	HTTPClient *http.Client
}

func (p *NVIDIAProvider) ID() string {
	return "nvidia"
}

func (p *NVIDIAProvider) Name() string {
	return "NVIDIA"
}

func (p *NVIDIAProvider) Capabilities() []string {
	return []string{"catalog", "runtime_classifier"}
}

func (p *NVIDIAProvider) TestCredentials(ctx context.Context, cfg ProviderConfig) error {
	if cfg.APIKey == "" {
		return fmt.Errorf("nvidia api key is required")
	}
	_, err := p.ListCatalog(ctx, cfg)
	return err
}

func (p *NVIDIAProvider) ListCatalog(ctx context.Context, cfg ProviderConfig) ([]CatalogEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(p.baseURL(), "/")+"/v1/models", nil)
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
		return nil, fmt.Errorf("nvidia catalog status %d: %s", res.StatusCode, readResponseBody(res.Body))
	}

	var payload struct {
		Data []struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Description string `json:"description"`
			Type        string `json:"type"`
		} `json:"data"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode nvidia catalog: %w", err)
	}

	out := make([]CatalogEntry, 0, len(payload.Data))
	for _, model := range payload.Data {
		if !looksLikeNVIDIAGuardrailModel(model.ID, model.Name) {
			continue
		}
		entry := CatalogEntry{
			ProviderID:                 p.ID(),
			EntryID:                    model.ID,
			Name:                       firstNonEmpty(model.Name, model.ID),
			Kind:                       CatalogEntryClassifierModel,
			Description:                model.Description,
			SupportsRuntimeEnforcement: true,
		}
		if model.Type != "" {
			entry.Metadata = map[string]string{"type": model.Type}
		}
		out = append(out, entry)
	}
	sortCatalogEntries(out)
	return out, nil
}

func (p *NVIDIAProvider) RunRuntime(ctx context.Context, cfg ProviderConfig, entry CatalogEntry, req EvaluateRequest) (RuntimeResult, error) {
	prompt, err := buildNVIDIARuntimePrompt(req)
	if err != nil {
		return RuntimeResult{}, err
	}
	body := map[string]any{
		"model":       entry.EntryID,
		"temperature": 0,
		"messages": []map[string]string{{
			"role":    "user",
			"content": prompt,
		}},
	}
	rawBody, err := json.Marshal(body)
	if err != nil {
		return RuntimeResult{}, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(p.baseURL(), "/")+"/v1/chat/completions", bytes.NewReader(rawBody))
	if err != nil {
		return RuntimeResult{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	applyBearer(httpReq, cfg.APIKey)

	res, err := p.client().Do(httpReq)
	if err != nil {
		return RuntimeResult{}, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return RuntimeResult{}, fmt.Errorf("nvidia runtime status %d: %s", res.StatusCode, readResponseBody(res.Body))
	}

	var payload struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		return RuntimeResult{}, fmt.Errorf("decode nvidia runtime: %w", err)
	}
	if len(payload.Choices) == 0 {
		return RuntimeResult{}, fmt.Errorf("nvidia runtime returned no choices")
	}

	parsed, err := parseNVIDIAVerdict(payload.Choices[0].Message.Content)
	if err != nil {
		return RuntimeResult{}, err
	}
	parsed.ProviderID = p.ID()
	parsed.EntryID = entry.EntryID
	return parsed, nil
}

func readResponseBody(body io.Reader) string {
	raw, err := io.ReadAll(body)
	if err != nil {
		return "failed to read response body: " + err.Error()
	}
	return strings.TrimSpace(string(raw))
}

func (p *NVIDIAProvider) client() *http.Client {
	if p != nil && p.HTTPClient != nil {
		return p.HTTPClient
	}
	return http.DefaultClient
}

func (p *NVIDIAProvider) baseURL() string {
	if p != nil && p.BaseURL != "" {
		return p.BaseURL
	}
	return defaultNVIDIABaseURL
}

func looksLikeNVIDIAGuardrailModel(id, name string) bool {
	text := strings.ToLower(id + " " + name)
	return strings.Contains(text, "content-safety") ||
		strings.Contains(text, "content safety") ||
		strings.Contains(text, "safety-guard") ||
		strings.Contains(text, "safety guard") ||
		strings.Contains(text, "nemoguard") ||
		strings.Contains(text, "topic-control") ||
		strings.Contains(text, "topic control")
}

func buildNVIDIARuntimePrompt(req EvaluateRequest) (string, error) {
	inputJSON, err := json.Marshal(req.Input)
	if err != nil {
		return "", fmt.Errorf("marshal runtime input: %w", err)
	}
	return fmt.Sprintf(`Task: Check whether the following agent tool invocation is safe or unsafe. Return only JSON.
Conversation JSON:
{"source":%q,"tool":%q,"input":%s}
Output JSON:
{"User Safety":"safe or unsafe","Safety Categories":"comma-separated categories if unsafe"}`, req.Source, req.Tool, string(inputJSON)), nil
}

func parseNVIDIAVerdict(content string) (RuntimeResult, error) {
	clean := strings.TrimSpace(content)
	clean = strings.TrimPrefix(clean, "```json")
	clean = strings.TrimPrefix(clean, "```")
	clean = strings.TrimSuffix(clean, "```")
	clean = strings.TrimSpace(clean)

	var payload struct {
		UserSafety       string `json:"User Safety"`
		ResponseSafety   string `json:"Response Safety"`
		SafetyCategories string `json:"Safety Categories"`
	}
	if err := json.Unmarshal([]byte(clean), &payload); err != nil {
		return RuntimeResult{}, fmt.Errorf("parse nvidia verdict: %w", err)
	}

	userSafety, userSet, err := parseSafetyLabel("User Safety", payload.UserSafety)
	if err != nil {
		return RuntimeResult{}, err
	}
	responseSafety, responseSet, err := parseSafetyLabel("Response Safety", payload.ResponseSafety)
	if err != nil {
		return RuntimeResult{}, err
	}
	if !userSet && !responseSet {
		return RuntimeResult{}, fmt.Errorf("parse nvidia verdict: missing safety label")
	}

	verdict := "allow"
	if userSafety == "unsafe" || responseSafety == "unsafe" {
		verdict = "deny"
	}
	details := map[string]string{}
	if userSet {
		details["user_safety"] = userSafety
	}
	if responseSet {
		details["response_safety"] = responseSafety
	}
	if payload.SafetyCategories != "" {
		details["safety_categories"] = payload.SafetyCategories
	}
	return RuntimeResult{Verdict: verdict, Details: details}, nil
}

func parseSafetyLabel(field, value string) (string, bool, error) {
	if strings.TrimSpace(value) == "" {
		return "", false, nil
	}
	label := strings.ToLower(strings.TrimSpace(value))
	switch label {
	case "safe", "unsafe":
		return label, true, nil
	default:
		return "", false, fmt.Errorf("parse nvidia verdict: invalid %s %q", field, value)
	}
}
