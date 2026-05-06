package api

import (
	"net/url"
	"strings"
)

var mcpURLCandidateKeys = []string{
	"url",
	"server_url",
	"mcp_server_url",
	"transport_url",
	"base_url",
}

func normalizeMCPHTTPURLInput(tool string, input map[string]any, extra ...map[string]any) map[string]any {
	if input == nil {
		input = map[string]any{}
	}
	if !isMCPToolName(tool) {
		return input
	}
	if existing, _ := input["url"].(string); isHTTPURL(existing) {
		return input
	}
	maps := append([]map[string]any{input}, extra...)
	for _, candidate := range mcpHTTPURLCandidates(maps...) {
		if isHTTPURL(candidate) {
			input["url"] = candidate
			return input
		}
	}
	return input
}

func isMCPToolName(tool string) bool {
	return strings.HasPrefix(tool, "mcp__") || strings.HasPrefix(tool, "mcp_")
}

func mcpHTTPURLCandidates(maps ...map[string]any) []string {
	var out []string
	var walk func(map[string]any)
	walk = func(m map[string]any) {
		for _, key := range mcpURLCandidateKeys {
			if value, ok := m[key].(string); ok && value != "" {
				out = append(out, value)
			}
		}
		for _, value := range m {
			if nested, ok := value.(map[string]any); ok {
				walk(nested)
			}
		}
	}
	for _, m := range maps {
		if len(m) > 0 {
			walk(m)
		}
	}
	return out
}

func isHTTPURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}
