// Helpers shared across the per-harness PostToolUse handlers.
//
// Each harness (Claude Code, Codex, Cursor, Gemini) emits a `tool_response`
// blob whose shape varies by tool. Different harness specs encode failure
// differently — Anthropic's canonical tool_result uses `is_error: true`,
// Gemini and some Codex flows use a non-empty `error` member. None of the
// harnesses emit a reliable top-level `success` boolean (the daemon used
// to read one anyway, which left every Claude tool call mis-labeled as a
// failure). summarizeToolResponse derives the success flag from the actual
// payload so the ledger reflects what the tool did, not what the harness
// did or didn't bother to forward.

package api

import "encoding/json"

// summarizeToolResponse returns (response_size, success) for a heterogeneous
// PostToolUse tool_response payload. Failure signals (any one is enough):
//
//	is_error: true        — Anthropic canonical (Claude Code)
//	error: <non-empty>    — Gemini / some Codex tools
//
// Anything else is treated as a successful run. We never hash the response
// body itself; only its byte length feeds the Merkle chain, so large
// outputs and any secrets they might contain stay out of the audit log.
func summarizeToolResponse(resp any) (int, bool) {
	if resp == nil {
		return 0, true
	}
	if s, ok := resp.(string); ok {
		return len(s), true
	}
	if m, ok := resp.(map[string]any); ok {
		size := 0
		if b, err := json.Marshal(m); err == nil {
			size = len(b)
		}
		if v, ok := m["is_error"].(bool); ok && v {
			return size, false
		}
		if errVal, present := m["error"]; present {
			switch v := errVal.(type) {
			case nil:
			case string:
				if v != "" {
					return size, false
				}
			case bool:
				if v {
					return size, false
				}
			default:
				return size, false
			}
		}
		return size, true
	}
	if b, err := json.Marshal(resp); err == nil {
		return len(b), true
	}
	return 0, true
}
