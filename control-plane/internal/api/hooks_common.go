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

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

var processExitCodePattern = regexp.MustCompile(`(?i)process exited with code\s+(-?\d+)`)

// summarizeToolResponse returns (response_size, success) for a heterogeneous
// PostToolUse tool_response payload. Failure signals (any one is enough):
//
//	is_error: true        — Anthropic canonical (Claude Code)
//	exit_code/status      — Codex command responses
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
		if success, ok := explicitToolSuccess(m); ok {
			return size, success
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

func explicitToolSuccess(m map[string]any) (bool, bool) {
	for _, key := range []string{"success", "ok"} {
		if v, ok := m[key].(bool); ok {
			return v, true
		}
	}
	for _, key := range []string{"exit_code", "exitCode", "exitCodeInt", "code"} {
		if code, ok := numericExitCode(m[key]); ok {
			return code == 0, true
		}
	}
	for _, key := range []string{"status", "state"} {
		if success, ok := statusSuccess(m[key]); ok {
			return success, true
		}
	}
	for _, key := range []string{"output", "stdout", "stderr", "message"} {
		if code, ok := outputExitCode(m[key]); ok {
			return code == 0, true
		}
	}
	return false, false
}

func numericExitCode(v any) (int, bool) {
	switch n := v.(type) {
	case nil:
		return 0, false
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	case json.Number:
		i, err := n.Int64()
		if err == nil {
			return int(i), true
		}
	case string:
		i, err := strconv.Atoi(strings.TrimSpace(n))
		if err == nil {
			return i, true
		}
	}
	return 0, false
}

func statusSuccess(v any) (bool, bool) {
	s, ok := v.(string)
	if !ok {
		return false, false
	}
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "complete", "completed", "success", "succeeded", "ok":
		return true, true
	case "failed", "failure", "error", "errored", "canceled", "cancelled", "timeout", "timed_out":
		return false, true
	default:
		return false, false
	}
}

func outputExitCode(v any) (int, bool) {
	s, ok := v.(string)
	if !ok {
		return 0, false
	}
	matches := processExitCodePattern.FindStringSubmatch(s)
	if len(matches) != 2 {
		return 0, false
	}
	code, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0, false
	}
	return code, true
}
