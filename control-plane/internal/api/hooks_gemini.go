// Gemini CLI hook endpoints. The shim binary at `agentlock hook gemini
// <event>` reads Gemini's stdin JSON, POSTs it here, and translates the
// response into Gemini's exit-code / JSON shape on the way out. Daemon-side
// flow mirrors hooks_codex.go: auto-create unattested session, evaluate
// against the live policy, suppress deny in monitor mode, append to the
// ledger. Source tag is "gemini".
//
// Wire-shape differences from Claude/Codex:
//   * Gemini's hook decision field is a flat `decision: "allow"|"deny"`
//     with a sibling `reason: "..."` — NOT Claude's nested
//     hookSpecificOutput.permissionDecision shape. We keep `continue` and
//     `stopReason` for harnesses that read those, but the load-bearing
//     fields here are `decision` + `reason`.
//   * Gemini doesn't send a tool_use_id. We synthesize one
//     ("gemini.pre-tool-use", etc.) so the ledger's idempotency key is
//     populated.
//   * MCP tools come through with names of the form `mcp_<server>_<tool>`
//     and the same tool_input schema as built-ins, so policy evaluation
//     is uniform — no Codex-style "MCP gap" caveat.
//   * Gemini's hook events are BeforeTool / AfterTool / SessionStart /
//     SessionEnd. We expose them under the same /v1/hooks/<harness>/<event>
//     URL convention as the other harnesses (pre-tool-use / post-tool-use
//     / session-start / stop) — the shim does the BeforeTool→pre-tool-use
//     name translation on the way in.

package api

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/openagentlock/openagentlock/control-plane/internal/policy"
	"github.com/openagentlock/openagentlock/control-plane/internal/storage"
)

// geminiHookOutput is the response envelope the shim parses. The shim
// keys off `decision` for the gating verdict and writes `reason` to
// stderr on deny. `continue` and `stopReason` are kept for forward-
// compatibility with Gemini versions that read either contract.
type geminiHookOutput struct {
	Continue   bool   `json:"continue"`
	StopReason string `json:"stopReason,omitempty"`
	Decision   string `json:"decision,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

type geminiPreToolInput struct {
	SessionID           string         `json:"session_id"`
	HookEventName       string         `json:"hook_event_name"`
	ToolName            string         `json:"tool_name"`
	ToolInput           map[string]any `json:"tool_input"`
	OriginalRequestName string         `json:"original_request_name"`
	MCPContext          map[string]any `json:"mcp_context"`
	TranscriptPath      string         `json:"transcript_path"`
	Cwd                 string         `json:"cwd"`
}

func geminiPreToolUseHandler(d Deps) http.HandlerFunc {
	if d.Store == nil {
		return todo("hooks.gemini.pre-tool-use")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var in geminiPreToolInput
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		if in.SessionID == "" || in.ToolName == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "session_id, tool_name required")
			return
		}

		sess, err := ensureGeminiSession(r, d, in.SessionID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "session_error", err.Error())
			return
		}

		evalPolicy := resolvePolicy(d, sess.PolicyHash)
		if evalPolicy == nil {
			writeError(w, http.StatusServiceUnavailable, "policy_unavailable", "no policy loaded")
			return
		}
		result := evalPolicy.Evaluate(policy.EvalRequest{
			Tool:  in.ToolName,
			Input: in.ToolInput,
		})

		var origVerdict, mode string
		result, mode, origVerdict = applyDaemonModeOverride(result)
		monitorMatch := result.MonitorMatch

		toolUseID := "gemini.pre-tool-use"

		payloadBytes, err := json.Marshal(map[string]any{
			"session_id":    in.SessionID,
			"source":        "gemini",
			"tool":          in.ToolName,
			"input":         in.ToolInput,
			"verdict":       origVerdict,
			"rule_id":       result.RuleID,
			"daemon_mode":   mode,
			"monitor_match": monitorMatch,
		})
		if err != nil {
			log.Printf("gemini pre-tool-use: marshal: %v", err)
			writeError(w, http.StatusInternalServerError, "marshal_error", err.Error())
			return
		}
		payloadHash := sha256.Sum256(payloadBytes)
		if _, err := d.Store.AppendLedger(r.Context(), storage.AppendInput{
			TS:           time.Now().UTC(),
			Source:       "gemini",
			ToolUseID:    toolUseID,
			Tool:    in.ToolName,
			Signer:       sess.Signer,
			RuleID:       result.RuleID,
			Verdict:      origVerdict,
			MonitorMatch: monitorMatch,
			PayloadHash:  payloadHash[:],
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "ledger_error", err.Error())
			return
		}

		reason := denyReasonWithNudge(result)
		out := geminiHookOutput{
			Continue: result.Verdict == "allow",
			Decision: result.Verdict,
			Reason:   reason,
		}
		if result.Verdict == "deny" {
			out.StopReason = reason
		}
		writeJSON(w, http.StatusOK, out)
	}
}

type geminiPostToolInput struct {
	SessionID     string         `json:"session_id"`
	HookEventName string         `json:"hook_event_name"`
	ToolName      string         `json:"tool_name"`
	ToolInput     map[string]any `json:"tool_input"`
	ToolResponse  any            `json:"tool_response"`
	// Gemini doesn't send a discrete success bool; presence of an `error`
	// field inside tool_response is the failure signal. We surface that
	// via the synthesized verdict below.
}

func geminiPostToolUseHandler(d Deps) http.HandlerFunc {
	if d.Store == nil {
		return todo("hooks.gemini.post-tool-use")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var in geminiPostToolInput
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		if in.SessionID == "" || in.ToolName == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "session_id, tool_name required")
			return
		}

		sess, err := ensureGeminiSession(r, d, in.SessionID)
		if err != nil {
			log.Printf("gemini post-tool-use: ensureGeminiSession: %v", err)
			writeError(w, http.StatusInternalServerError, "session_error", "session create failed")
			return
		}

		respSize, success := summarizeToolResponse(in.ToolResponse)
		toolUseID := "gemini.post-tool-use"
		verdict := "complete"
		if !success {
			verdict = "failure"
		}

		payloadBytes, err := json.Marshal(map[string]any{
			"session_id":    in.SessionID,
			"source":        "gemini",
			"tool":          in.ToolName,
			"tool_use_id":   toolUseID,
			"response_size": respSize,
			"success":       success,
		})
		if err != nil {
			log.Printf("gemini post-tool-use: marshal: %v", err)
			writeError(w, http.StatusInternalServerError, "marshal_error", "payload hash failed")
			return
		}
		payloadHash := sha256.Sum256(payloadBytes)
		if _, err := d.Store.AppendLedger(r.Context(), storage.AppendInput{
			TS:          time.Now().UTC(),
			Source:      "gemini",
			ToolUseID:   toolUseID,
			Tool:   in.ToolName,
			Signer:      sess.Signer,
			Verdict:     verdict,
			PayloadHash: payloadHash[:],
		}); err != nil {
			log.Printf("gemini post-tool-use: AppendLedger: %v", err)
			writeError(w, http.StatusInternalServerError, "ledger_error", "ledger append failed")
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{"continue": true})
	}
}

type geminiSessionStartInput struct {
	SessionID      string `json:"session_id"`
	HookEventName  string `json:"hook_event_name"`
	TranscriptPath string `json:"transcript_path"`
	Cwd            string `json:"cwd"`
	// Source is Gemini's enum: "startup" | "resume" | "clear".
	Source string `json:"source"`
}

func geminiSessionStartHandler(d Deps) http.HandlerFunc {
	if d.Store == nil {
		return todo("hooks.gemini.session-start")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var in geminiSessionStartInput
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		if in.SessionID == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "session_id required")
			return
		}

		sess, err := ensureGeminiSession(r, d, in.SessionID)
		if err != nil {
			log.Printf("gemini session-start: ensureGeminiSession: %v", err)
			writeError(w, http.StatusInternalServerError, "session_error", "session create failed")
			return
		}

		payloadBytes, err := json.Marshal(map[string]any{
			"session_id":      in.SessionID,
			"source":          "gemini",
			"gemini_source":   in.Source,
			"cwd":             in.Cwd,
			"transcript_path": in.TranscriptPath,
		})
		if err != nil {
			log.Printf("gemini session-start: marshal: %v", err)
			writeError(w, http.StatusInternalServerError, "marshal_error", "payload hash failed")
			return
		}
		payloadHash := sha256.Sum256(payloadBytes)
		if _, err := d.Store.AppendLedger(r.Context(), storage.AppendInput{
			TS:          time.Now().UTC(),
			Source:      "gemini",
			ToolUseID:   "gemini.session-start",
			Signer:      sess.Signer,
			PayloadHash: payloadHash[:],
		}); err != nil {
			log.Printf("gemini session-start: AppendLedger: %v", err)
			writeError(w, http.StatusInternalServerError, "ledger_error", "ledger append failed")
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{"continue": true})
	}
}

type geminiStopInput struct {
	SessionID     string `json:"session_id"`
	HookEventName string `json:"hook_event_name"`
	// Reason is Gemini's enum: "exit" | "clear" | "logout" |
	// "prompt_input_exit" | "other". We don't gate on it; the dashboard
	// can read it from the payload hash later if it wants per-reason
	// breakdowns.
	Reason string `json:"reason"`
}

// geminiStopHandler is the SessionEnd shim. Mirrors codexStopHandler — end
// the session if it exists, swallow ErrSessionEnded (re-end), no error on
// missing (Gemini may fire SessionEnd for sessions we never saw a tool
// call on).
func geminiStopHandler(d Deps) http.HandlerFunc {
	if d.Store == nil {
		return todo("hooks.gemini.stop")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var in geminiStopInput
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		if in.SessionID == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "session_id required")
			return
		}
		if _, err := d.Store.GetSession(r.Context(), in.SessionID); err == nil {
			if err := d.Store.EndSession(r.Context(), in.SessionID); err != nil && !errors.Is(err, storage.ErrSessionEnded) {
				log.Printf("gemini stop: EndSession: %v", err)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"continue": true})
	}
}

func ensureGeminiSession(r *http.Request, d Deps, id string) (storage.Session, error) {
	sess, err := d.Store.GetSession(r.Context(), id)
	if err == nil {
		return sess, nil
	}
	if !errors.Is(err, storage.ErrSessionNotFound) {
		return storage.Session{}, err
	}
	now := time.Now().UTC()
	live := livePolicyFor(d)
	policyHash := ""
	if live != nil {
		policyHash = live.Hash
	}
	newSess := storage.Session{
		ID:            id,
		StartedAt:     now,
		ExpiresAt:     now.Add(24 * time.Hour),
		PolicyHash:    policyHash,
		SessionPubKey: "none",
		Signer:        "none",
		SignerPubKey:  "none",
		Harness:       "gemini",
	}
	if err := d.Store.CreateSession(r.Context(), newSess); err != nil {
		if errors.Is(err, storage.ErrSessionExists) {
			return d.Store.GetSession(r.Context(), id)
		}
		return storage.Session{}, err
	}
	payloadBytes, _ := json.Marshal(map[string]any{
		"session_id": id,
		"signer":     "none",
		"source":     "gemini",
		"reason":     "auto-created on first hook traffic",
	})
	payloadHash := sha256.Sum256(payloadBytes)
	if _, err := d.Store.AppendLedger(r.Context(), storage.AppendInput{
		TS:          now,
		Source:      "gemini",
		ToolUseID:   "session.auto-create",
		Signer:      "none",
		PayloadHash: payloadHash[:],
	}); err != nil {
		log.Printf("gemini auto-session ledger: %v", err)
	}
	return newSess, nil
}
