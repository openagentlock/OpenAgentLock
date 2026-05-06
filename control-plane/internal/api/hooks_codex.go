// Codex CLI hook endpoints. The shim binary at `agentlock hook codex
// <event>` reads Codex's stdin JSON, POSTs it here, and translates the
// response into Codex's exit-code / JSON shape on the way out. Daemon-side
// flow mirrors hooks_claude.go: auto-create unattested session, evaluate
// against the live policy, suppress deny in monitor mode, append to the
// ledger. Source tag is "codex".
//
// Codex's request payload carries both tool_use_id and turn_id. We use
// tool_use_id as the idempotency key (parity with Claude's ledger) and
// record turn_id alongside in the payload hash so the dashboard can
// correlate calls within the same turn.

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

type codexPreToolInput struct {
	SessionID     string         `json:"session_id"`
	HookEventName string         `json:"hook_event_name"`
	ToolName      string         `json:"tool_name"`
	ToolInput     map[string]any `json:"tool_input"`
	ToolUseID     string         `json:"tool_use_id"`
	TurnID        string         `json:"turn_id"`
	Cwd           string         `json:"cwd"`
	Model         string         `json:"model"`
}

func codexPreToolUseHandler(d Deps) http.HandlerFunc {
	if d.Store == nil {
		return todo("hooks.codex.pre-tool-use")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var in codexPreToolInput
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		if in.SessionID == "" || in.ToolName == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "session_id, tool_name required")
			return
		}

		sess, err := ensureCodexSession(r, d, in.SessionID)
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

		toolUseID := in.ToolUseID
		if toolUseID == "" {
			toolUseID = "codex.pre-tool-use"
		}

		payloadBytes, err := json.Marshal(map[string]any{
			"session_id":    in.SessionID,
			"source":        "codex",
			"tool":          in.ToolName,
			"input":         in.ToolInput,
			"turn_id":       in.TurnID,
			"verdict":       origVerdict,
			"rule_id":       result.RuleID,
			"daemon_mode":   mode,
			"monitor_match": monitorMatch,
		})
		if err != nil {
			log.Printf("codex pre-tool-use: marshal: %v", err)
			writeError(w, http.StatusInternalServerError, "marshal_error", err.Error())
			return
		}
		payloadHash := sha256.Sum256(payloadBytes)
		if _, err := d.Store.AppendLedger(r.Context(), storage.AppendInput{
			TS:           time.Now().UTC(),
			Source:       "codex",
			Tool:         in.ToolName,
			ToolUseID:    toolUseID,
			Signer:       sess.Signer,
			RuleID:       result.RuleID,
			Verdict:      origVerdict,
			MonitorMatch: monitorMatch,
			MatcherInput: ledgerMatcherInput(in.ToolInput),
			PayloadHash:  payloadHash[:],
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "ledger_error", err.Error())
			return
		}

		// Same response envelope as Claude — the shim binary maps it onto
		// Codex's exit-code semantics (allow → exit 0; deny → exit 2 with
		// the JSON also written to stdout for harnesses that read it).
		// On deny + nudge, the hint is concatenated into the reason so
		// the model sees it through Codex's stderr channel.
		reason := denyReasonWithNudge(result)
		out := claudeHookOutput{
			Continue: result.Verdict == "allow",
			HookSpecificOutput: claudeHookSpecifics{
				HookEventName:            "PreToolUse",
				PermissionDecision:       result.Verdict,
				PermissionDecisionReason: reason,
			},
		}
		if result.Verdict == "deny" {
			out.StopReason = reason
		}
		writeJSON(w, http.StatusOK, out)
	}
}

type codexPostToolInput struct {
	SessionID     string         `json:"session_id"`
	HookEventName string         `json:"hook_event_name"`
	ToolName      string         `json:"tool_name"`
	ToolInput     map[string]any `json:"tool_input"`
	ToolUseID     string         `json:"tool_use_id"`
	TurnID        string         `json:"turn_id"`
	// Codex hook payloads don't carry a reliable top-level success
	// boolean; we derive it from tool_response so the ledger reflects
	// what the tool actually did. See hooks_common.go.
	ToolResponse any `json:"tool_response"`
}

func codexPostToolUseHandler(d Deps) http.HandlerFunc {
	if d.Store == nil {
		return todo("hooks.codex.post-tool-use")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var in codexPostToolInput
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		if in.SessionID == "" || in.ToolName == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "session_id, tool_name required")
			return
		}

		sess, err := ensureCodexSession(r, d, in.SessionID)
		if err != nil {
			log.Printf("codex post-tool-use: ensureCodexSession: %v", err)
			writeError(w, http.StatusInternalServerError, "session_error", "session create failed")
			return
		}

		respSize, success := summarizeToolResponse(in.ToolResponse)

		toolUseID := in.ToolUseID
		if toolUseID == "" {
			toolUseID = "codex.post-tool-use"
		}
		verdict := "complete"
		if !success {
			verdict = "failure"
		}

		payloadBytes, err := json.Marshal(map[string]any{
			"session_id":    in.SessionID,
			"source":        "codex",
			"tool":          in.ToolName,
			"tool_use_id":   toolUseID,
			"turn_id":       in.TurnID,
			"response_size": respSize,
			"success":       success,
		})
		if err != nil {
			log.Printf("codex post-tool-use: marshal: %v", err)
			writeError(w, http.StatusInternalServerError, "marshal_error", "payload hash failed")
			return
		}
		payloadHash := sha256.Sum256(payloadBytes)
		if _, err := d.Store.AppendLedger(r.Context(), storage.AppendInput{
			TS:          time.Now().UTC(),
			Source:      "codex",
			ToolUseID:   toolUseID,
			Tool:        in.ToolName,
			Signer:      sess.Signer,
			Verdict:     verdict,
			PayloadHash: payloadHash[:],
		}); err != nil {
			log.Printf("codex post-tool-use: AppendLedger: %v", err)
			writeError(w, http.StatusInternalServerError, "ledger_error", "ledger append failed")
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{"continue": true})
	}
}

type codexSessionStartInput struct {
	SessionID      string `json:"session_id"`
	HookEventName  string `json:"hook_event_name"`
	TranscriptPath string `json:"transcript_path"`
	Cwd            string `json:"cwd"`
	Model          string `json:"model"`
}

func codexSessionStartHandler(d Deps) http.HandlerFunc {
	if d.Store == nil {
		return todo("hooks.codex.session-start")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var in codexSessionStartInput
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		if in.SessionID == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "session_id required")
			return
		}

		sess, err := ensureCodexSession(r, d, in.SessionID)
		if err != nil {
			log.Printf("codex session-start: ensureCodexSession: %v", err)
			writeError(w, http.StatusInternalServerError, "session_error", "session create failed")
			return
		}

		payloadBytes, err := json.Marshal(map[string]any{
			"session_id":      in.SessionID,
			"source":          "codex",
			"cwd":             in.Cwd,
			"transcript_path": in.TranscriptPath,
			"model":           in.Model,
		})
		if err != nil {
			log.Printf("codex session-start: marshal: %v", err)
			writeError(w, http.StatusInternalServerError, "marshal_error", "payload hash failed")
			return
		}
		payloadHash := sha256.Sum256(payloadBytes)
		if _, err := d.Store.AppendLedger(r.Context(), storage.AppendInput{
			TS:          time.Now().UTC(),
			Source:      "codex",
			ToolUseID:   "codex.session-start",
			Signer:      sess.Signer,
			PayloadHash: payloadHash[:],
		}); err != nil {
			log.Printf("codex session-start: AppendLedger: %v", err)
			writeError(w, http.StatusInternalServerError, "ledger_error", "ledger append failed")
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{"continue": true})
	}
}

type codexStopInput struct {
	SessionID     string `json:"session_id"`
	HookEventName string `json:"hook_event_name"`
}

func codexStopHandler(d Deps) http.HandlerFunc {
	if d.Store == nil {
		return todo("hooks.codex.stop")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var in codexStopInput
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
				log.Printf("codex stop: EndSession: %v", err)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"continue": true})
	}
}

func ensureCodexSession(r *http.Request, d Deps, id string) (storage.Session, error) {
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
		Harness:       "codex",
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
		"source":     "codex",
		"reason":     "auto-created on first hook traffic",
	})
	payloadHash := sha256.Sum256(payloadBytes)
	if _, err := d.Store.AppendLedger(r.Context(), storage.AppendInput{
		TS:          now,
		Source:      "codex",
		ToolUseID:   "session.auto-create",
		Signer:      "none",
		PayloadHash: payloadHash[:],
	}); err != nil {
		log.Printf("codex auto-session ledger: %v", err)
	}
	return newSess, nil
}
