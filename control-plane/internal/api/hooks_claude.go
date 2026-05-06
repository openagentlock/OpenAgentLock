// Claude Code hook endpoints. These accept Claude's native PreToolUse /
// Stop JSON shape and emit Claude's expected hookSpecificOutput response.
// Unlike /v1/gates/check, these auto-create a daemon-side session on first
// traffic from an unknown session_id, tagged signer="none" (unattested).
// The unattested tag drives the red dashboard banner per CLAUDE.md signer
// discipline.

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

type claudePreToolInput struct {
	SessionID     string         `json:"session_id"`
	HookEventName string         `json:"hook_event_name"`
	ToolName      string         `json:"tool_name"`
	ToolInput     map[string]any `json:"tool_input"`
	ToolUseID     string         `json:"tool_use_id"`
	Cwd           string         `json:"cwd"`
}

type claudeHookOutput struct {
	Continue           bool                `json:"continue"`
	StopReason         string              `json:"stopReason,omitempty"`
	HookSpecificOutput claudeHookSpecifics `json:"hookSpecificOutput"`
}

type claudeHookSpecifics struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision,omitempty"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
}

func claudePreToolUseHandler(d Deps) http.HandlerFunc {
	// Only Store is load-bearing at handler construction time. The policy
	// is resolved per-request via resolvePolicy so a live policy reload
	// (or initial bootstrap that happened after wiring) is picked up
	// without needing a restart.
	if d.Store == nil {
		return todo("hooks.claude-code.pre-tool-use")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var in claudePreToolInput
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		if in.SessionID == "" || in.ToolName == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "session_id, tool_name required")
			return
		}

		sess, err := ensureClaudeSession(r, d, in.SessionID)
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
			toolUseID = "claude.pre-tool-use"
		}

		payloadBytes, err := json.Marshal(map[string]any{
			"session_id":    in.SessionID,
			"source":        "claude-code",
			"tool":          in.ToolName,
			"input":         in.ToolInput,
			"verdict":       origVerdict,
			"rule_id":       result.RuleID,
			"daemon_mode":   mode,
			"monitor_match": monitorMatch,
		})
		if err != nil {
			log.Printf("claude pre-tool-use: marshal: %v", err)
			writeError(w, http.StatusInternalServerError, "marshal_error", err.Error())
			return
		}
		payloadHash := sha256.Sum256(payloadBytes)
		if _, err := d.Store.AppendLedger(r.Context(), storage.AppendInput{
			TS:           time.Now().UTC(),
			Source:       "claude-code",
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

		// On deny with a nudge attached, append the hint into the same
		// channel — the harness's reason text — so the model sees both
		// the verdict explanation and the suggested remediation.
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

type claudeStopInput struct {
	SessionID     string `json:"session_id"`
	HookEventName string `json:"hook_event_name"`
}

type claudePostToolInput struct {
	SessionID     string         `json:"session_id"`
	HookEventName string         `json:"hook_event_name"`
	ToolName      string         `json:"tool_name"`
	ToolInput     map[string]any `json:"tool_input"`
	ToolUseID     string         `json:"tool_use_id"`
	// Claude Code populates `tool_response` with whatever the tool
	// returned. We don't mirror the full payload into the ledger
	// (potential secret-leak), just its success flag + a size hint.
	ToolResponse any  `json:"tool_response"`
	Success      bool `json:"success"`
}

// claudePostToolUseHandler records the completion outcome of each tool
// call in the ledger. Not a gate — we already denied or allowed at
// PreToolUse. This is observability: it gives the dashboard a row that
// says "the Bash call we allowed at seq N actually ran to completion
// at seq N+1". Without it, a successful-but-slow tool call looks the
// same in the ledger as a tool that silently failed server-side.
func claudePostToolUseHandler(d Deps) http.HandlerFunc {
	if d.Store == nil {
		return todo("hooks.claude-code.post-tool-use")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var in claudePostToolInput
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		if in.SessionID == "" || in.ToolName == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "session_id, tool_name required")
			return
		}

		// Auto-create the session if we haven't seen it yet. PreToolUse
		// should have created it earlier, but a restarted daemon or a
		// Claude that skipped PreToolUse entirely can land a PostToolUse
		// for an unknown session; treat that the same way.
		sess, err := ensureClaudeSession(r, d, in.SessionID)
		if err != nil {
			log.Printf("claude post-tool-use: ensureClaudeSession: %v", err)
			writeError(w, http.StatusInternalServerError, "session_error", "session create failed")
			return
		}

		// Only the size of the response goes into the ledger — enough
		// to distinguish "tool ran" from "tool timed out returning
		// nothing" without risking that a curl response with a secret
		// in it lands in the Merkle-hashed payload.
		respSize := 0
		if in.ToolResponse != nil {
			if s, ok := in.ToolResponse.(string); ok {
				respSize = len(s)
			} else if b, mErr := json.Marshal(in.ToolResponse); mErr == nil {
				respSize = len(b)
			}
		}

		toolUseID := in.ToolUseID
		if toolUseID == "" {
			toolUseID = "claude.post-tool-use"
		}
		verdict := "complete"
		if !in.Success {
			verdict = "failure"
		}

		payloadBytes, err := json.Marshal(map[string]any{
			"session_id":    in.SessionID,
			"source":        "claude-code",
			"tool":          in.ToolName,
			"tool_use_id":   toolUseID,
			"response_size": respSize,
			"success":       in.Success,
		})
		if err != nil {
			log.Printf("claude post-tool-use: marshal: %v", err)
			writeError(w, http.StatusInternalServerError, "marshal_error", "payload hash failed")
			return
		}
		payloadHash := sha256.Sum256(payloadBytes)
		if _, err := d.Store.AppendLedger(r.Context(), storage.AppendInput{
			TS:          time.Now().UTC(),
			Source:      "claude-code",
			ToolUseID:   toolUseID,
			Tool:        in.ToolName,
			Signer:      sess.Signer,
			Verdict:     verdict,
			PayloadHash: payloadHash[:],
		}); err != nil {
			log.Printf("claude post-tool-use: AppendLedger: %v", err)
			writeError(w, http.StatusInternalServerError, "ledger_error", "ledger append failed")
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{"continue": true})
	}
}

type claudeSessionStartInput struct {
	SessionID      string `json:"session_id"`
	HookEventName  string `json:"hook_event_name"`
	TranscriptPath string `json:"transcript_path"`
	Cwd            string `json:"cwd"`
	// Source is Claude Code's own enum: "startup" (fresh launch),
	// "resume" (reopened transcript), or "clear" (conversation reset).
	Source string `json:"source"`
}

// claudeSessionStartHandler fires when Claude Code launches (or
// resumes, or clears). We use it to create a daemon-side session
// immediately so the Sessions tab shows the harness connection even
// before any tool call happens. Also emits a ledger entry tagged
// `claude.session-start` so the audit log records when the harness
// attached.
func claudeSessionStartHandler(d Deps) http.HandlerFunc {
	if d.Store == nil {
		return todo("hooks.claude-code.session-start")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var in claudeSessionStartInput
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		if in.SessionID == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "session_id required")
			return
		}

		sess, err := ensureClaudeSession(r, d, in.SessionID)
		if err != nil {
			log.Printf("claude session-start: ensureClaudeSession: %v", err)
			writeError(w, http.StatusInternalServerError, "session_error", "session create failed")
			return
		}

		payloadBytes, err := json.Marshal(map[string]any{
			"session_id":      in.SessionID,
			"source":          "claude-code",
			"claude_source":   in.Source, // startup | resume | clear
			"cwd":             in.Cwd,
			"transcript_path": in.TranscriptPath,
		})
		if err != nil {
			log.Printf("claude session-start: marshal: %v", err)
			writeError(w, http.StatusInternalServerError, "marshal_error", "payload hash failed")
			return
		}
		payloadHash := sha256.Sum256(payloadBytes)
		if _, err := d.Store.AppendLedger(r.Context(), storage.AppendInput{
			TS:          time.Now().UTC(),
			Source:      "claude-code",
			ToolUseID:   "claude.session-start",
			Signer:      sess.Signer,
			PayloadHash: payloadHash[:],
		}); err != nil {
			log.Printf("claude session-start: AppendLedger: %v", err)
			writeError(w, http.StatusInternalServerError, "ledger_error", "ledger append failed")
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{"continue": true})
	}
}

func claudeStopHandler(d Deps) http.HandlerFunc {
	if d.Store == nil {
		return todo("hooks.claude-code.stop")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var in claudeStopInput
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		if in.SessionID == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "session_id required")
			return
		}
		// End the session if it exists. No error on missing — Claude may fire
		// Stop for sessions we never saw a tool call on.
		if _, err := d.Store.GetSession(r.Context(), in.SessionID); err == nil {
			if err := d.Store.EndSession(r.Context(), in.SessionID); err != nil && !errors.Is(err, storage.ErrSessionEnded) {
				log.Printf("claude stop: EndSession: %v", err)
			}
		}
		// Stop accepts only {continue, stopReason, ...} — NOT hookSpecificOutput.
		// Emitting the PreToolUse-shaped response fails Claude's schema validation.
		writeJSON(w, http.StatusOK, map[string]any{"continue": true})
	}
}

// ensureClaudeSession returns the daemon's session for the given ID,
// auto-creating an unattested "none" signer session if we have never seen
// it before. Auto-created sessions surface as red banners in the dashboard.
func ensureClaudeSession(r *http.Request, d Deps, id string) (storage.Session, error) {
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
		Harness:       "claude-code",
	}
	if err := d.Store.CreateSession(r.Context(), newSess); err != nil {
		if errors.Is(err, storage.ErrSessionExists) {
			return d.Store.GetSession(r.Context(), id)
		}
		return storage.Session{}, err
	}
	// Emit a session-create ledger entry tagged source=claude-code so the
	// dashboard shows the unattested session appearing.
	payloadBytes, _ := json.Marshal(map[string]any{
		"session_id": id,
		"signer":     "none",
		"source":     "claude-code",
		"reason":     "auto-created on first hook traffic",
	})
	payloadHash := sha256.Sum256(payloadBytes)
	if _, err := d.Store.AppendLedger(r.Context(), storage.AppendInput{
		TS:          now,
		Source:      "claude-code",
		ToolUseID:   "session.auto-create",
		Signer:      "none",
		PayloadHash: payloadHash[:],
	}); err != nil {
		log.Printf("claude auto-session ledger: %v", err)
	}
	return newSess, nil
}
