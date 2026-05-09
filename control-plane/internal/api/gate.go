package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/openagentlock/openagentlock/control-plane/internal/guardrails"
	"github.com/openagentlock/openagentlock/control-plane/internal/policy"
	"github.com/openagentlock/openagentlock/control-plane/internal/storage"
)

type gateCheckRequest struct {
	SessionID string         `json:"session_id"`
	Source    string         `json:"source"`
	Tool      string         `json:"tool"`
	Input     map[string]any `json:"input"`
	Cwd       string         `json:"cwd,omitempty"`
	Meta      map[string]any `json:"meta,omitempty"`
}

type gateCheckResponse struct {
	Verdict   string `json:"verdict"`
	RuleID    string `json:"rule_id"`
	Reason    string `json:"reason"`
	LedgerSeq uint64 `json:"ledger_seq"`
	Monitor   bool   `json:"monitor,omitempty"`
	Nudge     string `json:"nudge,omitempty"`
}

func gateCheckHandler(d Deps) http.HandlerFunc {
	if d.Store == nil || d.Policy == nil {
		return todo("gate.check")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var req gateCheckRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		if req.SessionID == "" || req.Tool == "" || req.Source == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "session_id, source, tool required")
			return
		}
		sess, err := d.Store.GetSession(r.Context(), req.SessionID)
		if err != nil {
			if errors.Is(err, storage.ErrSessionNotFound) {
				writeError(w, http.StatusNotFound, "session_not_found", req.SessionID)
				return
			}
			writeError(w, http.StatusInternalServerError, "storage_error", err.Error())
			return
		}
		active, err := d.Store.IsSessionActive(r.Context(), req.SessionID)
		if err != nil {
			log.Printf("gate.check: IsSessionActive: %v", err)
			writeError(w, http.StatusInternalServerError, "storage_error", "session state unavailable")
			return
		}
		if !active {
			writeError(w, http.StatusGone, "session_ended", req.SessionID)
			return
		}

		// Resolve the policy pinned to this session's hash; falls back to
		// live when the hash is unknown (e.g. registry not yet seeded).
		evalPolicy, result := evaluatePolicyForSession(d, sess, req.Cwd, req.Tool, req.Input)
		if evalPolicy == nil {
			writeError(w, http.StatusServiceUnavailable, "policy_unavailable", "no policy loaded")
			return
		}

		var origVerdict string
		result, _, origVerdict = applyDaemonModeOverride(result)
		guardrailTrace, guardrailRuleID := evaluateGuardrailsAfterLocalAllow(r.Context(), d, req.Source, req.Tool, req.Input, origVerdict, result)
		if guardrailTrace.FinalVerdict == "deny" {
			result.Verdict = "deny"
			result.RuleID = guardrailRuleID
			result.Reason = "blocked by external guardrail"
			result.MonitorMatch = false
			result.Nudge = ""
			origVerdict = "deny"
		}

		// Ledger entry for the evaluated call. The payload hash is over the
		// canonical request body so verifiers can re-derive it from the same
		// bytes the daemon saw. Sig is empty on this slice (session-key
		// signing lands with gate.check's own signed-envelope — deferred).
		payloadBytes, err := json.Marshal(map[string]any{
			"session_id": req.SessionID,
			"source":     req.Source,
			"tool":       req.Tool,
			"input":      req.Input,
			"verdict":    origVerdict,
			"rule_id":    result.RuleID,
			"guardrails": guardrailTrace,
		})
		if err != nil {
			log.Printf("gate.check: payload marshal: %v", err)
			writeError(w, http.StatusInternalServerError, "marshal_error", "payload serialization failed")
			return
		}
		payloadHash := sha256.Sum256(payloadBytes)
		entry, err := d.Store.AppendLedger(r.Context(), storage.AppendInput{
			TS:           time.Now().UTC(),
			Source:       req.Source,
			Tool:         req.Tool,
			ToolUseID:    "gate.check",
			Signer:       sess.Signer,
			RuleID:       result.RuleID,
			Verdict:      origVerdict,
			MonitorMatch: result.MonitorMatch,
			MatcherInput: ledgerMatcherInput(req.Input),
			PolicyTrace:  storagePolicyTrace(result.Trace),
			PayloadHash:  payloadHash[:],
			Sig:          nil,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "ledger_error", err.Error())
			return
		}
		if d.Guardrails != nil && guardrailTrace.LocalPolicyVerdict != "" {
			d.Guardrails.RecordTrace(entry.Seq, guardrailTrace)
		}

		writeJSON(w, http.StatusOK, gateCheckResponse{
			Verdict:   result.Verdict,
			RuleID:    result.RuleID,
			Reason:    result.Reason,
			LedgerSeq: entry.Seq,
			Monitor:   result.MonitorMatch,
			Nudge:     result.Nudge,
		})
	}
}

func evaluateGuardrailsAfterLocalAllow(ctx context.Context, d Deps, source, tool string, input map[string]any, localVerdict string, result policy.EvalResult) (guardrails.Trace, string) {
	if d.Guardrails == nil || result.Verdict != "allow" || localVerdict != "allow" {
		return guardrails.Trace{}, ""
	}
	trace, final := d.Guardrails.EvaluatePostPolicy(ctx, guardrails.EvaluateRequest{
		LocalPolicyVerdict: "allow",
		Source:             source,
		Tool:               tool,
		Input:              input,
	})
	if final != "deny" {
		return trace, ""
	}
	for _, stage := range trace.Stages {
		if stage.Verdict == "deny" {
			return trace, "guardrail:" + stage.ProviderID + "/" + stage.EntryID
		}
	}
	return trace, "guardrail"
}
