// Claude Desktop hook endpoints. Claude Desktop has no PreToolUse
// callback upstream (see anthropics/claude-code#45514), so these
// endpoints are NOT called by Claude Desktop directly. They're called
// by `agentlock mcp-proxy`, which sits between Claude Desktop and each
// user-installed MCP server, intercepts every JSON-RPC tools/call, and
// turns it into one of these requests.
//
// Wire shape mirrors hooks_claude.go on purpose — same input contract,
// same claudeHookOutput response, same ledger discipline — so existing
// policy gates and dashboards work uniformly across Claude Code and
// Claude Desktop. The only thing that changes is the `source` tag in
// the ledger ("claude-desktop") and the toolUseID prefix.

package api

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/openagentlock/openagentlock/control-plane/internal/storage"
)

// ensureClaudeDesktopSession is the desktop-tagged variant of
// ensureClaudeSession. Auto-creates an unattested session on first hit,
// stamping Harness="claude-desktop" so dashboards distinguish desktop
// proxy traffic from CLI traffic. Otherwise identical behavior.
func ensureClaudeDesktopSession(r *http.Request, d Deps, id string) (storage.Session, error) {
	sess, err := d.Store.GetSession(r.Context(), id)
	if err == nil {
		return refreshUnattestedPolicyHash(d, sess), nil
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
		Harness:       "claude-desktop",
	}
	if err := d.Store.CreateSession(r.Context(), newSess); err != nil {
		if errors.Is(err, storage.ErrSessionExists) {
			existing, getErr := d.Store.GetSession(r.Context(), id)
			if getErr != nil {
				return storage.Session{}, getErr
			}
			return refreshUnattestedPolicyHash(d, existing), nil
		}
		return storage.Session{}, err
	}
	return newSess, nil
}

// refreshUnattestedPolicyHash re-pins an unattested session's policy
// hash to whatever the live policy is right now. Without this, a
// long-lived auto-created session (the proxy's stable
// "claude-desktop-<server>" id, the CLI's installed Claude Code
// session) keeps evaluating against whatever policy snapshot was
// pinned at first-hit time — adding a deny gate later would not fire
// for that session until daemon restart. Mutation is in-memory only;
// the stored row keeps its original hash for audit. Attested sessions
// (signer != "none") are NOT touched — their signature committed to
// a specific policy hash and that pin is the entire point.
func refreshUnattestedPolicyHash(d Deps, sess storage.Session) storage.Session {
	if sess.Signer != "none" {
		return sess
	}
	live := livePolicyFor(d)
	if live == nil || live.Hash == sess.PolicyHash {
		return sess
	}
	sess.PolicyHash = live.Hash
	return sess
}

// claudeDesktopPreToolUseHandler runs the same gate-check + ledger flow
// as claudePreToolUseHandler, with source="claude-desktop". The proxy
// reads the response and either forwards the JSON-RPC tools/call to the
// real MCP server (allow) or synthesizes an MCP error reply (deny).
func claudeDesktopPreToolUseHandler(d Deps) http.HandlerFunc {
	if d.Store == nil {
		return todo("hooks.claude-desktop.pre-tool-use")
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
		in.ToolInput = normalizeMCPHTTPURLInput(in.ToolName, in.ToolInput)

		sess, err := ensureClaudeDesktopSession(r, d, in.SessionID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "session_error", err.Error())
			return
		}

		evalPolicy, result := evaluatePolicyForSession(d, sess, in.Cwd, in.ToolName, in.ToolInput)
		if evalPolicy == nil {
			writeError(w, http.StatusServiceUnavailable, "policy_unavailable", "no policy loaded")
			return
		}

		var origVerdict, mode string
		result, mode, origVerdict = applyDaemonModeOverride(result)
		monitorMatch := result.MonitorMatch

		toolUseID := in.ToolUseID
		if toolUseID == "" {
			toolUseID = "claude-desktop.pre-tool-use"
		}

		payloadBytes, err := json.Marshal(map[string]any{
			"session_id":    in.SessionID,
			"source":        "claude-desktop",
			"tool":          in.ToolName,
			"input":         in.ToolInput,
			"verdict":       origVerdict,
			"rule_id":       result.RuleID,
			"daemon_mode":   mode,
			"monitor_match": monitorMatch,
		})
		if err != nil {
			log.Printf("claude-desktop pre-tool-use: marshal: %v", err)
			writeError(w, http.StatusInternalServerError, "marshal_error", err.Error())
			return
		}
		payloadHash := sha256.Sum256(payloadBytes)
		if _, err := d.Store.AppendLedger(r.Context(), storage.AppendInput{
			TS:           time.Now().UTC(),
			Source:       "claude-desktop",
			Tool:         in.ToolName,
			ToolUseID:    toolUseID,
			Signer:       sess.Signer,
			RuleID:       result.RuleID,
			Verdict:      origVerdict,
			MonitorMatch: monitorMatch,
			MatcherInput: ledgerMatcherInput(in.ToolInput),
			PolicyTrace:  storagePolicyTrace(result.Trace),
			PayloadHash:  payloadHash[:],
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "ledger_error", err.Error())
			return
		}

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

// claudeDesktopPostToolUseHandler records completion outcomes from the
// proxy. Mirrors claudePostToolUseHandler with source="claude-desktop".
func claudeDesktopPostToolUseHandler(d Deps) http.HandlerFunc {
	if d.Store == nil {
		return todo("hooks.claude-desktop.post-tool-use")
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

		sess, err := ensureClaudeDesktopSession(r, d, in.SessionID)
		if err != nil {
			log.Printf("claude-desktop post-tool-use: session: %v", err)
			writeError(w, http.StatusInternalServerError, "session_error", "session create failed")
			return
		}

		respSize, success := summarizeToolResponse(in.ToolResponse)

		toolUseID := in.ToolUseID
		if toolUseID == "" {
			toolUseID = "claude-desktop.post-tool-use"
		}
		verdict := "complete"
		if !success {
			verdict = "failure"
		}

		payloadBytes, err := json.Marshal(map[string]any{
			"session_id":    in.SessionID,
			"source":        "claude-desktop",
			"tool":          in.ToolName,
			"tool_use_id":   toolUseID,
			"response_size": respSize,
			"success":       success,
		})
		if err != nil {
			log.Printf("claude-desktop post-tool-use: marshal: %v", err)
			writeError(w, http.StatusInternalServerError, "marshal_error", "payload hash failed")
			return
		}
		payloadHash := sha256.Sum256(payloadBytes)
		if _, err := d.Store.AppendLedger(r.Context(), storage.AppendInput{
			TS:          time.Now().UTC(),
			Source:      "claude-desktop",
			ToolUseID:   toolUseID,
			Tool:        in.ToolName,
			Signer:      sess.Signer,
			Verdict:     verdict,
			PayloadHash: payloadHash[:],
		}); err != nil {
			log.Printf("claude-desktop post-tool-use: ledger: %v", err)
			writeError(w, http.StatusInternalServerError, "ledger_error", "ledger append failed")
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{"continue": true})
	}
}
