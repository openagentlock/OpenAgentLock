// Cursor IDE hook endpoints. Cursor's native config carries
// `conversation_id` (the daemon's session_id) and `generation_id` —
// neither matches Claude's or Codex's field names, so it gets its own
// pair of decode structs. The wire response is the shared
// claudeHookOutput envelope; the agentlock shim binary translates that
// into Cursor's `{permission, agent_message?}` shape on the way back.
//
// Cursor exposes BOTH a generic `preToolUse` event AND a dedicated
// `beforeMCPExecution` event for MCP tool calls. We wire both because
// `preToolUse` matchers are not guaranteed to fire for MCP calls in
// every Cursor build, and we don't want a coverage gap. To avoid
// double-counting, both endpoints share an in-memory dedupe cache
// keyed on `tool_use_id`: the first event evaluates policy + appends
// to the ledger; the second returns the cached verdict without a
// second ledger entry. Same dedupe between `postToolUse` and
// `afterMCPExecution` for completeness records.
//
// The cache is process-local. Restarting the daemon resets it. That's
// fine — Cursor only emits both events in a single millisecond window
// per tool call, so a daemon restart in between is essentially never.

package api

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/openagentlock/openagentlock/control-plane/internal/policy"
	"github.com/openagentlock/openagentlock/control-plane/internal/storage"
)

const cursorDedupeTTL = 5 * time.Minute

type cursorDedupeKind int

const (
	cursorDedupePre cursorDedupeKind = iota
	cursorDedupePost
)

type cursorDedupeEntry struct {
	expiresAt time.Time
	kind      cursorDedupeKind
	// preResponse caches the full PreToolUse / BeforeMCPExecution envelope
	// so the second event in the pair returns byte-identical bytes.
	preResponse claudeHookOutput
}

type cursorDedupeCache struct {
	mu      sync.Mutex
	entries map[string]cursorDedupeEntry
}

func newCursorDedupeCache() *cursorDedupeCache {
	return &cursorDedupeCache{entries: map[string]cursorDedupeEntry{}}
}

// lookup returns the cached entry for (key, kind) when it exists and
// hasn't expired. The boolean is true on a hit.
func (c *cursorDedupeCache) lookup(key string, kind cursorDedupeKind) (cursorDedupeEntry, bool) {
	if key == "" {
		return cursorDedupeEntry{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepLocked()
	e, ok := c.entries[c.cacheKey(key, kind)]
	if !ok {
		return cursorDedupeEntry{}, false
	}
	if time.Now().After(e.expiresAt) {
		delete(c.entries, c.cacheKey(key, kind))
		return cursorDedupeEntry{}, false
	}
	return e, true
}

func (c *cursorDedupeCache) put(key string, kind cursorDedupeKind, e cursorDedupeEntry) {
	if key == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e.expiresAt = time.Now().Add(cursorDedupeTTL)
	e.kind = kind
	c.entries[c.cacheKey(key, kind)] = e
}

func (c *cursorDedupeCache) cacheKey(key string, kind cursorDedupeKind) string {
	switch kind {
	case cursorDedupePre:
		return "pre:" + key
	case cursorDedupePost:
		return "post:" + key
	}
	return key
}

// sweepLocked drops expired entries. Cheap because the map is bounded
// by the number of active tool calls in the last cursorDedupeTTL.
func (c *cursorDedupeCache) sweepLocked() {
	now := time.Now()
	for k, e := range c.entries {
		if now.After(e.expiresAt) {
			delete(c.entries, k)
		}
	}
}

// Process-local. Tests that need a clean cache call cursorResetDedupe.
var cursorDedupe = newCursorDedupeCache()

// cursorResetDedupe is intended for tests; it clears the cache so a
// previous test's tool_use_id can't bleed into the next.
func cursorResetDedupe() {
	cursorDedupe.mu.Lock()
	defer cursorDedupe.mu.Unlock()
	cursorDedupe.entries = map[string]cursorDedupeEntry{}
}

type cursorPreToolInput struct {
	ConversationID string         `json:"conversation_id"`
	GenerationID   string         `json:"generation_id"`
	HookEventName  string         `json:"hook_event_name"`
	CursorVersion  string         `json:"cursor_version"`
	Model          string         `json:"model"`
	WorkspaceRoots []string       `json:"workspace_roots"`
	ToolName       string         `json:"tool_name"`
	ToolInput      map[string]any `json:"tool_input"`
	ToolUseID      string         `json:"tool_use_id"`
	Cwd            string         `json:"cwd"`
	// Populated only on beforeMCPExecution / afterMCPExecution.
	MCPServerName string `json:"mcp_server_name,omitempty"`
	MCPToolName   string `json:"mcp_tool_name,omitempty"`
}

type cursorPostToolInput struct {
	ConversationID string         `json:"conversation_id"`
	GenerationID   string         `json:"generation_id"`
	HookEventName  string         `json:"hook_event_name"`
	ToolName       string         `json:"tool_name"`
	ToolInput      map[string]any `json:"tool_input"`
	ToolUseID      string         `json:"tool_use_id"`
	// Cursor hook payloads don't carry a reliable top-level success
	// boolean; we derive it from tool_response so the ledger reflects
	// what the tool actually did. See hooks_common.go.
	ToolResponse  any    `json:"tool_response"`
	MCPServerName string `json:"mcp_server_name,omitempty"`
	MCPToolName   string `json:"mcp_tool_name,omitempty"`
}

type cursorSessionStartInput struct {
	ConversationID string   `json:"conversation_id"`
	HookEventName  string   `json:"hook_event_name"`
	CursorVersion  string   `json:"cursor_version"`
	Model          string   `json:"model"`
	WorkspaceRoots []string `json:"workspace_roots"`
	Cwd            string   `json:"cwd"`
}

type cursorStopInput struct {
	ConversationID string `json:"conversation_id"`
	HookEventName  string `json:"hook_event_name"`
}

func cursorPreToolUseHandler(d Deps) http.HandlerFunc {
	return cursorGateHandler(d, "PreToolUse", cursorDedupePre)
}

func cursorBeforeMCPHandler(d Deps) http.HandlerFunc {
	return cursorGateHandler(d, "BeforeMCPExecution", cursorDedupePre)
}

// cursorGateHandler is shared by preToolUse and beforeMCPExecution.
// Both events are gates: they evaluate policy, append a ledger entry,
// and return the verdict in the shared claudeHookOutput envelope. The
// dedupe cache makes the second event in a (preToolUse, beforeMCP)
// pair a no-op that returns the cached verdict.
func cursorGateHandler(d Deps, eventName string, kind cursorDedupeKind) http.HandlerFunc {
	if d.Store == nil {
		return todo("hooks.cursor." + eventName)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var in cursorPreToolInput
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		if in.ConversationID == "" || in.ToolName == "" {
			writeError(w, http.StatusBadRequest, "invalid_request",
				"conversation_id, tool_name required")
			return
		}

		if cached, ok := cursorDedupe.lookup(in.ToolUseID, cursorDedupePre); ok {
			// Second event in the pair — return the cached verdict.
			// Re-emit with the *current* event name so the shim can map
			// it cleanly back into Cursor's expected output shape.
			out := cached.preResponse
			out.HookSpecificOutput.HookEventName = eventName
			writeJSON(w, http.StatusOK, out)
			return
		}

		sess, err := ensureCursorSession(r, d, in.ConversationID)
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
			toolUseID = "cursor.pre-tool-use"
		}

		payloadBytes, err := json.Marshal(map[string]any{
			"session_id":      in.ConversationID,
			"source":          "cursor",
			"tool":            in.ToolName,
			"input":           in.ToolInput,
			"generation_id":   in.GenerationID,
			"verdict":         origVerdict,
			"rule_id":         result.RuleID,
			"daemon_mode":     mode,
			"monitor_match":   monitorMatch,
			"mcp_server_name": in.MCPServerName,
			"mcp_tool_name":   in.MCPToolName,
		})
		if err != nil {
			log.Printf("cursor %s: marshal: %v", eventName, err)
			writeError(w, http.StatusInternalServerError, "marshal_error", err.Error())
			return
		}
		payloadHash := sha256.Sum256(payloadBytes)
		if _, err := d.Store.AppendLedger(r.Context(), storage.AppendInput{
			TS:           time.Now().UTC(),
			Source:       "cursor",
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

		// On deny + nudge, append the hint into the reason. The cached
		// response below preserves the concatenated form so the paired
		// MCP/preToolUse event short-circuits with the same text.
		reason := denyReasonWithNudge(result)
		out := claudeHookOutput{
			Continue: result.Verdict == "allow",
			HookSpecificOutput: claudeHookSpecifics{
				HookEventName:            eventName,
				PermissionDecision:       result.Verdict,
				PermissionDecisionReason: reason,
			},
		}
		if result.Verdict == "deny" {
			out.StopReason = reason
		}

		// Cache the response keyed on tool_use_id so the paired event
		// (whichever one fires second) doesn't re-evaluate or re-append.
		cursorDedupe.put(in.ToolUseID, cursorDedupePre, cursorDedupeEntry{
			preResponse: out,
		})

		writeJSON(w, http.StatusOK, out)
	}
}

// cursorPostToolUseHandler / cursorAfterMCPHandler are observability,
// not gates. Each pairs with the matching pre-event and only the first
// of the pair hits the ledger.
func cursorPostToolUseHandler(d Deps) http.HandlerFunc {
	return cursorOutcomeHandler(d, "PostToolUse")
}

func cursorAfterMCPHandler(d Deps) http.HandlerFunc {
	return cursorOutcomeHandler(d, "AfterMCPExecution")
}

func cursorOutcomeHandler(d Deps, eventName string) http.HandlerFunc {
	if d.Store == nil {
		return todo("hooks.cursor." + eventName)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var in cursorPostToolInput
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		if in.ConversationID == "" || in.ToolName == "" {
			writeError(w, http.StatusBadRequest, "invalid_request",
				"conversation_id, tool_name required")
			return
		}

		if _, ok := cursorDedupe.lookup(in.ToolUseID, cursorDedupePost); ok {
			// Second outcome event — already recorded by the first.
			writeJSON(w, http.StatusOK, map[string]any{"continue": true})
			return
		}

		sess, err := ensureCursorSession(r, d, in.ConversationID)
		if err != nil {
			log.Printf("cursor %s: ensureCursorSession: %v", eventName, err)
			writeError(w, http.StatusInternalServerError, "session_error", "session create failed")
			return
		}

		respSize, success := summarizeToolResponse(in.ToolResponse)

		toolUseID := in.ToolUseID
		if toolUseID == "" {
			toolUseID = "cursor.post-tool-use"
		}
		verdict := "complete"
		if !success {
			verdict = "failure"
		}

		payloadBytes, err := json.Marshal(map[string]any{
			"session_id":      in.ConversationID,
			"source":          "cursor",
			"tool":            in.ToolName,
			"tool_use_id":     toolUseID,
			"generation_id":   in.GenerationID,
			"response_size":   respSize,
			"success":         success,
			"mcp_server_name": in.MCPServerName,
			"mcp_tool_name":   in.MCPToolName,
		})
		if err != nil {
			log.Printf("cursor %s: marshal: %v", eventName, err)
			writeError(w, http.StatusInternalServerError, "marshal_error", "payload hash failed")
			return
		}
		payloadHash := sha256.Sum256(payloadBytes)
		if _, err := d.Store.AppendLedger(r.Context(), storage.AppendInput{
			TS:          time.Now().UTC(),
			Source:      "cursor",
			ToolUseID:   toolUseID,
			Tool:        in.ToolName,
			Signer:      sess.Signer,
			Verdict:     verdict,
			PayloadHash: payloadHash[:],
		}); err != nil {
			log.Printf("cursor %s: AppendLedger: %v", eventName, err)
			writeError(w, http.StatusInternalServerError, "ledger_error", "ledger append failed")
			return
		}

		cursorDedupe.put(in.ToolUseID, cursorDedupePost, cursorDedupeEntry{})
		writeJSON(w, http.StatusOK, map[string]any{"continue": true})
	}
}

func cursorSessionStartHandler(d Deps) http.HandlerFunc {
	if d.Store == nil {
		return todo("hooks.cursor.session-start")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var in cursorSessionStartInput
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		if in.ConversationID == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "conversation_id required")
			return
		}

		sess, err := ensureCursorSession(r, d, in.ConversationID)
		if err != nil {
			log.Printf("cursor session-start: ensureCursorSession: %v", err)
			writeError(w, http.StatusInternalServerError, "session_error", "session create failed")
			return
		}

		payloadBytes, err := json.Marshal(map[string]any{
			"session_id":      in.ConversationID,
			"source":          "cursor",
			"cwd":             in.Cwd,
			"workspace_roots": in.WorkspaceRoots,
			"cursor_version":  in.CursorVersion,
			"model":           in.Model,
		})
		if err != nil {
			log.Printf("cursor session-start: marshal: %v", err)
			writeError(w, http.StatusInternalServerError, "marshal_error", "payload hash failed")
			return
		}
		payloadHash := sha256.Sum256(payloadBytes)
		if _, err := d.Store.AppendLedger(r.Context(), storage.AppendInput{
			TS:          time.Now().UTC(),
			Source:      "cursor",
			ToolUseID:   "cursor.session-start",
			Signer:      sess.Signer,
			PayloadHash: payloadHash[:],
		}); err != nil {
			log.Printf("cursor session-start: AppendLedger: %v", err)
			writeError(w, http.StatusInternalServerError, "ledger_error", "ledger append failed")
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{"continue": true})
	}
}

func cursorStopHandler(d Deps) http.HandlerFunc {
	if d.Store == nil {
		return todo("hooks.cursor.stop")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var in cursorStopInput
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		if in.ConversationID == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "conversation_id required")
			return
		}
		if _, err := d.Store.GetSession(r.Context(), in.ConversationID); err == nil {
			if err := d.Store.EndSession(r.Context(), in.ConversationID); err != nil && !errors.Is(err, storage.ErrSessionEnded) {
				log.Printf("cursor stop: EndSession: %v", err)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"continue": true})
	}
}

// cursorBeforeShellExecInput captures Cursor 2.x's `beforeShellExecution`
// payload, which is shaped DIFFERENTLY from preToolUse: command lives
// at the top level (no tool_input wrapper), there is no tool_name, and
// no tool_use_id. The harness fires this *after* preToolUse for any
// shell call — so by the time it lands here, preToolUse has already
// evaluated policy and ledger-recorded the verdict.
//
// For us, beforeShellExecution is therefore informational. We
// re-evaluate against policy (with a synthetic tool_name: "Shell" so
// shell-only rules still trigger), echo the verdict so Cursor can
// short-circuit on deny without consulting the original preToolUse
// response, and skip the ledger append to avoid double-counting.
type cursorBeforeShellExecInput struct {
	ConversationID string `json:"conversation_id"`
	GenerationID   string `json:"generation_id"`
	HookEventName  string `json:"hook_event_name"`
	Command        string `json:"command"`
	Cwd            string `json:"cwd"`
	Sandbox        bool   `json:"sandbox"`
	CursorVersion  string `json:"cursor_version"`
}

func cursorBeforeShellHandler(d Deps) http.HandlerFunc {
	if d.Store == nil {
		return todo("hooks.cursor.before-shell-execution")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var in cursorBeforeShellExecInput
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		if in.ConversationID == "" {
			writeError(w, http.StatusBadRequest, "invalid_request",
				"conversation_id required")
			return
		}

		sess, err := ensureCursorSession(r, d, in.ConversationID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "session_error", err.Error())
			return
		}

		evalPolicy := resolvePolicy(d, sess.PolicyHash)
		if evalPolicy == nil {
			// No policy → can't evaluate, fail-open. preToolUse already
			// landed (or also failed-open), so this is a safe default.
			writeJSON(w, http.StatusOK, map[string]any{"continue": true})
			return
		}

		result := evalPolicy.Evaluate(policy.EvalRequest{
			Tool:  "Shell",
			Input: map[string]any{"command": in.Command},
		})

		result, _, _ = applyDaemonModeOverride(result)

		// No ledger append — preToolUse owns the audit trail for this
		// tool call. We're just echoing the verdict in Cursor's expected
		// envelope so it can fail-closed at the shell-execution stage.
		// Same nudge concat as the gate handler for parity.
		reason := denyReasonWithNudge(result)
		out := claudeHookOutput{
			Continue: result.Verdict == "allow",
			HookSpecificOutput: claudeHookSpecifics{
				HookEventName:            "BeforeShellExecution",
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

func ensureCursorSession(r *http.Request, d Deps, id string) (storage.Session, error) {
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
		Harness:       "cursor",
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
		"source":     "cursor",
		"reason":     "auto-created on first hook traffic",
	})
	payloadHash := sha256.Sum256(payloadBytes)
	if _, err := d.Store.AppendLedger(r.Context(), storage.AppendInput{
		TS:          now,
		Source:      "cursor",
		ToolUseID:   "session.auto-create",
		Signer:      "none",
		PayloadHash: payloadHash[:],
	}); err != nil {
		log.Printf("cursor auto-session ledger: %v", err)
	}
	return newSess, nil
}
