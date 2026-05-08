package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/openagentlock/openagentlock/control-plane/internal/policy"
	"github.com/openagentlock/openagentlock/control-plane/internal/storage"
)

type falsePositiveCaseResponse struct {
	SchemaVersion int                       `json:"schema_version"`
	CreatedAt     time.Time                 `json:"created_at"`
	PolicyHash    string                    `json:"policy_hash"`
	Event         falsePositiveEvent        `json:"event"`
	Input         map[string]string         `json:"input"`
	RawInput      map[string]string         `json:"raw_input,omitempty"`
	Redactions    []string                  `json:"redactions"`
	MatchedGate   gateView                  `json:"matched_gate"`
	PolicyTrace   []storage.PolicyTraceItem `json:"policy_trace,omitempty"`
	Audit         falsePositiveAudit        `json:"audit"`
}

type falsePositiveEvent struct {
	Seq          uint64 `json:"seq"`
	Source       string `json:"source"`
	Tool         string `json:"tool,omitempty"`
	ToolUseID    string `json:"tool_use_id"`
	Verdict      string `json:"verdict"`
	MonitorMatch bool   `json:"monitor_match,omitempty"`
	RuleID       string `json:"rule_id"`
}

type falsePositiveAudit struct {
	PayloadHash string `json:"payload_hash"`
	LeafHash    string `json:"leaf_hash"`
	PrevLeaf    string `json:"prev_leaf"`
}

type falsePositiveValidateRequest struct {
	Case            falsePositiveCaseResponse `json:"case"`
	ReplacementYAML string                    `json:"replacement_yaml"`
}

type falsePositiveValidateResponse struct {
	OK                 bool     `json:"ok"`
	Errors             []string `json:"errors,omitempty"`
	ReplacementID      string   `json:"replacement_id,omitempty"`
	ReplacementVerdict string   `json:"replacement_verdict,omitempty"`
}

type falsePositiveApplyRequest struct {
	Case            falsePositiveCaseResponse `json:"case"`
	ReplacementYAML string                    `json:"replacement_yaml"`
	Note            string                    `json:"note,omitempty"`
}

type falsePositiveApplyResponse struct {
	Hash          string `json:"hash"`
	Gates         int    `json:"gates"`
	DisabledID    string `json:"disabled_id"`
	ReplacementID string `json:"replacement_id"`
	NeedsReload   bool   `json:"needs_reload"`
}

var secretishRE = regexp.MustCompile(`(?i)(token|secret|password|passwd|api[_-]?key|authorization)=([^\s'"]+)`)

func falsePositiveCaseHandler(d Deps) http.HandlerFunc {
	if d.Store == nil || d.Policy == nil {
		return todo("false_positive.case")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		seq, err := extractFalsePositiveSeq(r.URL.Path)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		includeRaw := r.URL.Query().Get("include_raw") == "1" || r.URL.Query().Get("include_raw") == "true"
		c, status, code, err := buildFalsePositiveCase(r, d, seq, includeRaw)
		if err != nil {
			writeError(w, status, code, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, c)
	}
}

func falsePositiveValidateHandler(d Deps) http.HandlerFunc {
	if d.Policy == nil {
		return todo("false_positive.validate")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var req falsePositiveValidateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		resp := validateFalsePositiveReplacement(req.Case, req.ReplacementYAML)
		writeJSON(w, http.StatusOK, resp)
	}
}

func falsePositiveApplyHandler(d Deps) http.HandlerFunc {
	if d.Policy == nil {
		return todo("false_positive.apply")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var req falsePositiveApplyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		validation := validateFalsePositiveReplacement(req.Case, req.ReplacementYAML)
		if !validation.OK {
			writeJSON(w, http.StatusBadRequest, validation)
			return
		}
		if req.Case.PolicyHash == "" || livePolicyFor(d).Hash != req.Case.PolicyHash {
			writeError(w, http.StatusConflict, "stale_policy", "live policy hash differs from case bundle")
			return
		}
		var incoming yamlRawGate
		if err := yaml.Unmarshal([]byte(req.ReplacementYAML), &incoming); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_yaml", err.Error())
			return
		}
		if incoming.ID == req.Case.Event.RuleID {
			writeError(w, http.StatusBadRequest, "invalid_replacement", "replacement id must differ from disabled rule id")
			return
		}
		now := time.Now().UTC().Format(time.RFC3339)
		p, err := mutatePolicy(d, func(raw *yamlRawPolicy) error {
			foundOld := false
			for i := range raw.Gates {
				if raw.Gates[i].ID == req.Case.Event.RuleID {
					foundOld = true
					raw.Gates[i].Disabled = true
					raw.Gates[i].DisabledReason = "false_positive"
					raw.Gates[i].DisabledByEventSeq = req.Case.Event.Seq
					raw.Gates[i].DisabledAt = now
					raw.Gates[i].ReplacementRuleID = incoming.ID
					raw.Gates[i].FalsePositiveNote = strings.TrimSpace(req.Note)
					break
				}
			}
			if !foundOld {
				return errGateNotFound
			}
			for _, g := range raw.Gates {
				if g.ID == incoming.ID {
					return fmt.Errorf("replacement gate %q already exists", incoming.ID)
				}
			}
			raw.Gates = append(raw.Gates, incoming)
			return nil
		})
		if err != nil {
			if errors.Is(err, errGateNotFound) {
				writeError(w, http.StatusNotFound, "gate_not_found", req.Case.Event.RuleID)
				return
			}
			writeError(w, http.StatusBadRequest, "invalid_policy", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, falsePositiveApplyResponse{
			Hash:          p.Hash,
			Gates:         len(p.Gates),
			DisabledID:    req.Case.Event.RuleID,
			ReplacementID: incoming.ID,
			NeedsReload:   true,
		})
	}
}

func buildFalsePositiveCase(r *http.Request, d Deps, seq uint64, includeRaw bool) (falsePositiveCaseResponse, int, string, error) {
	entries, err := d.Store.ListLedger(r.Context())
	if err != nil {
		return falsePositiveCaseResponse{}, http.StatusInternalServerError, "storage_error", err
	}
	var entry storage.LedgerEntry
	found := false
	for _, e := range entries {
		if e.Seq == seq {
			entry = e
			found = true
			break
		}
	}
	if !found {
		return falsePositiveCaseResponse{}, http.StatusNotFound, "event_not_found", fmt.Errorf("ledger seq %d not found", seq)
	}
	if entry.RuleID == "" || entry.RuleID == "default" {
		return falsePositiveCaseResponse{}, http.StatusBadRequest, "no_matched_rule", errors.New("event has no matched rule")
	}
	if entry.Verdict != "deny" && !(entry.Verdict == "allow" && entry.MonitorMatch) {
		return falsePositiveCaseResponse{}, http.StatusBadRequest, "not_block_or_alert", errors.New("event is not a deny or monitor alert")
	}
	p := livePolicyFor(d)
	var gate *policy.Gate
	for i := range p.Gates {
		if p.Gates[i].ID == entry.RuleID {
			gate = &p.Gates[i]
			break
		}
	}
	if gate == nil {
		return falsePositiveCaseResponse{}, http.StatusNotFound, "gate_not_found", fmt.Errorf("matched gate %q not found", entry.RuleID)
	}
	input, redactions := redactInput(entry.Input)
	resp := falsePositiveCaseResponse{
		SchemaVersion: 1,
		CreatedAt:     time.Now().UTC(),
		PolicyHash:    p.Hash,
		Event: falsePositiveEvent{
			Seq:          entry.Seq,
			Source:       entry.Source,
			Tool:         entry.Tool,
			ToolUseID:    entry.ToolUseID,
			Verdict:      entry.Verdict,
			MonitorMatch: entry.MonitorMatch,
			RuleID:       entry.RuleID,
		},
		Input:       input,
		Redactions:  redactions,
		MatchedGate: gateToView(p, *gate),
		PolicyTrace: entry.PolicyTrace,
		Audit: falsePositiveAudit{
			PayloadHash: entry.PayloadHash,
			LeafHash:    entry.LeafHashHex,
			PrevLeaf:    entry.PrevLeafHex,
		},
	}
	if includeRaw {
		resp.RawInput = entry.Input
	}
	return resp, http.StatusOK, "", nil
}

func validateFalsePositiveReplacement(c falsePositiveCaseResponse, replacementYAML string) falsePositiveValidateResponse {
	var errs []string
	var incoming yamlRawGate
	if strings.TrimSpace(replacementYAML) == "" {
		return falsePositiveValidateResponse{OK: false, Errors: []string{"replacement_yaml is empty"}}
	}
	if err := yaml.Unmarshal([]byte(replacementYAML), &incoming); err != nil {
		return falsePositiveValidateResponse{OK: false, Errors: []string{"invalid yaml: " + err.Error()}}
	}
	if incoming.ID == "" {
		errs = append(errs, "replacement gate id required")
	}
	if incoming.ID == c.Event.RuleID {
		errs = append(errs, "replacement id must differ from disabled rule id")
	}
	pol, err := policyFromGateYAML(replacementYAML)
	if err != nil {
		errs = append(errs, "invalid policy: "+err.Error())
	}
	verdict := ""
	if pol != nil {
		result := pol.Evaluate(policy.EvalRequest{Tool: c.Event.Tool, Input: anyInput(c.Input)})
		verdict = result.OriginalVerdict
		if verdict == "" {
			verdict = result.Verdict
		}
		if verdict == "deny" {
			errs = append(errs, "replacement still denies the false-positive event")
		}
	}
	return falsePositiveValidateResponse{
		OK:                 len(errs) == 0,
		Errors:             errs,
		ReplacementID:      incoming.ID,
		ReplacementVerdict: verdict,
	}
}

func policyFromGateYAML(gateYAML string) (*policy.Policy, error) {
	var gate yamlRawGate
	if err := yaml.Unmarshal([]byte(gateYAML), &gate); err != nil {
		return nil, err
	}
	raw := yamlRawPolicy{
		Version: 1,
		Mode:    "enforce",
		Gates:   []yamlRawGate{gate},
	}
	out, err := yaml.Marshal(&raw)
	if err != nil {
		return nil, err
	}
	return policy.LoadBytes(out)
}

func gateToView(p *policy.Policy, g policy.Gate) gateView {
	return gateView{
		ID:              g.ID,
		Mode:            effectiveGateMode(p, g),
		Disabled:        g.Disabled,
		Source:          g.Source,
		Tool:            g.Match.Tool,
		ToolPrefix:      g.Match.ToolPrefix,
		AnyCommandRegex: regexStrings(g.Match.Regexes),
		AnyPathRegex:    regexStrings(g.Match.PathRegexes),
		AnyURLRegex:     regexStrings(g.Match.URLRegexes),
		Match:           matcherView(g.Match),
		Evaluators:      evaluatorNames(g.Evaluators()),
	}
}

func redactInput(input map[string]string) (map[string]string, []string) {
	out := make(map[string]string, len(input))
	var changed []string
	for k, v := range input {
		next := secretishRE.ReplaceAllString(v, "$1=[REDACTED]")
		if next != v {
			changed = append(changed, k)
		}
		out[k] = next
	}
	return out, changed
}

func anyInput(input map[string]string) map[string]any {
	out := make(map[string]any, len(input))
	for k, v := range input {
		out[k] = v
	}
	return out
}

func extractFalsePositiveSeq(path string) (uint64, error) {
	const prefix = "/v1/false-positives/cases/"
	if !strings.HasPrefix(path, prefix) {
		return 0, errors.New("false-positive case seq required")
	}
	rest := strings.TrimSpace(path[len(prefix):])
	if rest == "" || strings.ContainsRune(rest, '/') {
		return 0, errors.New("false-positive case seq required")
	}
	seq, err := strconv.ParseUint(rest, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid seq %q", rest)
	}
	return seq, nil
}
