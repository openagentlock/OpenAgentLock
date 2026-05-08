// Policy CRUD over HTTP. Each mutation round-trips through YAML so
// evaluator shapes we don't model explicitly in the CRUD request (e.g.
// allowlist, typosquat) survive the rebuild. Every successful mutation
// mints a new policy hash and pins it in policyRegistry.Live(); existing
// sessions keep their old pinned policy until they reload / re-attest.
//
// Persistence: if Deps.PolicyPath is set, the mutated YAML is written
// back atomically so a daemon restart picks up the change. In-memory
// only otherwise (tests, ephemeral runs).

package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/openagentlock/openagentlock/control-plane/internal/policy"
)

// policyMu serializes CRUD operations so concurrent edits don't lose
// writes. Not on the hot eval path; only acquired on mutation.
var policyMu sync.Mutex

// errGateNotFound is returned from a mutation callback when the targeted
// gate id doesn't exist. The handler maps it to a 404 and short-circuits
// the write-back — a delete on a missing gate must not rewrite disk or
// mint a new policy hash.
var errGateNotFound = errors.New("gate not found")

// yamlRawPolicy / yamlRawGate / yamlRawMatch / yamlRawEval mirror the
// schema in policy/policy.go. We keep local copies so policy_crud can
// unmarshal the raw YAML cached on *policy.Policy without exporting
// that internal schema.
type yamlRawPolicy struct {
	Version  int           `yaml:"version"`
	Mode     string        `yaml:"mode"`
	Defaults yaml.Node     `yaml:"defaults,omitempty"`
	Gates    []yamlRawGate `yaml:"gates"`
}

type yamlRawGate struct {
	ID                 string    `yaml:"id"`
	Mode               string    `yaml:"mode,omitempty"`
	Severity           string    `yaml:"severity,omitempty"`
	Disabled           bool      `yaml:"disabled,omitempty"`
	DisabledReason     string    `yaml:"disabled_reason,omitempty"`
	DisabledByEventSeq uint64    `yaml:"disabled_by_event_seq,omitempty"`
	DisabledAt         string    `yaml:"disabled_at,omitempty"`
	ReplacementRuleID  string    `yaml:"replacement_rule_id,omitempty"`
	FalsePositiveNote  string    `yaml:"false_positive_note,omitempty"`
	Match              yaml.Node `yaml:"match"`
	Evaluate           yaml.Node `yaml:"evaluate"`
}

type addGateRequest struct {
	ID              string   `json:"id"`
	Tool            string   `json:"tool"`
	ToolPrefix      string   `json:"tool_prefix,omitempty"`
	AnyCommandRegex []string `json:"any_command_regex,omitempty"`
	AnyPathRegex    []string `json:"any_path_regex,omitempty"`
	AnyURLRegex     []string `json:"any_url_regex,omitempty"`
	PathGlob        string   `json:"path_glob,omitempty"`
	Action          string   `json:"action"` // "deny" | "allow"
	Mode            string   `json:"mode,omitempty"`
}

type patchGateRequest struct {
	Disabled        *bool    `json:"disabled,omitempty"`
	AnyCommandRegex []string `json:"any_command_regex,omitempty"`
	AnyPathRegex    []string `json:"any_path_regex,omitempty"`
	AnyURLRegex     []string `json:"any_url_regex,omitempty"`
	Mode            string   `json:"mode,omitempty"`
}

func policyAddGateHandler(d Deps) http.HandlerFunc {
	if d.Policy == nil {
		return todo("policy.add_gate")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var req addGateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		if err := validateAddGate(req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		p, err := mutatePolicy(d, func(raw *yamlRawPolicy) error {
			for _, g := range raw.Gates {
				if g.ID == req.ID {
					return fmt.Errorf("gate %q already exists", req.ID)
				}
			}
			raw.Gates = append(raw.Gates, buildRawGateFromAdd(req))
			return nil
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_policy", err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"hash":         p.Hash,
			"gates":        len(p.Gates),
			"needs_reload": true,
		})
	}
}

// policyAddGateYAMLHandler accepts a complete gate block as YAML, used by
// `agentlock rules install` so a community rule with a non-trivial
// `evaluate` shape (allowlist, typosquat, ...) round-trips into the live
// policy without needing a JSON-shaped translation. The on-disk format is
// what the rule was authored in.
//
// Request body shape:
//
//	{ "yaml": "id: rogue.destructive-bash\nmatch:\n  tool: Bash\n... " }
//
// The YAML is a single gate (no leading "- "), parsed as yamlRawGate.
type addGateYAMLRequest struct {
	YAML    string `json:"yaml"`
	Replace bool   `json:"replace,omitempty"`
}

func policyAddGateYAMLHandler(d Deps) http.HandlerFunc {
	if d.Policy == nil {
		return todo("policy.add_gate_yaml")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var req addGateYAMLRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		if strings.TrimSpace(req.YAML) == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "yaml body is empty")
			return
		}
		var incoming yamlRawGate
		if err := yaml.Unmarshal([]byte(req.YAML), &incoming); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_yaml", err.Error())
			return
		}
		if incoming.ID == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "gate id required")
			return
		}
		p, err := mutatePolicy(d, func(raw *yamlRawPolicy) error {
			for i, g := range raw.Gates {
				if g.ID == incoming.ID {
					if !req.Replace {
						return fmt.Errorf("gate %q already exists (set replace=true to overwrite)", incoming.ID)
					}
					raw.Gates[i] = incoming
					return nil
				}
			}
			raw.Gates = append(raw.Gates, incoming)
			return nil
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_policy", err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"hash":         p.Hash,
			"gates":        len(p.Gates),
			"id":           incoming.ID,
			"needs_reload": true,
		})
	}
}

func policyPatchGateHandler(d Deps) http.HandlerFunc {
	if d.Policy == nil {
		return todo("policy.patch_gate")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		id := extractGateID(r.URL.Path)
		if id == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "gate id required")
			return
		}
		var req patchGateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		found := false
		p, err := mutatePolicy(d, func(raw *yamlRawPolicy) error {
			for i := range raw.Gates {
				if raw.Gates[i].ID != id {
					continue
				}
				found = true
				if req.Disabled != nil {
					raw.Gates[i].Disabled = *req.Disabled
				}
				if req.Mode != "" {
					raw.Gates[i].Mode = req.Mode
				}
				if req.AnyCommandRegex != nil {
					rewriteMatchRegexes(&raw.Gates[i].Match, "any_command_regex", req.AnyCommandRegex)
				}
				if req.AnyPathRegex != nil {
					rewriteMatchRegexes(&raw.Gates[i].Match, "any_path_regex", req.AnyPathRegex)
				}
				if req.AnyURLRegex != nil {
					rewriteMatchRegexes(&raw.Gates[i].Match, "any_url_regex", req.AnyURLRegex)
				}
				return nil
			}
			return errors.New("gate not found")
		})
		if !found {
			writeError(w, http.StatusNotFound, "gate_not_found", id)
			return
		}
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_policy", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"hash":         p.Hash,
			"gates":        len(p.Gates),
			"needs_reload": true,
		})
	}
}

func policyDeleteGateHandler(d Deps) http.HandlerFunc {
	if d.Policy == nil {
		return todo("policy.delete_gate")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		id := extractGateID(r.URL.Path)
		if id == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "gate id required")
			return
		}
		p, err := mutatePolicy(d, func(raw *yamlRawPolicy) error {
			out := make([]yamlRawGate, 0, len(raw.Gates))
			found := false
			for _, g := range raw.Gates {
				if g.ID == id {
					found = true
					continue
				}
				out = append(out, g)
			}
			if !found {
				return errGateNotFound
			}
			raw.Gates = out
			return nil
		})
		if err != nil {
			if errors.Is(err, errGateNotFound) {
				writeError(w, http.StatusNotFound, "gate_not_found", id)
				return
			}
			writeError(w, http.StatusBadRequest, "invalid_policy", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"hash":         p.Hash,
			"gates":        len(p.Gates),
			"needs_reload": true,
		})
	}
}

// mutatePolicy takes a mutation function over the raw YAML form, rebuilds
// the policy, and promotes it to live. Returns the new policy on success.
// Persists back to d.PolicyPath when set.
func mutatePolicy(d Deps, mut func(*yamlRawPolicy) error) (*policy.Policy, error) {
	policyMu.Lock()
	defer policyMu.Unlock()

	src := livePolicyFor(d)
	if src == nil || len(src.RawYAML) == 0 {
		return nil, errors.New("no editable policy loaded")
	}
	var raw yamlRawPolicy
	if err := yaml.Unmarshal(src.RawYAML, &raw); err != nil {
		return nil, fmt.Errorf("parse current policy: %w", err)
	}
	if err := mut(&raw); err != nil {
		return nil, err
	}
	out, err := yaml.Marshal(&raw)
	if err != nil {
		return nil, fmt.Errorf("marshal policy: %w", err)
	}
	p, err := policy.LoadBytes(out)
	if err != nil {
		return nil, fmt.Errorf("rebuild policy: %w", err)
	}
	// Persist to disk FIRST so a failed write never leaves the live
	// registry ahead of the on-disk YAML. Only swap after durable.
	if d.PolicyPath != "" {
		if err := policy.AtomicWriteFile(d.PolicyPath, out, 0o644); err != nil {
			return nil, fmt.Errorf("persist policy: %w", err)
		}
	}
	livePolicyRegistry.Swap(p)
	return p, nil
}

func validateAddGate(req addGateRequest) error {
	if req.ID == "" {
		return errors.New("id required")
	}
	if req.Tool == "" && req.ToolPrefix == "" {
		return errors.New("tool or tool_prefix required")
	}
	switch req.Action {
	case "allow", "deny":
	default:
		return fmt.Errorf("action must be allow|deny, got %q", req.Action)
	}
	return nil
}

func buildRawGateFromAdd(req addGateRequest) yamlRawGate {
	var match yaml.Node
	match.Kind = yaml.MappingNode
	if req.Tool != "" {
		appendYAMLMapEntry(&match, "tool", req.Tool)
	}
	if req.ToolPrefix != "" {
		appendYAMLMapEntry(&match, "tool_prefix", req.ToolPrefix)
	}
	if req.PathGlob != "" {
		appendYAMLMapEntry(&match, "path_glob", req.PathGlob)
	}
	if len(req.AnyCommandRegex) > 0 {
		appendYAMLMapSeq(&match, "any_command_regex", req.AnyCommandRegex)
	}
	if len(req.AnyPathRegex) > 0 {
		appendYAMLMapSeq(&match, "any_path_regex", req.AnyPathRegex)
	}
	if len(req.AnyURLRegex) > 0 {
		appendYAMLMapSeq(&match, "any_url_regex", req.AnyURLRegex)
	}

	var evaluate yaml.Node
	evaluate.Kind = yaml.SequenceNode
	oneEval := yamlNodeMap(map[string]string{
		"kind":   "always",
		"action": req.Action,
	})
	evaluate.Content = append(evaluate.Content, oneEval)

	return yamlRawGate{
		ID:       req.ID,
		Mode:     req.Mode,
		Match:    match,
		Evaluate: evaluate,
	}
}

// rewriteMatchRegexes replaces one regex list field inside the match map
// in-place, preserving other keys (tool, path_glob, etc.).
func rewriteMatchRegexes(match *yaml.Node, key string, regexes []string) {
	if match.Kind != yaml.MappingNode {
		return
	}
	// yaml.Node mapping: Content[0]=key, Content[1]=value, ...
	idx := -1
	for i := 0; i+1 < len(match.Content); i += 2 {
		if match.Content[i].Value == key {
			idx = i + 1
			break
		}
	}
	seq := yamlSeqNode(regexes)
	if idx == -1 {
		keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: key}
		match.Content = append(match.Content, keyNode, seq)
	} else {
		match.Content[idx] = seq
	}
}

func yamlSeqNode(vals []string) *yaml.Node {
	n := &yaml.Node{Kind: yaml.SequenceNode}
	for _, v := range vals {
		n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: v})
	}
	return n
}

func yamlNodeMap(kv map[string]string) *yaml.Node {
	n := &yaml.Node{Kind: yaml.MappingNode}
	for k, v := range kv {
		n.Content = append(n.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: k},
			&yaml.Node{Kind: yaml.ScalarNode, Value: v},
		)
	}
	return n
}

func appendYAMLMapEntry(m *yaml.Node, k, v string) {
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Value: k},
		&yaml.Node{Kind: yaml.ScalarNode, Value: v},
	)
}

func appendYAMLMapSeq(m *yaml.Node, k string, vs []string) {
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Value: k},
		yamlSeqNode(vs),
	)
}

// extractGateID returns the <id> portion of /v1/policy/gates/<id>. It
// rejects anything containing a slash so a nested path like
// /v1/policy/gates/foo/bar can't be interpreted as gate id "foo/bar".
func extractGateID(path string) string {
	const prefix = "/v1/policy/gates/"
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	rest := strings.TrimSpace(path[len(prefix):])
	if rest == "" || strings.ContainsRune(rest, '/') {
		return ""
	}
	return rest
}
