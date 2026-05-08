package api

import (
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/openagentlock/openagentlock/control-plane/internal/policy"
	"github.com/openagentlock/openagentlock/control-plane/internal/storage"
	"gopkg.in/yaml.v3"
)

const groupPolicyFileName = "group-policy.yaml"

type groupPolicyFile struct {
	Version int                     `yaml:"version"`
	Groups  map[string]groupSpec    `yaml:"groups"`
	Users   map[string]personalSpec `yaml:"users"`
}

type groupSpec struct {
	Inherits []string         `yaml:"inherits"`
	Gates    []map[string]any `yaml:"gates"`
}

type personalSpec struct {
	Groups []string         `yaml:"groups"`
	Gates  []map[string]any `yaml:"gates"`
}

type policyDoc struct {
	Version int              `yaml:"version"`
	Mode    string           `yaml:"mode,omitempty"`
	Gates   []map[string]any `yaml:"gates"`
}

func evaluatePolicyForSession(d Deps, sess storage.Session, cwd, tool string, input map[string]any) (*policy.Policy, policy.EvalResult) {
	base := resolvePolicyForCwd(d, sess.PolicyHash, cwd)
	if base == nil {
		return nil, policy.EvalResult{}
	}
	layers := groupPolicyLayers(d, sess)
	result := policy.EvaluateLayered(base, layers, policy.EvalRequest{Tool: tool, Input: input})
	return base, result
}

func groupPolicyLayers(d Deps, sess storage.Session) []policy.Layer {
	if d.AgentlockHome == "" {
		return nil
	}
	path := filepath.Join(d.AgentlockHome, groupPolicyFileName)
	bundle, err := loadGroupPolicyFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		log.Printf("group policy: load %s: %v", path, err)
		return nil
	}
	groups := append([]string(nil), sess.Groups...)
	if u, ok := bundle.Users[sess.UserID]; ok {
		groups = append(groups, u.Groups...)
	}
	groups = dedupeStrings(groups)
	ordered := expandGroupOrder(bundle.Groups, groups)
	layers := make([]policy.Layer, 0, len(ordered)+1)
	for _, name := range ordered {
		spec := bundle.Groups[name]
		p := compileLayerPolicy("group:"+name, spec.Gates)
		if p != nil {
			layers = append(layers, policy.Layer{Name: "group:" + name, Policy: p})
		}
	}
	if u, ok := bundle.Users[sess.UserID]; ok && len(u.Gates) > 0 {
		if p := compileLayerPolicy("user:"+sess.UserID, u.Gates); p != nil {
			layers = append(layers, policy.Layer{Name: "user:" + sess.UserID, Policy: p})
		}
	}
	return layers
}

func loadGroupPolicyFile(path string) (*groupPolicyFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out groupPolicyFile
	if err := yaml.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	if out.Groups == nil {
		out.Groups = map[string]groupSpec{}
	}
	if out.Users == nil {
		out.Users = map[string]personalSpec{}
	}
	return &out, nil
}

func compileLayerPolicy(source string, gates []map[string]any) *policy.Policy {
	if len(gates) == 0 {
		return nil
	}
	copied := make([]map[string]any, 0, len(gates))
	for _, g := range gates {
		next := map[string]any{}
		for k, v := range g {
			next[k] = v
		}
		if _, ok := next["source"]; !ok {
			next["source"] = source
		}
		copied = append(copied, next)
	}
	data, err := yaml.Marshal(policyDoc{Version: 1, Mode: "enforce", Gates: copied})
	if err != nil {
		log.Printf("group policy: marshal layer %s gates=%d: %v", source, len(copied), err)
		return nil
	}
	p, err := policy.LoadBytes(data)
	if err != nil {
		log.Printf("group policy: compile layer %s gates=%d: %v", source, len(copied), err)
		return nil
	}
	return p
}

func expandGroupOrder(groups map[string]groupSpec, roots []string) []string {
	var out []string
	visiting := map[string]bool{}
	visited := map[string]bool{}
	var visit func(string)
	visit = func(name string) {
		name = strings.TrimSpace(name)
		if name == "" || visited[name] || visiting[name] {
			return
		}
		spec, ok := groups[name]
		if !ok {
			return
		}
		visiting[name] = true
		for _, parent := range spec.Inherits {
			visit(parent)
		}
		visiting[name] = false
		visited[name] = true
		out = append(out, name)
	}
	for _, root := range roots {
		visit(root)
	}
	return out
}

func dedupeStrings(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func storagePolicyTrace(in []policy.TraceItem) []storage.PolicyTraceItem {
	out := make([]storage.PolicyTraceItem, 0, len(in))
	for _, item := range in {
		out = append(out, storage.PolicyTraceItem{
			Layer:      item.Layer,
			Source:     item.Source,
			RuleID:     item.RuleID,
			Verdict:    item.Verdict,
			Precedence: item.Precedence,
			Priority:   item.Priority,
		})
	}
	return out
}
