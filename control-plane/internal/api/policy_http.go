// Read-only policy view for the dashboard Rules tab. Write-side (add /
// update / delete gates) is a later slice — today the policy is loaded
// from YAML at startup and the daemon-level mode toggle is the only
// runtime knob. This endpoint projects the loaded policy into a UI-
// friendly shape.

package api

import (
	"fmt"
	"net/http"
	"regexp"

	"github.com/openagentlock/openagentlock/control-plane/internal/policy"
)

type gateView struct {
	ID              string   `json:"id"`
	Mode            string   `json:"mode"`
	Disabled        bool     `json:"disabled"`
	Source          string   `json:"source"`
	Tool            string   `json:"tool,omitempty"`
	ToolPrefix      string   `json:"tool_prefix,omitempty"`
	AnyCommandRegex []string `json:"any_command_regex,omitempty"`
	Evaluators      []string `json:"evaluators"`
}

func policyViewHandler(d Deps) http.HandlerFunc {
	if d.Policy == nil {
		return todo("policy.view")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		p := livePolicyFor(d)
		gates := make([]gateView, 0, len(p.Gates))
		for _, g := range p.Gates {
			gates = append(gates, gateView{
				ID:              g.ID,
				Mode:            effectiveGateMode(p, g),
				Disabled:        g.Disabled,
				Source:          g.Source,
				Tool:            g.Match.Tool,
				ToolPrefix:      g.Match.ToolPrefix,
				AnyCommandRegex: regexStrings(g.Match.Regexes),
				Evaluators:      evaluatorNames(g.Evaluators()),
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"hash":        p.Hash,
			"policy_mode": p.Mode,
			"daemon_mode": daemonMode(),
			"gates":       gates,
		})
	}
}

func effectiveGateMode(p *policy.Policy, g policy.Gate) string {
	if g.Mode != "" {
		return g.Mode
	}
	return p.Mode
}

func regexStrings(rs []*regexp.Regexp) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		if r != nil {
			out = append(out, r.String())
		}
	}
	return out
}

// evaluatorNames returns the concrete type name of each evaluator so the
// UI can show what sort of rule each gate contains (always-deny,
// allowlist, typosquat, etc).
func evaluatorNames(evs []policy.Evaluator) []string {
	out := make([]string, 0, len(evs))
	for _, e := range evs {
		out = append(out, fmt.Sprintf("%T", e))
	}
	return out
}
