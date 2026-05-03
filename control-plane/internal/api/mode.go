// Daemon-level mode override. Sits on top of policy.mode; a daemon-wide
// monitor setting forces all deny verdicts to allow at the handler
// output layer, while the ledger still records the original verdict so
// audit survives. Intended for the "big red button" toggle between
// pure-observation and full-firewall stance — separate from the
// per-rule mode knob in the policy YAML.

package api

import (
	"os"
	"strings"
	"sync/atomic"

	"github.com/openagentlock/openagentlock/control-plane/internal/policy"
)

const (
	daemonModeFirewall = "firewall"
	daemonModeMonitor  = "monitor"
)

// runtimeMode is set via PATCH /v1/mode. Empty string means "fall back to
// the AGENTLOCK_MODE env var (or firewall default)". atomic.Value holds
// a string so reads are lock-free on the hot path.
var runtimeMode atomic.Value

// daemonMode returns the effective mode. Precedence: runtime override >
// AGENTLOCK_MODE env > firewall default.
func daemonMode() string {
	if v, ok := runtimeMode.Load().(string); ok && v != "" {
		return v
	}
	v := strings.ToLower(strings.TrimSpace(os.Getenv("AGENTLOCK_MODE")))
	if v == daemonModeMonitor {
		return daemonModeMonitor
	}
	return daemonModeFirewall
}

// setRuntimeMode changes the runtime override. Empty string clears it.
// Invalid values are rejected.
func setRuntimeMode(m string) bool {
	m = strings.ToLower(strings.TrimSpace(m))
	switch m {
	case "", daemonModeFirewall, daemonModeMonitor:
		runtimeMode.Store(m)
		return true
	}
	return false
}

// applyDaemonModeOverride composes the daemon-level mode with a policy
// EvalResult. The daemon mode is the *outer* switch — the dashboard's
// big red button — and must trump the per-policy / per-gate monitor
// override the YAML can set.
//
// Three directions:
//   - daemon=monitor + verdict=deny → suppress to allow, strip nudge
//     (existing behavior, just centralised here so every hook handler
//     agrees)
//   - daemon=monitor + MonitorMatch passthrough → keep allow, strip
//     nudge (the agent is being allowed; a remediation hint would be
//     misleading)
//   - daemon=firewall + MonitorMatch + OriginalVerdict=deny → escalate
//     back to deny, KEEP the nudge so the user sees the hint that the
//     policy's monitor downgrade had stashed for this exact moment
//
// Returns the (possibly mutated) result + the daemon mode that was in
// effect, so callers can stamp the ledger consistently.
//
// origVerdict is the Verdict observed before this function ran — what
// the caller should write to the ledger to preserve the unmodified
// truth (matches existing pattern in gate.go / hooks_claude.go).
func applyDaemonModeOverride(r policy.EvalResult) (policy.EvalResult, string, string) {
	mode := daemonMode()
	origVerdict := r.Verdict
	switch mode {
	case daemonModeMonitor:
		if r.Verdict == "deny" {
			// policy.Evaluate already set OriginalVerdict for matched
			// gates, but stamp it again here so a request that arrives
			// already-deny from somewhere else (future evaluator that
			// short-circuits) still carries the truth across the
			// suppression boundary.
			r.OriginalVerdict = "deny"
			r.MonitorMatch = true
			r.Verdict = "allow"
			r.Reason = "deny suppressed by daemon monitor mode"
			// policy layer leaves Nudge populated on real denies (and on
			// monitor-downgraded denies, post-fix); clear it here because
			// the agent is being allowed to proceed and showing a hint
			// would be misleading.
			r.Nudge = ""
		} else if r.MonitorMatch {
			// Policy-level monitor downgrade carried the nudge through
			// (so daemon=firewall could re-attach on escalation). Daemon
			// is also in monitor, so the agent proceeds — clear the hint.
			r.Nudge = ""
		}
	case daemonModeFirewall:
		if r.MonitorMatch && r.OriginalVerdict == "deny" {
			r.Verdict = "deny"
			reason := "monitor match escalated by daemon firewall mode"
			if r.RuleID != "" {
				reason += " (rule " + r.RuleID + ")"
			}
			r.Reason = reason
			r.MonitorMatch = false
			origVerdict = "deny"
			// Nudge intentionally preserved: the policy layer carried it
			// through the monitor downgrade for exactly this case.
		}
	}
	return r, mode, origVerdict
}
