package api

import (
	"testing"

	"github.com/openagentlock/openagentlock/control-plane/internal/policy"
)

// applyDaemonModeOverride is the API-layer composition point that owns
// when to surface a nudge. The policy layer carries Nudge through a
// monitor downgrade (so daemon=firewall can re-escalate with the hint
// intact); this layer decides whether the user actually sees it.

// daemon=firewall must escalate a policy-level monitor match back to
// deny AND surface the nudge the policy stashed for this exact case.
// This is the C1 regression: the nudge was being stripped at the
// policy layer, leaving the deny bare.
func TestApplyDaemonModeOverride_FirewallEscalatesWithNudge(t *testing.T) {
	t.Setenv("AGENTLOCK_MODE", "")
	runtimeMode.Store("firewall")
	t.Cleanup(func() { runtimeMode.Store("") })

	in := policy.EvalResult{
		Verdict:         "allow",
		RuleID:          "safety.rm-suggest-trash",
		Reason:          "monitor: matched rule safety.rm-suggest-trash (deny)",
		MonitorMatch:    true,
		OriginalVerdict: "deny",
		Nudge:           "use trash instead",
	}
	out, mode, origVerdict := applyDaemonModeOverride(in)

	if mode != "firewall" {
		t.Fatalf("mode = %q, want firewall", mode)
	}
	if out.Verdict != "deny" {
		t.Fatalf("Verdict = %q, want deny (firewall escalation)", out.Verdict)
	}
	if origVerdict != "deny" {
		t.Fatalf("origVerdict = %q, want deny (ledger truth)", origVerdict)
	}
	if out.Nudge != "use trash instead" {
		t.Fatalf("Nudge = %q, want %q (firewall escalation must keep the hint)",
			out.Nudge, "use trash instead")
	}
	if out.MonitorMatch {
		t.Fatal("MonitorMatch must be cleared after firewall escalation")
	}
	if out.RuleID != "safety.rm-suggest-trash" {
		t.Fatalf("RuleID = %q, want safety.rm-suggest-trash", out.RuleID)
	}
}

// daemon=monitor + a policy-level monitor match (allow + MonitorMatch)
// must strip the nudge: the agent is being allowed to proceed in both
// layers, so surfacing a remediation hint would be misleading. This
// is the relocated cousin of the old policy-layer
// TestEvaluate_MonitorDowngradeSuppressesNudge.
func TestApplyDaemonModeOverride_MonitorMatchStripsNudge(t *testing.T) {
	t.Setenv("AGENTLOCK_MODE", "")
	runtimeMode.Store("monitor")
	t.Cleanup(func() { runtimeMode.Store("") })

	in := policy.EvalResult{
		Verdict:         "allow",
		RuleID:          "safety.rm-suggest-trash",
		Reason:          "monitor: matched rule safety.rm-suggest-trash (deny)",
		MonitorMatch:    true,
		OriginalVerdict: "deny",
		Nudge:           "use trash instead",
	}
	out, mode, origVerdict := applyDaemonModeOverride(in)

	if mode != "monitor" {
		t.Fatalf("mode = %q, want monitor", mode)
	}
	if out.Verdict != "allow" {
		t.Fatalf("Verdict = %q, want allow", out.Verdict)
	}
	if origVerdict != "allow" {
		// The verdict reaching the function was already-allow; the
		// ledger should record that as truth. (OriginalVerdict on the
		// EvalResult preserves the policy-layer deny separately.)
		t.Fatalf("origVerdict = %q, want allow", origVerdict)
	}
	if out.Nudge != "" {
		t.Fatalf("Nudge = %q, want empty (agent is being allowed to proceed)", out.Nudge)
	}
	if !out.MonitorMatch {
		t.Fatal("MonitorMatch must remain true so the ledger records the policy-level match")
	}
}

// daemon=monitor + a real policy-level deny must suppress to allow,
// stamp MonitorMatch, AND strip the nudge. Pre-existing behavior;
// covered here so the strip-on-final-allow contract is testable
// independent of any HTTP fixture.
func TestApplyDaemonModeOverride_MonitorSuppressesDenyAndStripsNudge(t *testing.T) {
	t.Setenv("AGENTLOCK_MODE", "")
	runtimeMode.Store("monitor")
	t.Cleanup(func() { runtimeMode.Store("") })

	in := policy.EvalResult{
		Verdict:         "deny",
		RuleID:          "safety.rm-suggest-trash",
		Reason:          "matched rule safety.rm-suggest-trash (deny)",
		OriginalVerdict: "deny",
		Nudge:           "use trash instead",
	}
	out, _, origVerdict := applyDaemonModeOverride(in)

	if out.Verdict != "allow" {
		t.Fatalf("Verdict = %q, want allow (monitor suppression)", out.Verdict)
	}
	if origVerdict != "deny" {
		t.Fatalf("origVerdict = %q, want deny (ledger truth)", origVerdict)
	}
	if !out.MonitorMatch {
		t.Fatal("MonitorMatch must be set after monitor suppression")
	}
	if out.Nudge != "" {
		t.Fatalf("Nudge = %q, want empty after monitor suppression", out.Nudge)
	}
}
