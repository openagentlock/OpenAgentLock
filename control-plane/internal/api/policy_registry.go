// policyRegistry pins compiled policies by hash so sessions keep the
// policy they attested to across live edits. New or reloaded sessions
// bind to whatever policyRegistry.Live() is at that moment; gate
// evaluation resolves sess.PolicyHash through ByHash so existing
// sessions keep their pinned policy until they explicitly reload.

package api

import (
	"sync"

	"github.com/openagentlock/openagentlock/control-plane/internal/policy"
)

// maxPolicyPins caps how many historical policy versions the registry
// retains. Each `Swap` (from policy edits) adds one. The live policy is
// never evicted; the oldest non-live pin goes first. 32 is enough for
// burst-editing policy from the dashboard while bounding memory.
const maxPolicyPins = 32

type policyRegistry struct {
	mu       sync.RWMutex
	pins     map[string]*policy.Policy
	pinOrder []string // insertion order for FIFO eviction; exclusive of live
	live     *policy.Policy
}

// livePolicyRegistry is the package-level registry. Initialised by
// bootstrapPolicy at daemon start with whatever policy LoadPolicy
// produced; mutations from /v1/policy/gates ... pin new hashes here.
var livePolicyRegistry = &policyRegistry{pins: map[string]*policy.Policy{}}

// bootstrapPolicy seeds the registry with the initial policy. Called
// from main.go after the first Load. Safe to call more than once; each
// call promotes the given policy to live and pins its hash.
func bootstrapPolicy(p *policy.Policy) {
	if p == nil {
		return
	}
	livePolicyRegistry.Swap(p)
}

// Swap pins the new policy by hash and promotes it to live. Evicts the
// oldest non-live pin once maxPolicyPins is reached so memory stays
// bounded under live-edit churn.
func (r *policyRegistry) Swap(p *policy.Policy) {
	if p == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.pins[p.Hash]; !ok {
		r.pins[p.Hash] = p
		r.pinOrder = append(r.pinOrder, p.Hash)
	}
	// Evict oldest non-live pins until within cap.
	for len(r.pinOrder) > maxPolicyPins {
		evict := r.pinOrder[0]
		r.pinOrder = r.pinOrder[1:]
		if r.live != nil && evict == r.live.Hash {
			// Never evict the live policy — push it to the back instead.
			r.pinOrder = append(r.pinOrder, evict)
			continue
		}
		delete(r.pins, evict)
	}
	r.live = p
}

// Live returns the latest pinned policy. Returns nil if bootstrap
// hasn't run yet (the gate handler falls back to Deps.Policy in that
// case so legacy tests still work).
func (r *policyRegistry) Live() *policy.Policy {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.live
}

// ByHash returns the pinned policy for a given hash. Falls back to
// live if the hash isn't pinned (long-lived session outlived a GC —
// not implemented yet, but future-proof).
func (r *policyRegistry) ByHash(hash string) *policy.Policy {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if p, ok := r.pins[hash]; ok {
		return p
	}
	return r.live
}

// resolvePolicy returns the policy to evaluate against for a session
// with the given pinned hash. Prefers registry; falls back to the
// Deps.Policy if the registry hasn't been bootstrapped (legacy tests).
func resolvePolicy(d Deps, sessionPolicyHash string) *policy.Policy {
	if p := livePolicyRegistry.ByHash(sessionPolicyHash); p != nil {
		return p
	}
	return d.Policy
}

// livePolicyFor returns the live policy for callers who need the current
// hash (new sessions, mutation endpoints). Falls back to Deps.Policy if
// the registry is empty.
func livePolicyFor(d Deps) *policy.Policy {
	if p := livePolicyRegistry.Live(); p != nil {
		return p
	}
	return d.Policy
}
