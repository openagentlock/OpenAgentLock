package policy

import _ "embed"

// baselineYAML is the first-boot policy bundled into the daemon binary.
// loaded by cmd/control-plane/main.go when AGENTLOCK_POLICY is unset.
// see baseline.yaml for the cross-harness rationale behind each gate.
//
//go:embed baseline.yaml
var baselineYAML []byte

// DefaultBaseline returns the embedded baseline policy bytes. Returns a
// fresh copy so callers can mutate without poisoning the embedded blob.
func DefaultBaseline() []byte {
	out := make([]byte, len(baselineYAML))
	copy(out, baselineYAML)
	return out
}
