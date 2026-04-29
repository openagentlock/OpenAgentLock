// Package ledger is the Go-side shim over the signed-Merkle log.
//
// Today LeafHash is implemented natively in Go. A later slice will
// replace the body with a cgo call into the Rust staticlib so the two
// impls cannot disagree. Parity is pinned by the test vector in
// ledger_test.go and ledger/tests/merkle.rs.
package ledger

import "crypto/sha256"

// LeafHash = sha256(payload_hash || sig || prev_leaf).
// prev_leaf must be 32 bytes; earlier entries chain into later ones so
// verification can start from any signed anchor.
func LeafHash(payloadHash, sig, prevLeaf []byte) [32]byte {
	h := sha256.New()
	h.Write(payloadHash)
	h.Write(sig)
	h.Write(prevLeaf)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
