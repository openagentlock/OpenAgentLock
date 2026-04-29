package ledger

// Cgo binding for the Rust Merkle primitives in
// `ledger/src/ffi.rs` + `ledger/include/openagentlock_ledger.h`. Build
// flags are supplied by the justfile (CGO_CFLAGS, CGO_LDFLAGS); no
// #cgo directives here to avoid hard-coding relative paths.

// #include <openagentlock_ledger.h>
// #include <stdlib.h>
import "C"

import (
	"errors"
	"unsafe"
)

var ErrFFIFailed = errors.New("openagentlock_ledger FFI returned failure")

// MerkleRoot computes the Merkle root over `leaves`, each exactly 32 bytes.
// Empty input returns sha256("") by convention (matches Rust's
// merkle::merkle_root). Delegates to the Rust staticlib.
func MerkleRoot(leaves [][32]byte) ([32]byte, error) {
	var out [32]byte
	var flatPtr *C.uint8_t
	var flat []byte
	if len(leaves) > 0 {
		flat = make([]byte, 0, len(leaves)*32)
		for _, l := range leaves {
			flat = append(flat, l[:]...)
		}
		flatPtr = (*C.uint8_t)(unsafe.Pointer(&flat[0]))
	}
	ok := C.oal_merkle_root(flatPtr, C.size_t(len(leaves)), (*C.uint8_t)(unsafe.Pointer(&out[0])))
	// keep flat alive until the call returns
	_ = flat
	if ok != 1 {
		return out, ErrFFIFailed
	}
	return out, nil
}

// VerifyProof returns true when `proof` reconstructs `root` from `leaf`
// at the given `index` in the original tree.
func VerifyProof(leaf [32]byte, index int, proof [][32]byte, root [32]byte) bool {
	var proofPtr *C.uint8_t
	var flat []byte
	if len(proof) > 0 {
		flat = make([]byte, 0, len(proof)*32)
		for _, p := range proof {
			flat = append(flat, p[:]...)
		}
		proofPtr = (*C.uint8_t)(unsafe.Pointer(&flat[0]))
	}
	ok := C.oal_verify_proof(
		(*C.uint8_t)(unsafe.Pointer(&leaf[0])),
		C.size_t(index),
		proofPtr,
		C.size_t(len(proof)),
		(*C.uint8_t)(unsafe.Pointer(&root[0])),
	)
	_ = flat
	return ok == 1
}

// LeafHashFFI is the Rust-backed leaf_hash. Kept separate from the pure
// `LeafHash` so callers can choose: LeafHash is used on the hot-path (no
// cgo overhead), LeafHashFFI is a parity oracle for tests.
func LeafHashFFI(payloadHash, sig, prevLeaf []byte) ([32]byte, error) {
	var out [32]byte
	if len(prevLeaf) != 32 {
		return out, errors.New("prev_leaf must be 32 bytes")
	}
	var phPtr, sigPtr *C.uint8_t
	if len(payloadHash) > 0 {
		phPtr = (*C.uint8_t)(unsafe.Pointer(&payloadHash[0]))
	}
	if len(sig) > 0 {
		sigPtr = (*C.uint8_t)(unsafe.Pointer(&sig[0]))
	}
	ok := C.oal_leaf_hash(
		phPtr, C.size_t(len(payloadHash)),
		sigPtr, C.size_t(len(sig)),
		(*C.uint8_t)(unsafe.Pointer(&prevLeaf[0])),
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
	)
	if ok != 1 {
		return out, ErrFFIFailed
	}
	return out, nil
}
