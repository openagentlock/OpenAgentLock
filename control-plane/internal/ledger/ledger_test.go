package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// leaf_hash = sha256(payload_hash || sig || prev_leaf). Must match the Rust
// impl in ledger/src/merkle.rs::leaf_hash so that when the FFI slice lands
// Go and Rust produce identical leaves over identical inputs.
func TestLeafHash_MatchesKnownVector(t *testing.T) {
	payload := []byte("payload")
	sig := []byte("signature")
	prev := make([]byte, 32)

	h := sha256.New()
	h.Write(payload)
	h.Write(sig)
	h.Write(prev)
	want := h.Sum(nil)

	got := LeafHash(payload, sig, prev)
	if hex.EncodeToString(got[:]) != hex.EncodeToString(want) {
		t.Fatalf("leaf hash mismatch\n want: %x\n  got: %x", want, got[:])
	}
}

func TestLeafHash_InputOrderMatters(t *testing.T) {
	a := LeafHash([]byte("a"), []byte("b"), make([]byte, 32))
	b := LeafHash([]byte("b"), []byte("a"), make([]byte, 32))
	if a == b {
		t.Fatal("leaves with swapped inputs must hash differently")
	}
}

func TestLeafHash_PrevLeafChainsForward(t *testing.T) {
	zero := make([]byte, 32)
	one := make([]byte, 32)
	one[0] = 1

	a := LeafHash([]byte("x"), []byte("y"), zero)
	b := LeafHash([]byte("x"), []byte("y"), one)
	if a == b {
		t.Fatal("prev_leaf change must change the leaf")
	}
}
