package ledger

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// Parity: the pure-Go LeafHash and the Rust-backed LeafHashFFI must
// produce identical bytes for every input. If this ever diverges, the
// Merkle root computed in Go stops matching the inclusion proofs produced
// by Rust and audits break silently.
func TestLeafHashFFI_MatchesPureGo(t *testing.T) {
	cases := []struct {
		name              string
		payload, sig, prev []byte
	}{
		{"basic", []byte("payload"), []byte("sig"), make([]byte, 32)},
		{"empty sig", []byte("x"), nil, bytes.Repeat([]byte{1}, 32)},
		{"empty payload", nil, []byte("sig"), bytes.Repeat([]byte{2}, 32)},
		{"long inputs", bytes.Repeat([]byte{0xab}, 1024), bytes.Repeat([]byte{0xcd}, 64), bytes.Repeat([]byte{0xef}, 32)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pure := LeafHash(c.payload, c.sig, c.prev)
			ffi, err := LeafHashFFI(c.payload, c.sig, c.prev)
			if err != nil {
				t.Fatalf("FFI: %v", err)
			}
			if pure != ffi {
				t.Fatalf("mismatch\n pure: %x\n  ffi: %x", pure, ffi)
			}
		})
	}
}

func TestMerkleRoot_EmptyIsSha256OfEmpty(t *testing.T) {
	got, err := MerkleRoot(nil)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(nil)
	if got != want {
		t.Fatalf("empty root\n want: %x\n  got: %x", want, got)
	}
}

func TestMerkleRoot_SingleLeafIsLeaf(t *testing.T) {
	leaf := [32]byte{1, 2, 3}
	got, err := MerkleRoot([][32]byte{leaf})
	if err != nil {
		t.Fatal(err)
	}
	if got != leaf {
		t.Fatalf("single-leaf root != leaf")
	}
}

func TestMerkleRoot_TwoLeavesIsSha256OfConcat(t *testing.T) {
	a := [32]byte{1}
	b := [32]byte{2}
	got, err := MerkleRoot([][32]byte{a, b})
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	h.Write(a[:])
	h.Write(b[:])
	want := sha256.Sum256(append(a[:], b[:]...))
	if got != want {
		t.Fatalf("two-leaf root\n want: %x\n  got: %x", want, got)
	}
}

func TestVerifyProof_SingleLeafEmptyProof(t *testing.T) {
	leaf := [32]byte{9}
	root, _ := MerkleRoot([][32]byte{leaf})
	if !VerifyProof(leaf, 0, nil, root) {
		t.Fatal("single-leaf empty-proof should verify")
	}
}
