package api

import (
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/openagentlock/openagentlock/control-plane/internal/ledger"
	"github.com/openagentlock/openagentlock/control-plane/internal/storage"
)

type ledgerRootResponse struct {
	Root       string    `json:"root"`
	Seq        uint64    `json:"seq"`
	Count      int       `json:"count"`
	ComputedAt time.Time `json:"computed_at"`
}

func ledgerRootHandler(d Deps) http.HandlerFunc {
	if d.Store == nil {
		return todo("ledger.root")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		entries, err := d.Store.ListLedger(r.Context())
		if err != nil {
			log.Printf("ledger list: %v", err)
			writeError(w, http.StatusInternalServerError, "storage_error", "ledger read failed")
			return
		}
		leaves := make([][32]byte, len(entries))
		for i, e := range entries {
			leaves[i] = e.LeafHash
		}
		root, err := ledger.MerkleRoot(leaves)
		if err != nil {
			log.Printf("merkle root ffi: %v", err)
			writeError(w, http.StatusInternalServerError, "ffi_error", "merkle root computation failed")
			return
		}
		resp := ledgerRootResponse{
			Root:       "sha256:" + hex.EncodeToString(root[:]),
			Count:      len(entries),
			ComputedAt: time.Now().UTC(),
		}
		if n := len(entries); n > 0 {
			resp.Seq = entries[n-1].Seq
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

type ledgerVerifyResponse struct {
	OK         bool   `json:"ok"`
	Root       string `json:"root"`
	Count      int    `json:"count"`
	FirstBadAt *int   `json:"first_bad_at,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// ledgerVerifyHandler recomputes every leaf from the stored payload hash,
// sig, and prev_leaf chain and confirms the stored leaf_hash matches. If
// any leaf disagrees, returns ok=false with the index of the first break.
// Then recomputes the Merkle root via the Rust FFI and returns it.
func ledgerVerifyHandler(d Deps) http.HandlerFunc {
	if d.Store == nil {
		return todo("ledger.verify")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		entries, err := d.Store.ListLedger(r.Context())
		if err != nil {
			log.Printf("ledger list: %v", err)
			writeError(w, http.StatusInternalServerError, "storage_error", "ledger read failed")
			return
		}

		var prev [32]byte
		leaves := make([][32]byte, 0, len(entries))
		for i, e := range entries {
			if err := verifyEntry(e, prev); err != nil {
				idx := i
				writeJSON(w, http.StatusOK, ledgerVerifyResponse{
					OK:         false,
					Count:      len(entries),
					FirstBadAt: &idx,
					Reason:     err.Error(),
				})
				return
			}
			leaves = append(leaves, e.LeafHash)
			prev = e.LeafHash
		}
		root, err := ledger.MerkleRoot(leaves)
		if err != nil {
			log.Printf("merkle root ffi: %v", err)
			writeError(w, http.StatusInternalServerError, "ffi_error", "merkle root computation failed")
			return
		}
		writeJSON(w, http.StatusOK, ledgerVerifyResponse{
			OK:    true,
			Root:  "sha256:" + hex.EncodeToString(root[:]),
			Count: len(entries),
		})
	}
}

// verifyEntry rebuilds the leaf from its stored inputs and checks the
// stored leaf_hash against the rebuilt one + the chain link against the
// expected prev_leaf. Every field must round-trip deterministically; any
// tamper breaks here.
func verifyEntry(e storage.LedgerEntry, prevExpected [32]byte) error {
	if e.PrevLeaf != prevExpected {
		return fmt.Errorf("seq %d: prev_leaf chain break: want %x got %x", e.Seq, prevExpected[:], e.PrevLeaf[:])
	}
	ph, err := hex.DecodeString(e.PayloadHash)
	if err != nil {
		return fmt.Errorf("seq %d: payload_hash decode: %w", e.Seq, err)
	}
	sig, err := hex.DecodeString(e.Sig)
	if err != nil {
		return fmt.Errorf("seq %d: sig decode: %w", e.Seq, err)
	}
	recomputed := ledger.LeafHash(ph, sig, prevExpected[:])
	if recomputed != e.LeafHash {
		return fmt.Errorf("seq %d: leaf_hash mismatch: recomputed %x stored %x",
			e.Seq, recomputed[:], e.LeafHash[:])
	}
	return nil
}
