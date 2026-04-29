//! C ABI over the Merkle primitives. Called by the Go control-plane via
//! cgo against `libopenagentlock_ledger.a` (static) or `.so`/`.dylib`
//! (dynamic). Kept deliberately thin:
//!
//! - Inputs are flat byte buffers with explicit lengths. No opaque handles.
//! - Outputs write into caller-allocated 32-byte buffers. The caller owns
//!   every allocation; no `free` dance.
//! - Functions return `bool` (success) via `u8` 0 / 1 so cgo doesn't need
//!   to know C `_Bool`.
//!
//! Parity with Go's pure-Go impl is pinned by `internal/ledger/ffi_test.go`
//! and `ledger/tests/ffi.rs`.

use crate::merkle;

/// Compute `leaf_hash(payload_hash ‖ sig ‖ prev_leaf)`.
///
/// - `payload_hash` / `payload_hash_len` — arbitrary-length bytes.
/// - `sig` / `sig_len` — arbitrary-length bytes (may be zero-length).
/// - `prev_leaf` — exactly 32 bytes.
/// - `out` — caller-owned 32-byte buffer receiving the digest.
///
/// Returns 1 on success, 0 on bad argument (null pointer, wrong prev_leaf len).
///
/// # Safety
/// All non-null pointer arguments must point to readable memory of the
/// given lengths. `out` must point to 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn oal_leaf_hash(
    payload_hash: *const u8,
    payload_hash_len: usize,
    sig: *const u8,
    sig_len: usize,
    prev_leaf: *const u8,
    out: *mut u8,
) -> u8 {
    if out.is_null() || prev_leaf.is_null() {
        return 0;
    }
    let payload = if payload_hash.is_null() {
        &[][..]
    } else {
        std::slice::from_raw_parts(payload_hash, payload_hash_len)
    };
    let sig_slice = if sig.is_null() {
        &[][..]
    } else {
        std::slice::from_raw_parts(sig, sig_len)
    };
    let prev = std::slice::from_raw_parts(prev_leaf, 32);
    let digest = merkle::leaf_hash(payload, sig_slice, prev);
    std::ptr::copy_nonoverlapping(digest.as_ptr(), out, 32);
    1
}

/// Compute the Merkle root over `count` leaves packed contiguously at
/// `leaves` (each 32 bytes). Empty input writes `sha256("")` into `out`
/// per the pure-Rust convention.
///
/// Returns 1 on success, 0 on bad argument.
///
/// # Safety
/// `leaves` must point to `count * 32` readable bytes. `out` must point
/// to 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn oal_merkle_root(
    leaves: *const u8,
    count: usize,
    out: *mut u8,
) -> u8 {
    if out.is_null() {
        return 0;
    }
    let flat = if count == 0 || leaves.is_null() {
        &[][..]
    } else {
        std::slice::from_raw_parts(leaves, count * 32)
    };
    let mut tree: Vec<[u8; 32]> = Vec::with_capacity(count);
    for i in 0..count {
        let mut leaf = [0u8; 32];
        leaf.copy_from_slice(&flat[i * 32..(i + 1) * 32]);
        tree.push(leaf);
    }
    let root = merkle::merkle_root(&tree);
    std::ptr::copy_nonoverlapping(root.as_ptr(), out, 32);
    1
}

/// Verify an inclusion proof.
///
/// - `leaf` — 32 bytes, the leaf under test.
/// - `index` — leaf index in the original tree.
/// - `proof` — `proof_len * 32` bytes of sibling hashes, low layer first.
/// - `root` — 32 bytes of the expected root.
///
/// Returns 1 if the proof reconstructs the root, 0 otherwise (also 0 on
/// null pointer).
///
/// # Safety
/// `leaf`, `root` must point to 32 readable bytes. `proof` must point to
/// `proof_len * 32` readable bytes (may be null iff `proof_len == 0`).
#[no_mangle]
pub unsafe extern "C" fn oal_verify_proof(
    leaf: *const u8,
    index: usize,
    proof: *const u8,
    proof_len: usize,
    root: *const u8,
) -> u8 {
    if leaf.is_null() || root.is_null() {
        return 0;
    }
    let mut leaf_bytes = [0u8; 32];
    leaf_bytes.copy_from_slice(std::slice::from_raw_parts(leaf, 32));
    let mut root_bytes = [0u8; 32];
    root_bytes.copy_from_slice(std::slice::from_raw_parts(root, 32));

    let proof_vec: Vec<[u8; 32]> = if proof_len == 0 {
        Vec::new()
    } else {
        let flat = std::slice::from_raw_parts(proof, proof_len * 32);
        (0..proof_len)
            .map(|i| {
                let mut n = [0u8; 32];
                n.copy_from_slice(&flat[i * 32..(i + 1) * 32]);
                n
            })
            .collect()
    };
    if merkle::verify_proof(leaf_bytes, index, &proof_vec, root_bytes) {
        1
    } else {
        0
    }
}
