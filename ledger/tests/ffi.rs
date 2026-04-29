//! Smoke test for the C ABI. Invokes `oal_*` fns via their Rust names and
//! confirms they produce the same outputs as the pure-Rust `merkle::*`
//! routines. This catches drift without needing a C linker in the test.

use openagentlock_ledger::{ffi, merkle};

fn call_leaf_hash(payload: &[u8], sig: &[u8], prev: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    // SAFETY: all buffers are valid slices of the stated lengths.
    let ok = unsafe {
        ffi::oal_leaf_hash(
            payload.as_ptr(),
            payload.len(),
            sig.as_ptr(),
            sig.len(),
            prev.as_ptr(),
            out.as_mut_ptr(),
        )
    };
    assert_eq!(ok, 1);
    out
}

fn call_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    let mut flat = Vec::with_capacity(leaves.len() * 32);
    for l in leaves {
        flat.extend_from_slice(l);
    }
    let mut out = [0u8; 32];
    // SAFETY: flat has len() == leaves.len()*32.
    let ok = unsafe { ffi::oal_merkle_root(flat.as_ptr(), leaves.len(), out.as_mut_ptr()) };
    assert_eq!(ok, 1);
    out
}

fn call_verify(leaf: [u8; 32], index: usize, proof: &[[u8; 32]], root: [u8; 32]) -> bool {
    let mut flat = Vec::with_capacity(proof.len() * 32);
    for p in proof {
        flat.extend_from_slice(p);
    }
    let proof_ptr = if proof.is_empty() { std::ptr::null() } else { flat.as_ptr() };
    // SAFETY: leaf/root are valid 32-byte arrays; flat has proof.len()*32 bytes.
    let ok = unsafe {
        ffi::oal_verify_proof(leaf.as_ptr(), index, proof_ptr, proof.len(), root.as_ptr())
    };
    ok == 1
}

#[test]
fn leaf_hash_matches_pure_rust() {
    let payload = b"payload";
    let sig = b"sig";
    let prev = [0u8; 32];
    let ffi_out = call_leaf_hash(payload, sig, &prev);
    let pure = merkle::leaf_hash(payload, sig, &prev);
    assert_eq!(ffi_out, pure);
}

#[test]
fn leaf_hash_accepts_empty_sig() {
    let payload = b"x";
    let prev = [1u8; 32];
    let ffi_out = call_leaf_hash(payload, &[], &prev);
    let pure = merkle::leaf_hash(payload, &[], &prev);
    assert_eq!(ffi_out, pure);
}

#[test]
fn merkle_root_matches_pure_rust_two_leaves() {
    let leaves = [[1u8; 32], [2u8; 32]];
    assert_eq!(call_merkle_root(&leaves), merkle::merkle_root(&leaves));
}

#[test]
fn merkle_root_matches_pure_rust_three_leaves_odd_tail() {
    let leaves = [[1u8; 32], [2u8; 32], [3u8; 32]];
    assert_eq!(call_merkle_root(&leaves), merkle::merkle_root(&leaves));
}

#[test]
fn merkle_root_empty_input_is_sha256_of_empty() {
    let ffi_out = call_merkle_root(&[]);
    let pure = merkle::merkle_root(&[]);
    assert_eq!(ffi_out, pure);
}

#[test]
fn verify_proof_round_trip() {
    let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
    let root = merkle::merkle_root(&leaves);
    for i in 0..leaves.len() {
        let proof = merkle::inclusion_proof(&leaves, i);
        assert!(call_verify(leaves[i], i, &proof, root), "leaf {i}");
    }
}

#[test]
fn verify_proof_rejects_tamper() {
    let leaves = vec![[1u8; 32], [2u8; 32]];
    let root = merkle::merkle_root(&leaves);
    let proof = merkle::inclusion_proof(&leaves, 0);
    let mut bad_leaf = leaves[0];
    bad_leaf[0] ^= 0xff;
    assert!(!call_verify(bad_leaf, 0, &proof, root));
}
