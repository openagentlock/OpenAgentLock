//! Strict TDD for the Merkle helpers in `openagentlock_ledger::merkle`.
//!
//! Run: `cd ledger && cargo test`. Initial state: every assertion below
//! either fails or panics in `unimplemented!()`. Implement `merkle_root`,
//! `inclusion_proof`, and `verify_proof` minimally to make these green.

use openagentlock_ledger::merkle::{inclusion_proof, leaf_hash, merkle_root, verify_proof};
use sha2::{Digest, Sha256};

fn h(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

#[test]
fn leaf_hash_matches_definition() {
    // leaf = sha256(payload_hash || sig || prev_leaf)
    let payload = h(b"payload");
    let sig = [0xAAu8; 64];
    let prev = h(b"prev");

    let mut want = Sha256::new();
    want.update(payload);
    want.update(sig);
    want.update(prev);
    let want: [u8; 32] = want.finalize().into();

    let got = leaf_hash(&payload, &sig, &prev);
    assert_eq!(got, want);
}

#[test]
fn root_of_empty_tree_is_sha256_of_empty_string() {
    // Convention: empty tree == sha256("").
    let want = h(b"");
    let got = merkle_root(&[]);
    assert_eq!(got, want);
}

#[test]
fn root_of_single_leaf_is_the_leaf_itself() {
    let l = h(b"only");
    assert_eq!(merkle_root(&[l]), l);
}

#[test]
fn root_of_two_leaves_is_sha256_of_concat() {
    let a = h(b"a");
    let b = h(b"b");
    let mut want = Sha256::new();
    want.update(a);
    want.update(b);
    let want: [u8; 32] = want.finalize().into();
    assert_eq!(merkle_root(&[a, b]), want);
}

#[test]
fn root_of_three_leaves_duplicates_odd_tail() {
    // RFC-6962-style: odd tail duplicates the last leaf at each level.
    let a = h(b"a");
    let b = h(b"b");
    let c = h(b"c");

    // Level 1: sha256(a||b), sha256(c||c)
    let mut ab = Sha256::new();
    ab.update(a);
    ab.update(b);
    let ab: [u8; 32] = ab.finalize().into();
    let mut cc = Sha256::new();
    cc.update(c);
    cc.update(c);
    let cc: [u8; 32] = cc.finalize().into();
    // Level 2: sha256(ab||cc)
    let mut want = Sha256::new();
    want.update(ab);
    want.update(cc);
    let want: [u8; 32] = want.finalize().into();

    assert_eq!(merkle_root(&[a, b, c]), want);
}

#[test]
fn inclusion_proof_for_single_leaf_is_empty_and_verifies() {
    let l = h(b"only");
    let proof = inclusion_proof(&[l], 0);
    assert!(proof.is_empty());
    assert!(verify_proof(l, 0, &proof, l));
}

#[test]
fn inclusion_proof_for_each_leaf_in_two_leaf_tree_verifies() {
    let a = h(b"a");
    let b = h(b"b");
    let leaves = vec![a, b];
    let root = merkle_root(&leaves);

    let proof_a = inclusion_proof(&leaves, 0);
    let proof_b = inclusion_proof(&leaves, 1);
    assert!(verify_proof(a, 0, &proof_a, root));
    assert!(verify_proof(b, 1, &proof_b, root));
}

#[test]
fn inclusion_proof_for_each_leaf_in_three_leaf_tree_verifies() {
    let leaves: Vec<[u8; 32]> = (0..3).map(|i| h(&[i as u8])).collect();
    let root = merkle_root(&leaves);
    for i in 0..leaves.len() {
        let proof = inclusion_proof(&leaves, i);
        assert!(verify_proof(leaves[i], i, &proof, root), "leaf {i} did not verify");
    }
}

#[test]
fn verify_proof_rejects_wrong_root() {
    let leaves: Vec<[u8; 32]> = (0..4).map(|i| h(&[i as u8])).collect();
    let root = merkle_root(&leaves);
    let bogus = h(b"bogus");
    let proof = inclusion_proof(&leaves, 2);
    assert!(verify_proof(leaves[2], 2, &proof, root));
    assert!(!verify_proof(leaves[2], 2, &proof, bogus));
}

#[test]
fn verify_proof_rejects_wrong_leaf() {
    let leaves: Vec<[u8; 32]> = (0..4).map(|i| h(&[i as u8])).collect();
    let root = merkle_root(&leaves);
    let proof = inclusion_proof(&leaves, 1);
    let wrong = h(b"wrong");
    assert!(!verify_proof(wrong, 1, &proof, root));
}
