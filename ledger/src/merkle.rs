//! Merkle tree over leaf hashes. Leaves come from the ledger entries;
//! internal nodes are sha256(left || right). Odd tails duplicate the
//! last leaf (RFC 6962-style pattern).

use sha2::{Digest, Sha256};

/// `leaf_hash(payload_hash, sig, prev_leaf) = sha256(payload_hash ‖ sig ‖ prev_leaf)`.
pub fn leaf_hash(payload_hash: &[u8], sig: &[u8], prev_leaf: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(payload_hash);
    h.update(sig);
    h.update(prev_leaf);
    h.finalize().into()
}

fn hash_pair(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(left);
    h.update(right);
    h.finalize().into()
}

fn next_layer(layer: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut next = Vec::with_capacity(layer.len().div_ceil(2));
    let mut i = 0;
    while i < layer.len() {
        let left = layer[i];
        // Odd tail: duplicate the last leaf at this layer.
        let right = if i + 1 < layer.len() { layer[i + 1] } else { layer[i] };
        next.push(hash_pair(left, right));
        i += 2;
    }
    next
}

/// Merkle root over a slice of leaf hashes. Empty input returns sha256("") by convention.
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return Sha256::digest(b"").into();
    }
    if leaves.len() == 1 {
        return leaves[0];
    }
    let mut layer: Vec<[u8; 32]> = leaves.to_vec();
    while layer.len() > 1 {
        layer = next_layer(&layer);
    }
    layer[0]
}

/// Inclusion proof: sibling path from `index` up to (but not including) the root.
pub fn inclusion_proof(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
    if leaves.len() <= 1 {
        return Vec::new();
    }
    let mut proof = Vec::new();
    let mut layer: Vec<[u8; 32]> = leaves.to_vec();
    let mut idx = index;
    while layer.len() > 1 {
        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        // Odd tail: if the sibling index is out of range, the node is its own sibling.
        let sibling = if sibling_idx < layer.len() {
            layer[sibling_idx]
        } else {
            layer[idx]
        };
        proof.push(sibling);
        layer = next_layer(&layer);
        idx /= 2;
    }
    proof
}

/// Verify a leaf against a root using its proof + index.
pub fn verify_proof(
    leaf: [u8; 32],
    index: usize,
    proof: &[[u8; 32]],
    root: [u8; 32],
) -> bool {
    let mut hash = leaf;
    let mut idx = index;
    for sibling in proof {
        hash = if idx % 2 == 0 {
            hash_pair(hash, *sibling)
        } else {
            hash_pair(*sibling, hash)
        };
        idx /= 2;
    }
    hash == root
}
