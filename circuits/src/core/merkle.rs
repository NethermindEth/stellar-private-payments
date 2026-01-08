//! Merkle tree utilities using Poseidon2 hash
//!
//! Provides merkle tree operations for use in ZK circuits. These functions
//! match the Circom circuit implementations and produce identical roots/proofs.

use alloc::vec::Vec;
use core::ops::Add;
use zkhash::{
    fields::bn256::FpBN256 as Scalar,
    poseidon2::{poseidon2::Poseidon2, poseidon2_instance_bn256::POSEIDON2_BN256_PARAMS_2},
};

/// Poseidon2 compression for merkle tree nodes
///
/// Computes `P(left, right)[0] + left` where P is the Poseidon2 permutation.
/// This matches the feed-forward compression used in Circom circuits.
#[inline]
pub fn poseidon2_compression(left: Scalar, right: Scalar) -> Scalar {
    let poseidon2 = Poseidon2::new(&POSEIDON2_BN256_PARAMS_2);
    let input = [left, right];
    let perm = poseidon2.permutation(&input);
    perm[0].add(input[0])
}

/// Build a Merkle root from a full list of leaves
///
/// Computes the Merkle root by repeatedly hashing pairs of nodes until
/// a single root remains.
///
/// # Panics
///
/// Panics if `leaves` is empty.
pub fn merkle_root(mut leaves: Vec<Scalar>) -> Scalar {
    assert!(!leaves.is_empty(), "leaves cannot be empty");
    assert!(
        leaves.len().is_power_of_two(),
        "leaves length must be a power of 2"
    );
    while leaves.len() > 1 {
        let mut next = Vec::with_capacity(leaves.len() / 2);
        for pair in leaves.chunks_exact(2) {
            next.push(poseidon2_compression(pair[0], pair[1]));
        }
        leaves = next;
    }
    leaves[0]
}

/// Compute the Merkle path and path index bits for a given leaf
/// index
///
/// Generates the Merkle proof for a leaf at the given index, including all
/// sibling nodes along the path to the root and the path indices encoded as
/// a bit pattern.
///
/// # Returns
///
/// Returns a tuple containing:
/// - `path_elements`: Vector of sibling scalar values along the path
/// - `path_indices`: Path indices encoded as a u64 bit pattern
/// - `levels`: Number of levels in the tree
pub fn merkle_proof(leaves: &[Scalar], mut index: usize) -> (Vec<Scalar>, u64, usize) {
    assert!(!leaves.is_empty() && leaves.len().is_power_of_two());
    let mut level_nodes = leaves.to_vec();
    let levels = level_nodes.len().ilog2() as usize;

    let mut path_elems = Vec::with_capacity(levels);
    let mut path_indices_bits_lsb = Vec::with_capacity(levels);

    for _level in 0..levels {
        let sib_index = if index.is_multiple_of(2) {
            index.checked_add(1).expect("sibling index overflow")
        } else {
            index.checked_sub(1).expect("sibling index underflow")
        };

        path_elems.push(level_nodes[sib_index]);
        path_indices_bits_lsb.push((index & 1) as u64);

        let mut next = Vec::with_capacity(leaves.len() / 2);
        for pair in level_nodes.chunks_exact(2) {
            next.push(poseidon2_compression(pair[0], pair[1]));
        }
        level_nodes = next;
        index /= 2;
    }

    let mut path_indices: u64 = 0;
    for (i, b) in path_indices_bits_lsb.iter().copied().enumerate() {
        path_indices |= b << i;
    }

    (path_elems, path_indices, levels)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_root_single_leaf() {
        let leaf = Scalar::from(42u64);
        let root = merkle_root(alloc::vec![leaf]);
        assert_eq!(root, leaf);
    }

    #[test]
    fn test_merkle_root_two_leaves() {
        let leaves = alloc::vec![Scalar::from(1u64), Scalar::from(2u64)];
        let root = merkle_root(leaves.clone());
        let expected = poseidon2_compression(leaves[0], leaves[1]);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_proof_basics() {
        let leaves: Vec<Scalar> = (0..4).map(Scalar::from).collect();
        let (path, indices, levels) = merkle_proof(&leaves, 0);

        assert_eq!(levels, 2);
        assert_eq!(path.len(), 2);
        assert_eq!(indices, 0);
    }

    #[test]
    fn test_merkle_proof_verifies() {
        let leaves: Vec<Scalar> = (0..4).map(Scalar::from).collect();
        let root = merkle_root(leaves.clone());

        for idx in 0..4 {
            let (path, indices, levels) = merkle_proof(&leaves, idx);
            let mut current = leaves[idx];

            for (level, elem) in path.iter().enumerate().take(levels) {
                let is_right = (indices >> level) & 1 == 1;
                current = if is_right {
                    poseidon2_compression(*elem, current)
                } else {
                    poseidon2_compression(current, *elem)
                };
            }

            assert_eq!(current, root, "Proof verification failed for index {}", idx);
        }
    }
}
