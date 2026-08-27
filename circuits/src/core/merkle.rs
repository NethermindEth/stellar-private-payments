//! Merkle tree utilities using Poseidon2 hash
//!
//! Provides merkle tree operations for use in ZK circuits. These functions
//! match the Circom circuit implementations and produce identical roots/proofs.
//! Duplicated copy of SDK prover Merkle tree logic
//! (`sdk/native/src/zk/merkle.rs`). Bit-identical synchronization is enforced
//! by `e2e-tests/src/tests/coherence/merkle.rs`, over both a full tree and the
//! padded prefix the pool actually holds.

use alloc::vec::Vec;
use ark_bn254::Fr as Scalar;
use ark_ff::PrimeField;
use core::ops::Add;
use taceo_poseidon2::bn254::t2;

/// Zero leaf shared by the pool and ASP membership trees, big-endian.
///
/// `poseidon2("XLM")`. Matches `get_zeroes()[0]` in `soroban-utils` and
/// `ZERO_LEAF_BYTES` in the SDK prover.
pub const ZERO_LEAF_BE: [u8; 32] = [
    37, 48, 34, 136, 219, 153, 53, 3, 68, 151, 65, 131, 206, 49, 13, 99, 181, 58, 187, 158, 240,
    248, 87, 87, 83, 238, 211, 110, 1, 24, 249, 206,
];

/// Zero leaf as a field element.
#[inline]
pub fn zero_leaf() -> Scalar {
    Scalar::from_be_bytes_mod_order(&ZERO_LEAF_BE)
}

/// Poseidon2 compression for merkle tree nodes
///
/// Computes `P(left, right)[0] + left` where P is the Poseidon2 permutation.
/// This matches the feed-forward compression used in Circom circuits.
#[inline]
pub fn poseidon2_compression(left: Scalar, right: Scalar) -> Scalar {
    let perm = t2::permutation(&[left, right]);
    perm[0].add(left)
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

/// Node value of a completely empty subtree, indexed by level
///
/// Index 0 is the zero leaf and index `depth` is the root of an empty tree.
pub fn empty_subtree_roots(depth: usize) -> Vec<Scalar> {
    let mut empty = Vec::with_capacity(depth.checked_add(1).expect("depth overflow"));
    empty.push(zero_leaf());
    for level in 0..depth {
        empty.push(poseidon2_compression(empty[level], empty[level]));
    }
    empty
}

/// Merkle tree over an append-only prefix of leaves at a fixed depth
///
/// Indices from `leaves.len()` up to `2^depth` hold the zero leaf, so building
/// costs `O(leaves.len() * depth)` instead of `O(2^depth)`. Roots and proofs
/// match [`merkle_root`] and [`merkle_proof`] over the dense equivalent.
pub struct PrefixTree {
    depth: usize,
    /// Empty-subtree value per level, as returned by [`empty_subtree_roots`].
    empty: Vec<Scalar>,
    /// Computed nodes per level for the prefix only; `levels[0]` are the
    /// leaves. Anything past the end of a level is `empty[level]`.
    levels: Vec<Vec<Scalar>>,
}

impl PrefixTree {
    /// Build the tree from its filled prefix
    ///
    /// # Panics
    ///
    /// Panics if `depth` is outside `1..=32`, or if `leaves` holds more entries
    /// than a tree of that depth.
    pub fn new(leaves: &[Scalar], depth: usize) -> Self {
        assert!(
            depth > 0 && depth <= 32,
            "depth must be between 1 and 32, got {depth}"
        );
        let capacity = 1usize << depth;
        assert!(
            leaves.len() <= capacity,
            "{} leaves exceed the {capacity} a depth-{depth} tree holds",
            leaves.len()
        );

        let empty = empty_subtree_roots(depth);
        let mut levels = Vec::with_capacity(depth.checked_add(1).expect("depth overflow"));
        levels.push(leaves.to_vec());

        for level in 0..depth {
            let current = &levels[level];
            let mut next = Vec::with_capacity(current.len().div_ceil(2));
            for pair in current.chunks(2) {
                let right = pair.get(1).copied().unwrap_or(empty[level]);
                next.push(poseidon2_compression(pair[0], right));
            }
            levels.push(next);
        }

        Self {
            depth,
            empty,
            levels,
        }
    }

    /// Number of levels between the leaves and the root
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Root of the tree
    pub fn root(&self) -> Scalar {
        self.node(self.depth, 0)
    }

    /// Node value, falling back to the empty subtree past the prefix
    fn node(&self, level: usize, index: usize) -> Scalar {
        self.levels[level]
            .get(index)
            .copied()
            .unwrap_or(self.empty[level])
    }

    /// Sibling path for `index`, with the path bits packed LSB-first
    ///
    /// # Panics
    ///
    /// Panics if `index` lies outside a tree of this depth.
    pub fn proof(&self, index: usize) -> (Vec<Scalar>, u64) {
        assert!(
            index < 1usize << self.depth,
            "leaf index {index} is outside a depth-{} tree",
            self.depth
        );

        let mut path_elems = Vec::with_capacity(self.depth);
        let mut path_indices: u64 = 0;
        let mut current = index;

        for level in 0..self.depth {
            path_elems.push(self.node(level, current ^ 1));
            path_indices |= ((current & 1) as u64) << level;
            current /= 2;
        }

        (path_elems, path_indices)
    }
}

/// Merkle root of a leaf prefix at `depth`, padding with the zero leaf
pub fn merkle_root_padded(leaves: &[Scalar], depth: usize) -> Scalar {
    PrefixTree::new(leaves, depth).root()
}

/// Merkle proof for `index` within a leaf prefix at `depth`
///
/// Returns the sibling path and the path indices packed LSB-first.
pub fn merkle_proof_padded(leaves: &[Scalar], index: usize, depth: usize) -> (Vec<Scalar>, u64) {
    PrefixTree::new(leaves, depth).proof(index)
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
    fn padded_matches_dense_on_a_full_tree() {
        let leaves: Vec<Scalar> = (0..8).map(Scalar::from).collect();
        assert_eq!(merkle_root_padded(&leaves, 3), merkle_root(leaves.clone()));

        for idx in 0..8 {
            let (dense_path, dense_indices, _) = merkle_proof(&leaves, idx);
            let (padded_path, padded_indices) = merkle_proof_padded(&leaves, idx, 3);
            assert_eq!(dense_path, padded_path, "path mismatch at index {idx}");
            assert_eq!(dense_indices, padded_indices, "indices mismatch at {idx}");
        }
    }

    #[test]
    fn padded_prefix_matches_a_zero_leaf_filled_dense_tree() {
        let prefix: Vec<Scalar> = (1..4).map(Scalar::from).collect();
        let mut full = alloc::vec![zero_leaf(); 8];
        full[..prefix.len()].copy_from_slice(&prefix);

        assert_eq!(merkle_root_padded(&prefix, 3), merkle_root(full.clone()));

        for idx in 0..prefix.len() {
            let (dense_path, dense_indices, _) = merkle_proof(&full, idx);
            let (padded_path, padded_indices) = merkle_proof_padded(&prefix, idx, 3);
            assert_eq!(dense_path, padded_path, "path mismatch at index {idx}");
            assert_eq!(dense_indices, padded_indices, "indices mismatch at {idx}");
        }
    }

    #[test]
    fn empty_prefix_root_is_the_empty_subtree_root() {
        let empty = empty_subtree_roots(5);
        assert_eq!(merkle_root_padded(&[], 5), empty[5]);
        assert_eq!(empty[0], zero_leaf());
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
