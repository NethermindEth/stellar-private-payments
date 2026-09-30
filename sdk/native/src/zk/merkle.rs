//! Merkle tree utilities for proof generation
//!
//! Provides merkle tree operations matching the Circom circuit implementations.
//!
//! `circuits` crate keeps a duplicated copy of this logic
//! (`circuits/src/core/merkle.rs`), so we can avoid inter-dependency.
//! Bit-identical synchronization is enforced by
//! `e2e-tests/src/tests/coherence/merkle.rs`, over both a full tree and the
//! padded prefix the pool actually holds.

use core::ops::Add;

use crate::{
    types::Field,
    zk::{
        crypto,
        serialization::{field_to_scalar, scalar_to_field},
    },
};
use anyhow::{Result, anyhow};
use ark_bn254::Fr as Scalar;
use taceo_poseidon2::bn254::t2;

/// Poseidon2 compression for merkle tree nodes.
///
/// Computes `P(left, right)[0] + left` where P is the Poseidon2 permutation.
#[inline]
pub fn poseidon2_compression(left: Scalar, right: Scalar) -> Scalar {
    let perm = t2::permutation(&[left, right]);
    perm[0].add(left)
}

/// Build a Merkle root from a full power-of-two leaf list.
pub fn merkle_root(mut leaves: Vec<Scalar>) -> Scalar {
    assert!(!leaves.is_empty(), "leaves cannot be empty");
    assert!(
        leaves.len().is_power_of_two(),
        "leaves length must be a power of 2"
    );
    while leaves.len() > 1 {
        let mut next = Vec::with_capacity(leaves.len() / 2);
        for pair in leaves.as_chunks::<2>().0 {
            next.push(poseidon2_compression(pair[0], pair[1]));
        }
        leaves = next;
    }
    leaves[0]
}

/// Merkle proof: sibling path, path-index bits, and tree depth.
pub fn merkle_proof_internal(leaves: &[Scalar], mut index: usize) -> (Vec<Scalar>, u64, usize) {
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
        for pair in level_nodes.as_chunks::<2>().0 {
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

fn hash_pair(left: Field, right: Field) -> Field {
    let left_s = field_to_scalar(&left);
    let right_s = field_to_scalar(&right);
    let hashed = poseidon2_compression(left_s, right_s);
    scalar_to_field(&hashed)
}

/// Merkle proof data
pub struct MerkleProof {
    /// Path elements
    pub path_elements: Vec<Field>,
    /// Path indices as a single scalar
    pub path_indices: Field,
    /// Computed root
    pub root: Field,
    /// Number of levels
    pub levels: usize,
}

impl MerkleProof {
    /// Get path elements, one field element per level.
    pub fn path_elements(&self) -> Vec<Field> {
        self.path_elements.clone()
    }

    /// Get path indices packed into a field element.
    pub fn path_indices(&self) -> Field {
        self.path_indices
    }

    /// Get computed root as a field element.
    pub fn root(&self) -> Field {
        self.root
    }

    /// Get number of levels
    pub fn levels(&self) -> usize {
        self.levels
    }
}

/// Memory-efficient Merkle helper for an append-only prefix of leaves.
///
/// Does **not** allocate the full `2^depth` leaf
/// array. It treats all missing leaves as the contract's `zero_leaf` value and
/// computes:
/// - the full-depth Merkle root, and
/// - Merkle proofs for any existing leaf index `< leaves.len()`.
pub struct MerklePrefixTree {
    depth: usize,
    leaves: Vec<Field>,
    /// `empty[level]` is the node value of a completely-empty subtree at
    /// `level`, where level 0 is the leaf level and level `depth` is the
    /// root.
    empty: Vec<Field>,
}

/// Built/cached prefix Merkle tree for efficiently computing multiple proofs.
///
/// Stores the computed node values for each level, but only for the provided
/// prefix width (missing nodes are still treated as `empty[level]`).
#[derive(Clone)]
pub struct MerklePrefixTreeBuilt {
    depth: usize,
    /// See [`MerklePrefixTree::empty`].
    empty: Vec<Field>,
    /// `levels[level]` contains the computed nodes for that level for the
    /// provided prefix. `levels[0]` are the leaves; `levels[depth][0]` is the
    /// root (after padding with `empty` as needed).
    levels: Vec<Vec<Field>>,
}

impl MerklePrefixTree {
    /// Construct a prefix Merkle tree of the given `depth` from `leaves`.
    ///
    /// - `depth` is the full Merkle depth used by the contract/circuit.
    /// - `leaves` must be ordered by `leaf_index` with no gaps: index
    ///   `0..leaves.len()-1`.
    ///
    /// Missing leaves (i.e., indices `>= leaves.len()`) are treated as the
    /// contract's `zero_leaf` value, and the computed root/proofs match the
    /// circuit's Poseidon2 merkle implementation.
    pub fn new(depth: u32, leaves: &[Field]) -> Result<Self> {
        let depth = usize::try_from(depth).map_err(|_| anyhow!("tree depth too large"))?;
        if depth == 0 || depth > 32 {
            return Err(anyhow!("Depth must be between 1 and 32"));
        }

        // Build the empty-subtree chain using the same zero leaf as the
        // contract.
        let mut zero_leaf_be = crypto::zero_leaf();
        zero_leaf_be.reverse();
        let zero_leaf_le: [u8; 32] = zero_leaf_be
            .try_into()
            .map_err(|_| anyhow!("zero leaf: expected 32 bytes"))?;
        let zero = Field::try_from_le_bytes(zero_leaf_le)?;

        let empty_cap = depth
            .checked_add(1)
            .ok_or_else(|| anyhow!("depth overflow"))?;
        let mut empty = Vec::with_capacity(empty_cap);
        empty.push(zero);
        for i in 0..depth {
            empty.push(hash_pair(empty[i], empty[i]));
        }

        let scalar_leaves = leaves.to_vec();

        Ok(Self {
            depth,
            leaves: scalar_leaves,
            empty,
        })
    }

    /// Return the number of provided leaves in this prefix.
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    /// Build and cache all internal levels for this prefix tree.
    ///
    /// This is intended for per-operation use: build once, then compute a root
    /// and multiple membership proofs without re-hashing the entire prefix for
    /// each proof.
    pub fn build(&self) -> MerklePrefixTreeBuilt {
        Self::build_from_parts(self.depth, self.leaves.clone(), self.empty.clone())
    }

    /// Consume this tree and build the cached variant without cloning leaves.
    pub fn into_built(self) -> MerklePrefixTreeBuilt {
        Self::build_from_parts(self.depth, self.leaves, self.empty)
    }

    fn build_from_parts(
        depth: usize,
        leaves: Vec<Field>,
        empty: Vec<Field>,
    ) -> MerklePrefixTreeBuilt {
        let levels_cap = depth.checked_add(1).expect("depth overflow");
        let mut levels = Vec::with_capacity(levels_cap);
        levels.push(leaves);

        // An empty prefix keeps every level empty rather than padding it with
        // `empty[level]`, so `leaf_count()` stays 0. `root()` and `proof()`
        // already fall back to `empty` for missing nodes.
        for level in 0..depth {
            let level_len = levels[level].len();
            let next_len = level_len.div_ceil(2);
            let mut next = Vec::with_capacity(next_len);
            for i in 0..next_len {
                let left_idx = i.checked_mul(2).expect("index overflow");
                let right_idx = left_idx.checked_add(1).expect("index overflow");
                let left = levels[level].get(left_idx).copied().unwrap_or(empty[level]);
                let right = levels[level]
                    .get(right_idx)
                    .copied()
                    .unwrap_or(empty[level]);
                next.push(hash_pair(left, right));
            }
            levels.push(next);
        }

        MerklePrefixTreeBuilt {
            depth,
            empty,
            levels,
        }
    }

    /// Compute the full-depth Merkle root for this prefix.
    ///
    /// This hashes up to `depth` levels, using `zero_leaf`-derived empty
    /// subtree nodes for all missing leaves.
    pub fn root(&self) -> Result<Field> {
        let mut nodes = self.leaves.clone();

        for level in 0..self.depth {
            if nodes.is_empty() {
                nodes.push(self.empty[level]);
            }

            let nodes_len = nodes.len();
            let next_len = nodes_len.div_ceil(2);
            let mut next = Vec::with_capacity(next_len);
            for i in 0..next_len {
                let left_idx = i.checked_mul(2).expect("index overflow");
                let right_idx = left_idx.checked_add(1).expect("index overflow");
                let left = nodes.get(left_idx).copied().unwrap_or(self.empty[level]);
                let right = nodes.get(right_idx).copied().unwrap_or(self.empty[level]);
                next.push(hash_pair(left, right));
            }
            nodes = next;
        }

        Ok(nodes.first().copied().unwrap_or(self.empty[self.depth]))
    }
}

impl MerklePrefixTreeBuilt {
    /// Return the number of provided leaves in this prefix.
    pub fn leaf_count(&self) -> usize {
        self.levels.first().map(|v| v.len()).unwrap_or(0)
    }

    /// Compute the full-depth Merkle root for this built prefix.
    pub fn root(&self) -> Result<Field> {
        let root = self
            .levels
            .get(self.depth)
            .and_then(|v| v.first())
            .copied()
            .unwrap_or(self.empty[self.depth]);
        Ok(root)
    }

    /// Append `leaves` after the current prefix, re-hashing only the nodes
    /// they change.
    ///
    /// The result is identical to rebuilding the tree from the old prefix
    /// followed by `leaves`, but costs about `leaves.len() + depth` hashes
    /// instead of one hash per node of the whole prefix. Fails without
    /// changing the tree if the new prefix would not fit in `2^depth` leaves.
    pub fn append(&mut self, leaves: &[Field]) -> Result<()> {
        if leaves.is_empty() {
            return Ok(());
        }

        let start = self.leaf_count();
        let end = start
            .checked_add(leaves.len())
            .ok_or_else(|| anyhow!("leaf count overflow"))?;
        // `depth <= 32`, so the capacity fits in a u64 even on wasm32.
        let capacity = u32::try_from(self.depth)
            .ok()
            .and_then(|d| 1u64.checked_shl(d))
            .ok_or_else(|| anyhow!("tree depth too large"))?;
        let end_u64 = u64::try_from(end).map_err(|_| anyhow!("leaf count overflow"))?;
        if end_u64 > capacity {
            return Err(anyhow!(
                "tree is full: {} leaves + {} new > capacity {}",
                start,
                leaves.len(),
                capacity
            ));
        }

        self.levels[0].extend_from_slice(leaves);

        // `[lo, hi)` is the range of nodes at `level` that changed. Their
        // parents are the only nodes one level up that need re-hashing.
        let mut lo = start;
        let mut hi = end;
        for level in 0..self.depth {
            let parent_lo = lo / 2;
            let parent_hi = hi.div_ceil(2);
            let (below, above) = self
                .levels
                .split_at_mut(level.checked_add(1).expect("level overflow"));
            let (children, parents) = (&below[level], &mut above[0]);

            for p in parent_lo..parent_hi {
                let left_idx = p.checked_mul(2).expect("index overflow");
                let right_idx = left_idx.checked_add(1).expect("index overflow");
                let left = children[left_idx];
                let right = children
                    .get(right_idx)
                    .copied()
                    .unwrap_or(self.empty[level]);
                let node = hash_pair(left, right);
                match parents.get_mut(p) {
                    Some(slot) => *slot = node,
                    None => parents.push(node),
                }
            }

            lo = parent_lo;
            hi = parent_hi;
        }

        Ok(())
    }

    /// Compute a Merkle proof for `index` for the provided prefix.
    ///
    /// `index` must be `< leaf_count()`.
    pub fn proof(&self, index: u32) -> Result<MerkleProof> {
        let idx_usize = usize::try_from(index).map_err(|_| anyhow!("index too large"))?;
        if idx_usize >= self.leaf_count() {
            return Err(anyhow!(
                "leaf index out of range: index={}, leaves={}",
                idx_usize,
                self.leaf_count()
            ));
        }

        let mut path_elements: Vec<Field> = Vec::with_capacity(self.depth);
        let mut path_indices_bits: u64 = 0;
        let mut current_index = idx_usize;

        for level in 0..self.depth {
            let sib_index = current_index ^ 1;
            let sib = self.levels[level]
                .get(sib_index)
                .copied()
                .unwrap_or(self.empty[level]);

            path_elements.push(sib);

            if !current_index.is_multiple_of(2) {
                path_indices_bits |= 1u64 << level;
            }
            current_index /= 2;
        }

        let mut path_indices_le = [0u8; 32];
        path_indices_le[..8].copy_from_slice(&path_indices_bits.to_le_bytes());
        let path_indices = Field::try_from_le_bytes(path_indices_le)?;

        let root = self.root()?;

        Ok(MerkleProof {
            path_elements,
            path_indices,
            root,
            levels: self.depth,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zk::serialization::scalar_to_bytes;
    use ark_bn254::Fr as Scalar;
    use ark_ff::{BigInteger, PrimeField, Zero};

    #[test]
    fn prefix_built_root_matches_prefix_root() {
        let depth = 8u32;
        let leaves = [
            Field::try_from_le_bytes([7u8; 32]).expect("field"),
            Field::try_from_le_bytes([9u8; 32]).expect("field"),
            Field::try_from_le_bytes([11u8; 32]).expect("field"),
        ];

        let tree = MerklePrefixTree::new(depth, &leaves).expect("new");
        let built = tree.build();

        assert_eq!(tree.root().expect("root"), built.root().expect("root"));
    }

    #[test]
    fn prefix_built_proof_matches_circuits_full_tree() {
        let depth = 4u32;
        let leaves = [
            Field::try_from_le_bytes([1u8; 32]).expect("field"),
            Field::try_from_le_bytes([2u8; 32]).expect("field"),
            Field::try_from_le_bytes([3u8; 32]).expect("field"),
        ];

        let tree = MerklePrefixTree::new(depth, &leaves)
            .expect("new")
            .into_built();

        let mut zero_leaf_be = crypto::zero_leaf();
        zero_leaf_be.reverse();
        let zero_leaf_le: [u8; 32] = zero_leaf_be.try_into().expect("zero");
        let zero = Field::try_from_le_bytes(zero_leaf_le).expect("zero");

        let depth_usize = usize::try_from(depth).expect("depth");
        let expected_leaves = 1usize << depth_usize;
        let mut full: Vec<Scalar> = vec![field_to_scalar(&zero); expected_leaves];
        for (i, leaf) in leaves.iter().enumerate() {
            full[i] = field_to_scalar(leaf);
        }

        let root_scalar = merkle_root(full.clone());
        let root_le = scalar_to_bytes(&root_scalar);
        let root_le: [u8; 32] = root_le.try_into().expect("32");
        let root_field = Field::try_from_le_bytes(root_le).expect("field");
        assert_eq!(tree.root().expect("root"), root_field);

        for idx in 0..leaves.len() {
            let (path, indices, levels) = merkle_proof_internal(&full, idx);
            assert_eq!(levels, depth_usize);

            let proof = tree
                .proof(u32::try_from(idx).expect("idx fits in u32"))
                .expect("proof");
            assert_eq!(proof.levels, depth_usize);
            assert_eq!(proof.root, root_field);

            let mut proof_indices = [0u8; 8];
            proof_indices.copy_from_slice(&proof.path_indices.to_le_bytes()[..8]);
            let proof_indices = u64::from_le_bytes(proof_indices);
            assert_eq!(proof_indices, indices, "indices mismatch at idx={idx}");

            let expected_path: Vec<Field> = path.into_iter().map(|s| scalar_to_field(&s)).collect();
            assert_eq!(
                proof.path_elements, expected_path,
                "path mismatch at idx={idx}"
            );
        }
    }

    #[test]
    fn empty_built_tree_has_no_leaves() {
        let tree = MerklePrefixTree::new(8, &[]).expect("new");
        let unbuilt_root = tree.root().expect("root");
        let built = tree.into_built();

        assert_eq!(built.leaf_count(), 0);
        assert!(built.proof(0).is_err());
        assert_eq!(built.root().expect("root"), unbuilt_root);
    }

    fn leaf(i: u64) -> Field {
        let mut le = [0u8; 32];
        le[..8].copy_from_slice(&i.to_le_bytes());
        Field::try_from_le_bytes(le).expect("field")
    }

    fn leaves(from: u64, to: u64) -> Vec<Field> {
        (from..to).map(leaf).collect()
    }

    /// Root and every proof of `tree` equal a fresh build over `all`.
    fn assert_matches_rebuild(depth: u32, tree: &MerklePrefixTreeBuilt, all: &[Field]) {
        let rebuilt = MerklePrefixTree::new(depth, all).expect("new").into_built();
        let n = all.len();

        assert_eq!(tree.leaf_count(), n, "leaf count at n={n}");
        assert_eq!(
            tree.root().expect("root"),
            rebuilt.root().expect("root"),
            "root at n={n}"
        );
        for idx in 0..u32::try_from(n).expect("n fits in u32") {
            let got = tree.proof(idx).expect("proof");
            let want = rebuilt.proof(idx).expect("proof");
            assert_eq!(got.path_elements, want.path_elements, "path at {idx}/{n}");
            assert_eq!(got.path_indices, want.path_indices, "indices at {idx}/{n}");
            assert_eq!(got.root, want.root, "proof root at {idx}/{n}");
            assert_eq!(got.levels, want.levels, "levels at {idx}/{n}");
        }
        assert!(tree.proof(u32::try_from(n).expect("n")).is_err());
    }

    #[test]
    fn append_to_empty_tree_matches_rebuild() {
        let mut tree = MerklePrefixTree::new(8, &[]).expect("new").into_built();
        tree.append(&leaves(1, 2)).expect("append");
        assert_matches_rebuild(8, &tree, &leaves(1, 2));

        let mut tree = MerklePrefixTree::new(8, &[]).expect("new").into_built();
        tree.append(&leaves(1, 4)).expect("append");
        assert_matches_rebuild(8, &tree, &leaves(1, 4));
    }

    /// Every split of every prefix of a depth-5 tree, so appends start and
    /// end on and across each power-of-two boundary up to full capacity.
    #[test]
    fn append_every_split_matches_rebuild() {
        const DEPTH: u32 = 5;
        let cap = 1u64 << DEPTH;
        for start in 0..=cap {
            for end in start..=cap {
                let mut tree = MerklePrefixTree::new(DEPTH, &leaves(1, start.saturating_add(1)))
                    .expect("new")
                    .into_built();
                tree.append(&leaves(start.saturating_add(1), end.saturating_add(1)))
                    .expect("append");
                assert_matches_rebuild(DEPTH, &tree, &leaves(1, end.saturating_add(1)));
            }
        }
    }

    #[test]
    fn many_single_appends_match_rebuild() {
        const DEPTH: u32 = 7;
        let mut tree = MerklePrefixTree::new(DEPTH, &[]).expect("new").into_built();
        for n in 1..=(1u64 << DEPTH) {
            tree.append(&[leaf(n)]).expect("append");
            assert_matches_rebuild(DEPTH, &tree, &leaves(1, n.saturating_add(1)));
        }
    }

    #[test]
    fn append_past_capacity_fails_and_leaves_tree_unchanged() {
        let mut tree = MerklePrefixTree::new(3, &leaves(1, 7))
            .expect("new")
            .into_built();

        assert!(tree.append(&leaves(7, 10)).is_err());
        assert_matches_rebuild(3, &tree, &leaves(1, 7));

        tree.append(&leaves(7, 9)).expect("fill to capacity");
        assert_matches_rebuild(3, &tree, &leaves(1, 9));

        assert!(tree.append(&[leaf(9)]).is_err());
        assert_matches_rebuild(3, &tree, &leaves(1, 9));
    }

    #[test]
    fn append_at_min_and_max_depth_matches_rebuild() {
        let mut tree = MerklePrefixTree::new(1, &[]).expect("new").into_built();
        tree.append(&[leaf(1)]).expect("append");
        tree.append(&[leaf(2)]).expect("append");
        assert_matches_rebuild(1, &tree, &leaves(1, 3));
        assert!(tree.append(&[leaf(3)]).is_err());

        let mut tree = MerklePrefixTree::new(32, &leaves(1, 4))
            .expect("new")
            .into_built();
        tree.append(&leaves(4, 6)).expect("append");
        tree.append(&[leaf(6)]).expect("append");
        assert_matches_rebuild(32, &tree, &leaves(1, 7));
    }

    #[test]
    fn field_to_scalar_roundtrip_zero_and_one() {
        let zero = Field::ZERO;
        let one = Field::ONE;

        assert_eq!(field_to_scalar(&zero), Scalar::from(0u64));
        assert_eq!(field_to_scalar(&one), Scalar::from(1u64));
    }

    #[test]
    fn field_to_scalar_roundtrip_modulus_minus_one() {
        let mut modulus_le = Scalar::MODULUS.to_bytes_le();
        let mut borrow = 1u8;
        for byte in &mut modulus_le {
            if *byte >= borrow {
                *byte -= borrow;
                borrow = 0;
                break;
            } else {
                *byte = 0xFF;
                borrow = 1;
            }
        }
        assert_eq!(borrow, 0, "modulus should be > 0");

        let scalar = Scalar::from_le_bytes_mod_order(&modulus_le);
        let field = scalar_to_field(&scalar);

        assert_eq!(field_to_scalar(&field), scalar);
    }

    #[test]
    fn field_to_scalar_modulus_reduces_to_zero() {
        let modulus_le = Scalar::MODULUS.to_bytes_le();
        let modulus_le: [u8; 32] = modulus_le
            .try_into()
            .expect("modulus bytes should be 32 bytes");
        let reduced = Scalar::from_le_bytes_mod_order(&modulus_le);

        assert!(reduced.is_zero());

        let field = scalar_to_field(&reduced);
        assert_eq!(field_to_scalar(&field), Scalar::from(0u64));
    }
}
