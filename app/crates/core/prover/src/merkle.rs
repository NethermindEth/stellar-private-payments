//! Merkle tree utilities for proof generation
//!
//! Provides merkle tree operations matching the Circom circuit implementations.
//! Core merkle functions are re-exported from `circuits::core::merkle`.

use alloc::vec::Vec;

use anyhow::{Result, anyhow};
use zkhash::{ark_ff::PrimeField, fields::bn256::FpBN256 as Scalar};

use crate::{crypto, serialization::scalar_to_bytes};
use types::Field;

// Re-export core merkle functions from circuits
pub use circuits::core::merkle::{
    merkle_proof as merkle_proof_internal, merkle_root, poseidon2_compression,
};

fn field_to_scalar(field: Field) -> Scalar {
    Scalar::from_le_bytes_mod_order(&field.to_le_bytes())
}

fn scalar_to_field(scalar: Scalar) -> Field {
    let le = scalar_to_bytes(&scalar);
    let le: [u8; 32] = le.try_into().expect("scalar bytes length");
    Field::try_from_le_bytes(le).expect("scalar to field conversion")
}

fn hash_pair(left: Field, right: Field) -> Field {
    let left_s = field_to_scalar(left);
    let right_s = field_to_scalar(right);
    let hashed = poseidon2_compression(left_s, right_s);
    scalar_to_field(hashed)
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

        // Build the empty-subtree chain using the same zero leaf as the contract.
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

        for level in 0..depth {
            if levels[level].is_empty() {
                levels[level].push(empty[level]);
            }

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

    /// Compute a Merkle proof for `index`, returning:
    /// - `path_elements`: sibling node values as 32-byte little-endian field
    ///   bytes
    /// - `path_indices`: packed path bits as a 32-byte little-endian scalar
    ///
    /// `index` must be `< leaf_count()`.
    pub fn proof_bytes(&self, index: u32) -> Result<(Vec<[u8; 32]>, [u8; 32])> {
        let idx_usize = usize::try_from(index).map_err(|_| anyhow!("index too large"))?;
        if idx_usize >= self.leaves.len() {
            return Err(anyhow!(
                "leaf index out of range: index={}, leaves={}",
                idx_usize,
                self.leaves.len()
            ));
        }

        let mut level_nodes = self.leaves.clone();
        let mut index = idx_usize;

        let mut path_elements = Vec::with_capacity(self.depth);
        let mut path_indices_bits_lsb = Vec::with_capacity(self.depth);

        for level in 0..self.depth {
            let sib_index = if index.is_multiple_of(2) {
                index
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("sibling index overflow"))?
            } else {
                index
                    .checked_sub(1)
                    .ok_or_else(|| anyhow!("sibling index underflow"))?
            };

            let sib = level_nodes
                .get(sib_index)
                .copied()
                .unwrap_or(self.empty[level]);
            path_elements.push(sib.to_le_bytes());
            path_indices_bits_lsb.push((index & 1) as u64);

            if level_nodes.is_empty() {
                level_nodes.push(self.empty[level]);
            }
            let level_len = level_nodes.len();
            let next_len = level_len.div_ceil(2);
            let mut next = Vec::with_capacity(next_len);
            for i in 0..next_len {
                let left_idx = i.checked_mul(2).expect("index overflow");
                let right_idx = left_idx.checked_add(1).expect("index overflow");
                let left = level_nodes
                    .get(left_idx)
                    .copied()
                    .unwrap_or(self.empty[level]);
                let right = level_nodes
                    .get(right_idx)
                    .copied()
                    .unwrap_or(self.empty[level]);
                next.push(hash_pair(left, right));
            }
            level_nodes = next;
            index /= 2;
        }

        let mut path_indices: u64 = 0;
        for (i, b) in path_indices_bits_lsb.into_iter().enumerate() {
            path_indices |= b << i;
        }

        let mut idx_le = [0u8; 32];
        idx_le[..8].copy_from_slice(&path_indices.to_le_bytes());

        Ok((path_elements, idx_le))
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

    /// Compute a pool-witness compatible Merkle proof for `index`.
    ///
    /// `index` must be `< leaf_count()`.
    pub fn proof_bytes(&self, index: u32) -> Result<(Vec<[u8; 32]>, [u8; 32])> {
        let proof = self.proof(index)?;

        let mut out_elems = Vec::with_capacity(proof.path_elements.len());
        for elem in proof.path_elements {
            out_elems.push(elem.to_le_bytes());
        }

        Ok((out_elems, proof.path_indices.to_le_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use zkhash::ark_ff::{BigInteger, Zero};

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
    fn prefix_built_proof_bytes_matches_prefix_proof_bytes() {
        let depth = 6u32;
        let leaves: Vec<Field> = (0u8..15u8)
            .map(|v| Field::try_from_le_bytes([v; 32]).expect("field"))
            .collect();

        let tree = MerklePrefixTree::new(depth, &leaves).expect("new");
        let built = tree.build();

        for idx in [0u32, 1u32, 2u32, 7u32, 14u32] {
            let (a_elems, a_idx) = tree.proof_bytes(idx).expect("proof");
            let (b_elems, b_idx) = built.proof_bytes(idx).expect("proof");
            assert_eq!(a_elems, b_elems, "path elems mismatch at idx={idx}");
            assert_eq!(a_idx, b_idx, "path idx mismatch at idx={idx}");
        }
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
        let mut full: Vec<Scalar> = vec![field_to_scalar(zero); expected_leaves];
        for (i, leaf) in leaves.iter().enumerate() {
            full[i] = field_to_scalar(*leaf);
        }

        let root_scalar = circuits::core::merkle::merkle_root(full.clone());
        let root_le = scalar_to_bytes(&root_scalar);
        let root_le: [u8; 32] = root_le.try_into().expect("32");
        let root_field = Field::try_from_le_bytes(root_le).expect("field");
        assert_eq!(tree.root().expect("root"), root_field);

        for idx in 0..leaves.len() {
            let (path, indices, levels) = circuits::core::merkle::merkle_proof(&full, idx);
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

            let expected_path: Vec<Field> = path.into_iter().map(scalar_to_field).collect();
            assert_eq!(
                proof.path_elements, expected_path,
                "path mismatch at idx={idx}"
            );
        }
    }

    #[test]
    fn field_to_scalar_roundtrip_zero_and_one() {
        let zero = Field::ZERO;
        let one = Field::ONE;

        assert_eq!(field_to_scalar(zero), Scalar::from(0u64));
        assert_eq!(field_to_scalar(one), Scalar::from(1u64));
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
        let field = scalar_to_field(scalar);

        assert_eq!(field_to_scalar(field), scalar);
    }

    #[test]
    fn field_to_scalar_modulus_reduces_to_zero() {
        let modulus_le = Scalar::MODULUS.to_bytes_le();
        let modulus_le: [u8; 32] = modulus_le
            .try_into()
            .expect("modulus bytes should be 32 bytes");
        let reduced = Scalar::from_le_bytes_mod_order(&modulus_le);

        assert!(reduced.is_zero());

        let field = scalar_to_field(reduced);
        assert_eq!(field_to_scalar(field), Scalar::from(0u64));
    }
}
