//! Merkle tree utilities for proof generation
//!
//! Provides merkle tree operations matching the Circom circuit implementations.

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;

use wasm_bindgen::prelude::*;
use zkhash::fields::bn256::FpBN256 as Scalar;

use crate::crypto::poseidon2_compression;
use crate::serialization::{bytes_to_scalar, scalar_to_bytes};
use crate::types::FIELD_SIZE;

/// Merkle proof data returned to JavaScript
#[wasm_bindgen]
pub struct MerkleProof {
    /// Path elements (siblings)
    path_elements: Vec<u8>,
    /// Path indices as a single scalar
    path_indices: Vec<u8>,
    /// Computed root
    root: Vec<u8>,
    /// Number of levels
    levels: usize,
}

#[wasm_bindgen]
impl MerkleProof {
    /// Get path elements as flat bytes (levels * 32 bytes)
    #[wasm_bindgen(getter)]
    pub fn path_elements(&self) -> Vec<u8> {
        self.path_elements.clone()
    }

    /// Get path indices as bytes (32 bytes)
    #[wasm_bindgen(getter)]
    pub fn path_indices(&self) -> Vec<u8> {
        self.path_indices.clone()
    }

    /// Get computed root as bytes (32 bytes)
    #[wasm_bindgen(getter)]
    pub fn root(&self) -> Vec<u8> {
        self.root.clone()
    }

    /// Get number of levels
    #[wasm_bindgen(getter)]
    pub fn levels(&self) -> usize {
        self.levels
    }
}

/// Simple in-memory Merkle tree for proof generation
#[wasm_bindgen]
pub struct MerkleTree {
    /// Tree levels (level 0 = leaves)
    levels_data: Vec<Vec<Scalar>>,
    /// Number of levels (depth)
    depth: usize,
    /// Next leaf index to insert
    next_index: usize,
}

#[wasm_bindgen]
impl MerkleTree {
    /// Create a new Merkle tree with given depth
    ///
    /// Tree will have 2^depth leaves
    #[wasm_bindgen(constructor)]
    pub fn new(depth: usize) -> Result<MerkleTree, JsValue> {
        if depth == 0 || depth > 32 {
            return Err(JsValue::from_str("Depth must be between 1 and 32"));
        }

        let num_leaves = 1usize << depth;
        let zero = Scalar::from(0u64);

        // Initialize all levels with zeros
        let mut levels_data = Vec::with_capacity(depth + 1);

        // Level 0 = leaves (all zeros initially)
        levels_data.push(vec![zero; num_leaves]);

        // Build empty tree (all zeros hash to zero with Poseidon)
        let mut current_level_size = num_leaves;
        let mut prev_hash = zero;

        for _ in 0..depth {
            current_level_size /= 2;
            prev_hash = hash_pair(prev_hash, prev_hash);
            levels_data.push(vec![prev_hash; current_level_size]);
        }

        Ok(MerkleTree {
            levels_data,
            depth,
            next_index: 0,
        })
    }

    /// Insert a leaf and return its index
    #[wasm_bindgen]
    pub fn insert(&mut self, leaf_bytes: &[u8]) -> Result<u32, JsValue> {
        let leaf = bytes_to_scalar(leaf_bytes)?;
        let index = self.next_index;

        let max_leaves = 1usize << self.depth;
        if index >= max_leaves {
            return Err(JsValue::from_str("Merkle tree is full"));
        }

        // Insert leaf at level 0
        self.levels_data[0][index] = leaf;

        // Update path to root
        let mut current_index = index;
        let mut current_hash = leaf;

        for level in 0..self.depth {
            let sibling_index = current_index ^ 1; // Toggle last bit to get sibling
            let sibling = self.levels_data[level][sibling_index];

            // Compute parent hash
            let (left, right) = if current_index % 2 == 0 {
                (current_hash, sibling)
            } else {
                (sibling, current_hash)
            };

            current_hash = hash_pair(left, right);
            current_index /= 2;

            // Update parent level
            self.levels_data[level + 1][current_index] = current_hash;
        }

        self.next_index += 1;

        // Safe cast since we checked max_leaves which fits in u32 for depth <= 32
        Ok(index as u32)
    }

    /// Get the current root
    #[wasm_bindgen]
    pub fn root(&self) -> Vec<u8> {
        let root = self.levels_data[self.depth][0];
        scalar_to_bytes(&root)
    }

    /// Get merkle proof for a leaf at given index
    #[wasm_bindgen]
    pub fn get_proof(&self, index: u32) -> Result<MerkleProof, JsValue> {
        let index = index as usize;
        let max_leaves = 1usize << self.depth;

        if index >= max_leaves {
            return Err(JsValue::from_str("Index out of bounds"));
        }

        let mut path_elements = Vec::with_capacity(self.depth * FIELD_SIZE);
        let mut path_indices_bits: u64 = 0;
        let mut current_index = index;

        for level in 0..self.depth {
            let sibling_index = current_index ^ 1;
            let sibling = self.levels_data[level][sibling_index];

            // Add sibling to path
            path_elements.extend_from_slice(&scalar_to_bytes(&sibling));

            // Record direction (0 = left, 1 = right)
            if current_index % 2 == 1 {
                path_indices_bits |= 1u64 << level;
            }

            current_index /= 2;
        }

        let path_indices = scalar_to_bytes(&Scalar::from(path_indices_bits));
        let root = scalar_to_bytes(&self.levels_data[self.depth][0]);

        Ok(MerkleProof {
            path_elements,
            path_indices,
            root,
            levels: self.depth,
        })
    }

    /// Get the next available leaf index
    #[wasm_bindgen(getter)]
    pub fn next_index(&self) -> u32 {
        self.next_index as u32
    }

    /// Get tree depth
    #[wasm_bindgen(getter)]
    pub fn depth(&self) -> usize {
        self.depth
    }
}

/// Compute merkle root from leaves
#[wasm_bindgen]
pub fn compute_merkle_root(leaves_bytes: &[u8], depth: usize) -> Result<Vec<u8>, JsValue> {
    if leaves_bytes.len() % FIELD_SIZE != 0 {
        return Err(JsValue::from_str("Leaves bytes must be multiple of 32"));
    }

    let num_leaves = leaves_bytes.len() / FIELD_SIZE;
    let expected_leaves = 1usize << depth;

    if num_leaves != expected_leaves {
        return Err(JsValue::from_str(&format!(
            "Expected {} leaves for depth {}, got {}",
            expected_leaves,
            depth,
            num_leaves
        )));
    }

    // Parse leaves
    let mut current_level: Vec<Scalar> = Vec::with_capacity(num_leaves);
    for i in 0..num_leaves {
        let chunk = &leaves_bytes[i * FIELD_SIZE..(i + 1) * FIELD_SIZE];
        current_level.push(bytes_to_scalar(chunk)?);
    }

    // Hash up the tree
    for _ in 0..depth {
        let mut next_level = Vec::with_capacity(current_level.len() / 2);
        for pair in current_level.chunks(2) {
            next_level.push(hash_pair(pair[0], pair[1]));
        }
        current_level = next_level;
    }

    Ok(scalar_to_bytes(&current_level[0]))
}

/// Hash two field elements using Poseidon2 compression
fn hash_pair(left: Scalar, right: Scalar) -> Scalar {
    poseidon2_compression(left, right)
}

/// Compute the Merkle parent from ordered children (left, right)
///
/// Uses Poseidon2 compression to combine two child nodes into a parent node.
pub fn merkle_parent(left: Scalar, right: Scalar) -> Scalar {
    hash_pair(left, right)
}

/// Build a Merkle root from a full list of leaves
///
/// Computes the Merkle root by repeatedly hashing pairs of nodes until
/// a single root remains.
pub fn merkle_root(mut leaves: Vec<Scalar>) -> Scalar {
    while leaves.len() > 1 {
        let mut next = Vec::with_capacity(leaves.len() / 2);
        for pair in leaves.chunks_exact(2) {
            next.push(hash_pair(pair[0], pair[1]));
        }
        leaves = next;
    }
    leaves[0]
}

/// Compute the Merkle path (siblings) and path index bits for a given leaf index
///
/// Generates the Merkle proof for a leaf at the given index, including all
/// sibling nodes along the path to the root.
pub fn merkle_proof_internal(leaves: &[Scalar], mut index: usize) -> (Vec<Scalar>, u64, usize) {
    assert!(!leaves.is_empty() && leaves.len().is_power_of_two());
    let mut level_nodes = leaves.to_vec();
    let levels = level_nodes.len().ilog2() as usize;

    let mut path_elems = Vec::with_capacity(levels);
    let mut path_indices_bits_lsb = Vec::with_capacity(levels);

    for _level in 0..levels {
        let sib_index = if index % 2 == 0 {
            index + 1
        } else {
            index - 1
        };

        path_elems.push(level_nodes[sib_index]);
        path_indices_bits_lsb.push((index & 1) as u64);

        let mut next = Vec::with_capacity(leaves.len() / 2);
        for pair in level_nodes.chunks_exact(2) {
            next.push(hash_pair(pair[0], pair[1]));
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


