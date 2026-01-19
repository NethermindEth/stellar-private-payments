//! Merkle tree utilities for proof generation
//!
//! Provides merkle tree operations matching the Circom circuit implementations.
//! Core merkle functions are re-exported from `circuits::core::merkle`.

use alloc::{format, vec, vec::Vec};

use wasm_bindgen::prelude::*;
use zkhash::fields::bn256::FpBN256 as Scalar;

use crate::{
    serialization::{bytes_to_scalar, scalar_to_bytes},
    types::FIELD_SIZE,
};

// Re-export core merkle functions from circuits
pub use circuits::core::merkle::{
    merkle_proof as merkle_proof_internal, merkle_root, poseidon2_compression,
};

/// Merkle proof data returned to JavaScript
#[wasm_bindgen]
pub struct MerkleProof {
    /// Path elements
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

/// Simple Merkle tree for proof generation
#[wasm_bindgen]
pub struct MerkleTree {
    /// Tree levels
    levels_data: Vec<Vec<Scalar>>,
    /// Number of levels
    depth: usize,
    /// Next leaf index to insert
    next_index: u64,
}

// TODO: For now we implement a full merkle tree for quick prototyping. We
// should implement a partial merkle tree next to minimize storage on user side
#[wasm_bindgen]
impl MerkleTree {
    /// Create a new Merkle tree with given depth
    #[wasm_bindgen(constructor)]
    pub fn new(depth: usize) -> Result<MerkleTree, JsValue> {
        if depth == 0 || depth > 32 {
            return Err(JsValue::from_str("Depth must be between 1 and 32"));
        }

        // Use checked shift to avoid overflow
        let depth_u32 = u32::try_from(depth).expect("Depth didn't fit in u32");
        let num_leaves = 1usize.checked_shl(depth_u32).ok_or_else(|| {
            JsValue::from_str("Depth too large for this platform, would overflow")
        })?;
        let zero = Scalar::from(0u64);

        // Initialize all levels with zeros
        let capacity = depth
            .checked_add(1)
            .ok_or_else(|| JsValue::from_str("Depth overflow"))?;
        let mut levels_data = Vec::with_capacity(capacity);

        // Leaves at level 0
        levels_data.push(vec![zero; num_leaves]);

        // Build empty tree (all zeros hash to zero with Poseidon)
        let mut current_level_size = num_leaves;
        let mut prev_hash = zero;

        for _ in 0..depth {
            current_level_size /= 2;
            prev_hash = poseidon2_compression(prev_hash, prev_hash);
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

        let max_leaves = 1u64 << self.depth;
        if index >= max_leaves {
            return Err(JsValue::from_str("Merkle tree is full"));
        }

        let index_usize =
            usize::try_from(index).map_err(|_| JsValue::from_str("Index too large"))?;

        // Insert leaf
        self.levels_data[0][index_usize] = leaf;

        // Update path to root
        let mut current_index = index_usize;
        let mut current_hash = leaf;

        for level in 0..self.depth {
            let sibling_index = current_index ^ 1; // Toggle last bit to get sibling
            let sibling = self.levels_data[level][sibling_index];

            // Compute parent hash
            let (left, right) = if current_index.is_multiple_of(2) {
                (current_hash, sibling)
            } else {
                (sibling, current_hash)
            };

            current_hash = poseidon2_compression(left, right);
            current_index /= 2;

            // Update parent level
            let parent_level = level
                .checked_add(1)
                .ok_or_else(|| JsValue::from_str("Level overflow"))?;
            self.levels_data[parent_level][current_index] = current_hash;
        }

        self.next_index = self
            .next_index
            .checked_add(1)
            .ok_or_else(|| JsValue::from_str("Index overflow"))?;

        // index is bounded by max_leaves (1 << depth where depth <= 32)
        u32::try_from(index).map_err(|_| JsValue::from_str("Index too large for u32"))
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
        let index = usize::try_from(index).map_err(|_| JsValue::from_str("Index too large"))?;
        let max_leaves = 1usize << self.depth;

        if index >= max_leaves {
            return Err(JsValue::from_str("Index out of bounds"));
        }

        let capacity = self
            .depth
            .checked_mul(FIELD_SIZE)
            .ok_or_else(|| JsValue::from_str("Overflow calculating path capacity"))?;
        let mut path_elements = Vec::with_capacity(capacity);
        let mut path_indices_bits: u64 = 0;
        let mut current_index = index;

        for level in 0..self.depth {
            let sibling_index = current_index ^ 1;
            let sibling = self.levels_data[level][sibling_index];

            // Add sibling to path
            path_elements.extend_from_slice(&scalar_to_bytes(&sibling));

            // Record direction (0 = left, 1 = right)
            if !current_index.is_multiple_of(2) {
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
    pub fn next_index(&self) -> u64 {
        self.next_index
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
    if !leaves_bytes.len().is_multiple_of(FIELD_SIZE) {
        return Err(JsValue::from_str("Leaves bytes must be multiple of 32"));
    }

    let num_leaves = leaves_bytes.len() / FIELD_SIZE;
    let expected_leaves = 1usize << depth;

    if num_leaves != expected_leaves {
        return Err(JsValue::from_str(&format!(
            "Expected {} leaves for depth {}, got {}",
            expected_leaves, depth, num_leaves
        )));
    }

    // Parse leaves
    let mut current_level: Vec<Scalar> = Vec::with_capacity(num_leaves);
    for i in 0..num_leaves {
        let start = i
            .checked_mul(FIELD_SIZE)
            .ok_or_else(|| JsValue::from_str("Index overflow"))?;
        let end = i
            .checked_add(1)
            .and_then(|n| n.checked_mul(FIELD_SIZE))
            .ok_or_else(|| JsValue::from_str("Index overflow"))?;
        let chunk = &leaves_bytes[start..end];
        current_level.push(bytes_to_scalar(chunk)?);
    }

    // Hash up the tree
    for _ in 0..depth {
        let mut next_level = Vec::with_capacity(current_level.len() / 2);
        for pair in current_level.chunks(2) {
            next_level.push(poseidon2_compression(pair[0], pair[1]));
        }
        current_level = next_level;
    }

    Ok(scalar_to_bytes(&current_level[0]))
}
