//! Merkle tree utilities for proof generation
//!
//! Provides merkle tree operations matching the Circom circuit implementations.
//! Core merkle functions are re-exported from `circuits::core::merkle`.

use alloc::{format, vec, vec::Vec};

use ark_ff::PrimeField;
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

// TODO: For now we implement a full merkle tree. We should study if a partial
// merkle tree is enough. To minimize storage on user side
#[wasm_bindgen]
impl MerkleTree {
    /// Create a new Merkle tree with given depth and default zero leaf (0)
    #[wasm_bindgen(constructor)]
    pub fn new(depth: usize) -> Result<MerkleTree, JsValue> {
        Self::build_tree(depth, Scalar::from(0u64))
    }

    /// Create a new Merkle tree with a custom zero leaf value.
    /// This allows matching contract implementations that use non-zero empty
    /// leaves (e.g., poseidon2("XLM") as the zero value).
    ///
    /// # Arguments
    /// * `depth` - Tree depth (1-32)
    /// * `zero_leaf_bytes` - Custom zero leaf value as 32 bytes (Little-Endian)
    #[wasm_bindgen]
    pub fn new_with_zero_leaf(depth: usize, zero_leaf_bytes: &[u8]) -> Result<MerkleTree, JsValue> {
        let zero = bytes_to_scalar(zero_leaf_bytes)?;
        Self::build_tree(depth, zero)
    }

    /// Internal helper to build the tree with a given zero value
    fn build_tree(depth: usize, zero: Scalar) -> Result<MerkleTree, JsValue> {
        if depth == 0 || depth > 32 {
            return Err(JsValue::from_str("Depth must be between 1 and 32"));
        }

        // Use checked shift to avoid overflow
        let depth_u32 = u32::try_from(depth).expect("Depth didn't fit in u32");
        let num_leaves = 1usize.checked_shl(depth_u32).ok_or_else(|| {
            JsValue::from_str("Depth too large for this platform, would overflow")
        })?;

        // Initialize all levels with zeros
        let capacity = depth
            .checked_add(1)
            .ok_or_else(|| JsValue::from_str("Depth overflow"))?;
        let mut levels_data = Vec::with_capacity(capacity);

        // Leaves at level 0
        levels_data.push(vec![zero; num_leaves]);

        // Build empty tree by hashing up
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

    /// Insert a leaf at the next available index and return that index
    #[wasm_bindgen]
    pub fn insert(&mut self, leaf_bytes: &[u8]) -> Result<u32, JsValue> {
        let index = u32::try_from(self.next_index)
            .map_err(|_| JsValue::from_str("Index too large for u32"))?;
        self.insert_at(leaf_bytes, index)
    }

    /// Insert a leaf at a specific index and return that index
    ///
    /// Allows out-of-order insertion and overwriting existing leaves.
    /// Errors if `index` exceeds `next_index` (would create a gap).
    #[wasm_bindgen]
    pub fn insert_at(&mut self, leaf_bytes: &[u8], index: u32) -> Result<u32, JsValue> {
        let leaf = bytes_to_scalar(leaf_bytes)?;
        self.insert_at_internal(leaf, index)
            .map_err(|e| JsValue::from_str(&e))
    }

    fn insert_at_internal(
        &mut self,
        leaf: Scalar,
        index: u32,
    ) -> Result<u32, alloc::string::String> {
        let index_u64 = u64::from(index);

        if index_u64 > self.next_index {
            return Err(format!(
                "insert_at: index {} exceeds next_index {}, would create gap",
                index, self.next_index
            ));
        }

        let max_leaves = 1u64 << self.depth;
        if index_u64 >= max_leaves {
            return Err("Merkle tree is full".into());
        }

        let index_usize = usize::try_from(index).map_err(|_| "Index too large")?;

        self.update_path(index_usize, leaf);

        let next = index_u64.checked_add(1).ok_or("Index overflow")?;
        self.next_index = self.next_index.max(next);

        Ok(index)
    }

    fn update_path(&mut self, index: usize, leaf: Scalar) {
        self.levels_data[0][index] = leaf;

        let mut current_index = index;
        let mut current_hash = leaf;

        for level in 0..self.depth {
            let sibling_index = current_index ^ 1;
            let sibling = self.levels_data[level][sibling_index];

            let (left, right) = if current_index.is_multiple_of(2) {
                (current_hash, sibling)
            } else {
                (sibling, current_hash)
            };

            current_hash = poseidon2_compression(left, right);
            current_index /= 2;

            let parent_level = level.checked_add(1).expect("level < depth <= 32");
            self.levels_data[parent_level][current_index] = current_hash;
        }
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

    /// Serialize the tree to bytes for storage
    ///
    /// Wire format (all LE): `[depth: u32][next_index: u64][level 0 .. level depth scalars]`
    #[wasm_bindgen]
    pub fn serialize(&self) -> Vec<u8> {
        let depth_u32 = u32::try_from(self.depth).expect("depth <= 32");
        let mut buf = Vec::new();
        buf.extend_from_slice(&depth_u32.to_le_bytes());
        buf.extend_from_slice(&self.next_index.to_le_bytes());
        for level in &self.levels_data {
            for scalar in level {
                buf.extend_from_slice(&scalar_to_bytes(scalar));
            }
        }
        buf
    }

    /// Reconstruct a tree from bytes produced by `serialize()`
    #[wasm_bindgen]
    pub fn deserialize(data: &[u8]) -> Result<MerkleTree, JsValue> {
        Self::deserialize_internal(data).map_err(|e| JsValue::from_str(&e))
    }

    fn deserialize_internal(data: &[u8]) -> Result<MerkleTree, alloc::string::String> {
        if data.len() < 12 {
            return Err("Data too short for header".into());
        }

        let depth_u32 =
            u32::from_le_bytes(data[..4].try_into().map_err(|_| "Invalid depth bytes")?);
        let depth = usize::try_from(depth_u32).map_err(|_| "Depth too large for platform")?;

        if depth == 0 || depth > 32 {
            return Err("Depth must be between 1 and 32".into());
        }

        let next_index =
            u64::from_le_bytes(data[4..12].try_into().map_err(|_| "Invalid next_index bytes")?);

        let num_leaves = 1usize
            .checked_shl(depth_u32)
            .ok_or("Leaf count overflow")?;
        let total_scalars = num_leaves
            .checked_mul(2)
            .and_then(|n| n.checked_sub(1))
            .ok_or("Total size overflow")?;
        let expected_len = total_scalars
            .checked_mul(FIELD_SIZE)
            .and_then(|n| n.checked_add(12))
            .ok_or("Expected length overflow")?;

        if data.len() != expected_len {
            return Err(format!(
                "Expected {} bytes, got {}",
                expected_len,
                data.len()
            ));
        }

        let scalars = &data[12..];
        let mut levels_data =
            Vec::with_capacity(depth.checked_add(1).ok_or("Capacity overflow")?);
        let mut offset = 0usize;
        let mut level_size = num_leaves;

        for _ in 0..=depth {
            let level_bytes = level_size
                .checked_mul(FIELD_SIZE)
                .ok_or("Level bytes overflow")?;
            let end = offset
                .checked_add(level_bytes)
                .ok_or("Offset overflow")?;

            levels_data.push(
                scalars[offset..end]
                    .chunks_exact(FIELD_SIZE)
                    .map(Scalar::from_le_bytes_mod_order)
                    .collect(),
            );

            offset = end;
            level_size /= 2;
        }

        Ok(MerkleTree {
            levels_data,
            depth,
            next_index,
        })
    }

    /// Build a tree from indexed leaves in one bottom-up pass
    ///
    /// Input `leaves_data` is `[index: u32 LE, leaf: 32 bytes]` repeated.
    #[wasm_bindgen]
    pub fn build_from_leaves(
        depth: usize,
        zero_leaf_bytes: &[u8],
        leaves_data: &[u8],
    ) -> Result<MerkleTree, JsValue> {
        let zero = bytes_to_scalar(zero_leaf_bytes)?;
        Self::build_from_leaves_internal(depth, zero, leaves_data)
            .map_err(|e| JsValue::from_str(&e))
    }

    fn build_from_leaves_internal(
        depth: usize,
        zero: Scalar,
        leaves_data: &[u8],
    ) -> Result<MerkleTree, alloc::string::String> {
        if depth == 0 || depth > 32 {
            return Err("Depth must be between 1 and 32".into());
        }

        const ENTRY_SIZE: usize = FIELD_SIZE + 4;

        if !leaves_data.len().is_multiple_of(ENTRY_SIZE) {
            return Err("leaves_data length must be a multiple of 36".into());
        }

        let depth_u32 = u32::try_from(depth).expect("depth <= 32");
        let num_leaves = 1usize
            .checked_shl(depth_u32)
            .ok_or("Leaf count overflow")?;

        let mut levels_data = vec![vec![zero; num_leaves]];
        let mut max_index: Option<u32> = None;

        for chunk in leaves_data.chunks_exact(ENTRY_SIZE) {
            let index = u32::from_le_bytes(
                chunk[..4].try_into().map_err(|_| "Invalid index bytes")?,
            );
            let index_usize = usize::try_from(index).map_err(|_| "Index too large")?;

            if index_usize >= num_leaves {
                return Err(format!("Leaf index {} out of bounds", index));
            }

            levels_data[0][index_usize] = Scalar::from_le_bytes_mod_order(&chunk[4..]);
            max_index = Some(max_index.map_or(index, |m| m.max(index)));
        }

        for level in 0..depth {
            let parents: Vec<Scalar> = levels_data[level]
                .chunks(2)
                .map(|pair| poseidon2_compression(pair[0], pair[1]))
                .collect();
            levels_data.push(parents);
        }

        let next_index = match max_index {
            Some(idx) => u64::from(idx).checked_add(1).ok_or("Index overflow")?,
            None => 0,
        };

        Ok(MerkleTree {
            levels_data,
            depth,
            next_index,
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serialization::scalar_to_bytes;

    fn leaf(val: u64) -> Vec<u8> {
        scalar_to_bytes(&Scalar::from(val))
    }

    fn pack_entry(index: u32, val: u64) -> Vec<u8> {
        let mut entry = index.to_le_bytes().to_vec();
        entry.extend_from_slice(&leaf(val));
        entry
    }

    #[test]
    fn insert_at_index_zero_empty_tree() {
        let mut tree = MerkleTree::new(4).expect("new tree");
        let idx = tree.insert_at(&leaf(42), 0).expect("insert_at 0");
        assert_eq!(idx, 0);
        assert_eq!(tree.next_index(), 1);
    }

    #[test]
    fn insert_at_equals_next_index() {
        let mut tree = MerkleTree::new(4).expect("new tree");
        tree.insert(&leaf(1)).expect("insert 0");
        tree.insert(&leaf(2)).expect("insert 1");
        assert_eq!(tree.next_index(), 2);

        let idx = tree.insert_at(&leaf(3), 2).expect("insert_at 2");
        assert_eq!(idx, 2);
        assert_eq!(tree.next_index(), 3);
    }

    #[test]
    fn insert_at_beyond_next_index_errors() {
        let mut tree = MerkleTree::new(4).expect("new tree");
        let err = tree
            .insert_at_internal(Scalar::from(1u64), 1)
            .expect_err("should reject gap");
        assert!(err.contains("exceeds next_index"));
    }

    #[test]
    fn insert_at_overwrites_without_advancing() {
        let mut tree = MerkleTree::new(4).expect("new tree");
        tree.insert(&leaf(1)).expect("insert 0");
        tree.insert(&leaf(2)).expect("insert 1");
        tree.insert(&leaf(3)).expect("insert 2");

        let root_before = tree.root();
        let next_before = tree.next_index();

        tree.insert_at(&leaf(99), 1).expect("overwrite index 1");

        assert_eq!(tree.next_index(), next_before);
        assert_ne!(tree.root(), root_before);
    }

    #[test]
    fn insert_at_then_get_proof_matches_root() {
        let mut tree = MerkleTree::new(4).expect("new tree");
        tree.insert_at(&leaf(10), 0).expect("insert_at 0");
        tree.insert_at(&leaf(20), 1).expect("insert_at 1");

        let proof = tree.get_proof(0).expect("proof for 0");
        assert_eq!(proof.root(), tree.root());

        let proof = tree.get_proof(1).expect("proof for 1");
        assert_eq!(proof.root(), tree.root());
    }

    #[test]
    fn equivalence_insert_vs_insert_at() {
        let leaves: Vec<Vec<u8>> = (1..=5).map(leaf).collect();

        let mut sequential = MerkleTree::new(4).expect("new tree");
        for l in &leaves {
            sequential.insert(l).expect("insert");
        }

        let mut indexed = MerkleTree::new(4).expect("new tree");
        for (i, l) in leaves.iter().enumerate() {
            let idx = u32::try_from(i).expect("index fits u32");
            indexed.insert_at(l, idx).expect("insert_at");
        }

        assert_eq!(sequential.root(), indexed.root());
        assert_eq!(sequential.next_index(), indexed.next_index());
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let mut tree = MerkleTree::new(4).expect("new tree");
        tree.insert(&leaf(1)).expect("insert 0");
        tree.insert(&leaf(2)).expect("insert 1");
        tree.insert(&leaf(3)).expect("insert 2");

        let data = tree.serialize();
        let restored = MerkleTree::deserialize_internal(&data).expect("deserialize");

        assert_eq!(tree.root(), restored.root());
        assert_eq!(tree.next_index(), restored.next_index());
        assert_eq!(tree.depth(), restored.depth());
    }

    #[test]
    fn serialize_deserialize_with_insert_at() {
        let mut tree = MerkleTree::new(4).expect("new tree");
        tree.insert(&leaf(1)).expect("insert 0");
        tree.insert(&leaf(2)).expect("insert 1");
        tree.insert_at(&leaf(99), 0).expect("overwrite 0");

        let data = tree.serialize();
        let restored = MerkleTree::deserialize_internal(&data).expect("deserialize");

        assert_eq!(tree.root(), restored.root());
        assert_eq!(tree.next_index(), restored.next_index());
    }

    #[test]
    fn deserialize_empty_errors() {
        let err = MerkleTree::deserialize_internal(&[])
            .err()
            .expect("should reject empty");
        assert!(err.contains("too short"));
    }

    #[test]
    fn deserialize_invalid_depth_errors() {
        let mut data = vec![0u8; 12];
        data[..4].copy_from_slice(&0u32.to_le_bytes());
        let err = MerkleTree::deserialize_internal(&data)
            .err()
            .expect("should reject depth 0");
        assert!(err.contains("Depth"));
    }

    #[test]
    fn deserialize_truncated_errors() {
        let tree = MerkleTree::new(4).expect("new tree");
        let data = tree.serialize();
        let err = MerkleTree::deserialize_internal(&data[..data.len().saturating_sub(1)])
            .err()
            .expect("should reject truncated");
        assert!(err.contains("Expected"));
    }

    #[test]
    fn build_from_leaves_equivalence() {
        let zero = Scalar::from(0u64);

        let mut sequential = MerkleTree::new(4).expect("new tree");
        for v in 1..=5u64 {
            sequential.insert(&leaf(v)).expect("insert");
        }

        let leaves_data: Vec<u8> = (1..=5u64)
            .enumerate()
            .flat_map(|(i, v)| {
                let idx = u32::try_from(i).expect("index fits u32");
                pack_entry(idx, v)
            })
            .collect();

        let batch = MerkleTree::build_from_leaves_internal(4, zero, &leaves_data)
            .expect("build_from_leaves");

        assert_eq!(sequential.root(), batch.root());
        assert_eq!(sequential.next_index(), batch.next_index());
    }

    #[test]
    fn build_from_leaves_empty() {
        let zero = Scalar::from(0u64);

        let empty = MerkleTree::build_from_leaves_internal(4, zero, &[])
            .expect("build empty");
        let fresh = MerkleTree::new(4).expect("new tree");

        assert_eq!(empty.root(), fresh.root());
        assert_eq!(empty.next_index(), 0);
    }

    #[test]
    fn build_from_leaves_single() {
        let zero = Scalar::from(0u64);

        let batch = MerkleTree::build_from_leaves_internal(4, zero, &pack_entry(0, 42))
            .expect("build single");

        let mut single = MerkleTree::new(4).expect("new tree");
        single.insert(&leaf(42)).expect("insert");

        assert_eq!(batch.root(), single.root());
        assert_eq!(batch.next_index(), 1);
    }

    #[test]
    fn build_from_leaves_out_of_bounds() {
        let zero = Scalar::from(0u64);

        let err = MerkleTree::build_from_leaves_internal(4, zero, &pack_entry(16, 1))
            .err()
            .expect("should reject out of bounds");
        assert!(err.contains("out of bounds"));
    }

    #[test]
    fn build_from_leaves_invalid_length() {
        let zero = Scalar::from(0u64);

        let err = MerkleTree::build_from_leaves_internal(4, zero, &[0u8; 35])
            .err()
            .expect("should reject bad length");
        assert!(err.contains("multiple of 36"));
    }
}
