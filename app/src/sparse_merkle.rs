//! Sparse Merkle Tree utilities for WASM (no_std compatible)
//!
//! Provides sparse merkle tree functionality using BTreeMap for no_std
//! compatibility.
//!
//! Equivalent functionality to `circuits::test::utils::sparse_merkle_tree` in
//! the circuit crate. But without std dependencies: Bigint and Hashmap
//! dependencies mostly. SMT interface.

use alloc::{collections::BTreeMap, vec::Vec};

use wasm_bindgen::prelude::*;
use zkhash::{ark_ff::PrimeField, fields::bn256::FpBN256 as Scalar};

use crate::{
    crypto::{poseidon2_compression, poseidon2_hash2_internal},
    serialization::{bytes_to_scalar, scalar_to_bytes},
};

/// Poseidon2 hash for leaf nodes: Poseidon2(key, value, domain=1)
fn poseidon2_hash_leaf(key: Scalar, value: Scalar) -> Scalar {
    poseidon2_hash2_internal(key, value, Some(Scalar::from(1u64)))
}

/// Split a scalar into 256 bits (LSB first)
fn scalar_to_bits(scalar: &Scalar) -> Vec<bool> {
    let bigint = scalar.into_bigint();
    let mut bits = Vec::with_capacity(256);

    for limb in bigint.0.iter() {
        for i in 0..64 {
            bits.push((limb >> i) & 1 == 1);
        }
    }

    bits.truncate(256);
    bits
}

/// Node type in the sparse merkle tree
#[derive(Clone, Debug)]
enum Node {
    /// Empty node (represents zero)
    Empty,
    /// Leaf node containing (key, value)
    Leaf { key: Scalar, value: Scalar },
    /// Internal node containing (left_child_hash, right_child_hash)
    Internal { left: Scalar, right: Scalar },
}

/// Result of SMT find operation
#[derive(Clone, Debug)]
pub struct FindResult {
    /// Whether the key was found
    pub found: bool,
    /// Sibling hashes along the path
    pub siblings: Vec<Scalar>,
    /// The found value (if found)
    pub found_value: Scalar,
    /// The key that was not found (for collision detection)
    pub not_found_key: Scalar,
    /// The value at collision (if not found)
    pub not_found_value: Scalar,
    /// Whether the path ended at zero
    pub is_old0: bool,
}

/// Result of SMT operations (insert/update/delete)
#[derive(Clone, Debug)]
pub struct SMTResult {
    /// The old root before the operation
    pub old_root: Scalar,
    /// The new root after the operation
    pub new_root: Scalar,
    /// Sibling hashes along the path
    pub siblings: Vec<Scalar>,
    /// The old key
    pub old_key: Scalar,
    /// The old value
    pub old_value: Scalar,
    /// The new key
    pub new_key: Scalar,
    /// The new value
    pub new_value: Scalar,
    /// Whether the old value was zero
    pub is_old0: bool,
}

/// Sparse Merkle Tree using BTreeMap for no_std compatibility
pub struct SparseMerkleTree {
    /// Database storing nodes by their hash
    db: BTreeMap<[u8; 32], Node>,
    /// Current root hash
    root: Scalar,
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl SparseMerkleTree {
    /// Create a new empty sparse merkle tree
    pub fn new() -> Self {
        SparseMerkleTree {
            db: BTreeMap::new(),
            root: Scalar::from(0u64),
        }
    }

    /// Get the current root
    pub fn root(&self) -> Scalar {
        self.root
    }

    /// Convert scalar to bytes for use as BTreeMap key
    fn scalar_to_key(s: &Scalar) -> [u8; 32] {
        let mut key = [0u8; 32];
        let bytes = scalar_to_bytes(s);
        key.copy_from_slice(&bytes);
        key
    }

    /// Get a node from the database
    fn get_node(&self, hash: &Scalar) -> Option<&Node> {
        if *hash == Scalar::from(0u64) {
            return Some(&Node::Empty);
        }
        self.db.get(&Self::scalar_to_key(hash))
    }

    /// Store a node in the database
    fn put_node(&mut self, hash: Scalar, node: Node) {
        if hash != Scalar::from(0u64) {
            self.db.insert(Self::scalar_to_key(&hash), node);
        }
    }

    /// Find a key in the tree
    pub fn find(&self, key: &Scalar) -> Result<FindResult, &'static str> {
        let key_bits = scalar_to_bits(key);
        self.find_internal(key, &key_bits, &self.root, 0)
    }

    fn find_internal(
        &self,
        key: &Scalar,
        key_bits: &[bool],
        current_hash: &Scalar,
        level: usize,
    ) -> Result<FindResult, &'static str> {
        if *current_hash == Scalar::from(0u64) {
            return Ok(FindResult {
                found: false,
                siblings: Vec::new(),
                found_value: Scalar::from(0u64),
                not_found_key: *key,
                not_found_value: Scalar::from(0u64),
                is_old0: true,
            });
        }

        match self.get_node(current_hash) {
            Some(Node::Leaf {
                key: leaf_key,
                value: leaf_value,
            }) => {
                if leaf_key == key {
                    Ok(FindResult {
                        found: true,
                        siblings: Vec::new(),
                        found_value: *leaf_value,
                        not_found_key: Scalar::from(0u64),
                        not_found_value: Scalar::from(0u64),
                        is_old0: false,
                    })
                } else {
                    Ok(FindResult {
                        found: false,
                        siblings: Vec::new(),
                        found_value: Scalar::from(0u64),
                        not_found_key: *leaf_key,
                        not_found_value: *leaf_value,
                        is_old0: false,
                    })
                }
            }
            Some(Node::Internal { left, right }) => {
                let (child, sibling) = if key_bits[level] {
                    (right, left)
                } else {
                    (left, right)
                };

                let next_level = level
                    .checked_add(1)
                    .ok_or("Level overflow in find_internal")?;
                let mut result = self.find_internal(key, key_bits, child, next_level)?;
                result.siblings.insert(0, *sibling);
                Ok(result)
            }
            Some(Node::Empty) => Ok(FindResult {
                found: false,
                siblings: Vec::new(),
                found_value: Scalar::from(0u64),
                not_found_key: *key,
                not_found_value: Scalar::from(0u64),
                is_old0: true,
            }),
            None => Err("Node not found in database"),
        }
    }

    /// Insert a key-value pair
    pub fn insert(&mut self, key: &Scalar, value: &Scalar) -> Result<SMTResult, &'static str> {
        let find_result = self.find(key)?;

        if find_result.found {
            return Err("Key already exists");
        }

        let old_root = self.root;
        let key_bits = scalar_to_bits(key);

        // Create the new leaf
        let new_leaf_hash = poseidon2_hash_leaf(*key, *value);
        self.put_node(
            new_leaf_hash,
            Node::Leaf {
                key: *key,
                value: *value,
            },
        );

        // Build the path from leaf to root
        let mut current_hash = new_leaf_hash;
        let mut siblings = find_result.siblings.clone();

        // If there's a collision (not_found_key != 0 and is_old0 == false), we need to
        // extend the path
        if !find_result.is_old0 {
            let old_key_bits = scalar_to_bits(&find_result.not_found_key);

            // Find where the paths diverge
            let mut diverge_level = siblings.len();
            while diverge_level < 256 && old_key_bits[diverge_level] == key_bits[diverge_level] {
                siblings.push(Scalar::from(0u64));
                diverge_level = diverge_level.saturating_add(1);
            }

            // Add the old leaf as a sibling at the divergence point
            let old_leaf_hash =
                poseidon2_hash_leaf(find_result.not_found_key, find_result.not_found_value);
            siblings.push(old_leaf_hash);
        }

        // Build path from bottom to top
        for (level, sibling) in siblings.iter().enumerate().rev() {
            let (left, right) = if key_bits[level] {
                (*sibling, current_hash)
            } else {
                (current_hash, *sibling)
            };

            current_hash = poseidon2_compression(left, right);
            self.put_node(current_hash, Node::Internal { left, right });
        }

        self.root = current_hash;

        // Trim trailing zeros from siblings for the result
        let mut result_siblings = siblings;
        while result_siblings.last() == Some(&Scalar::from(0u64)) {
            result_siblings.pop();
        }
        // Remove the collision leaf if we added one
        if !find_result.is_old0 && !result_siblings.is_empty() {
            result_siblings.pop();
        }

        Ok(SMTResult {
            old_root,
            new_root: self.root,
            siblings: result_siblings,
            old_key: find_result.not_found_key,
            old_value: find_result.not_found_value,
            new_key: *key,
            new_value: *value,
            is_old0: find_result.is_old0,
        })
    }

    /// Update a key's value
    pub fn update(&mut self, key: &Scalar, new_value: &Scalar) -> Result<SMTResult, &'static str> {
        let find_result = self.find(key)?;

        if !find_result.found {
            return Err("Key does not exist");
        }

        let old_root = self.root;
        let old_value = find_result.found_value;
        let key_bits = scalar_to_bits(key);

        // Create the new leaf
        let new_leaf_hash = poseidon2_hash_leaf(*key, *new_value);
        self.put_node(
            new_leaf_hash,
            Node::Leaf {
                key: *key,
                value: *new_value,
            },
        );

        // Build path from bottom to top
        let mut current_hash = new_leaf_hash;
        for (level, sibling) in find_result.siblings.iter().enumerate().rev() {
            let (left, right) = if key_bits[level] {
                (*sibling, current_hash)
            } else {
                (current_hash, *sibling)
            };

            current_hash = poseidon2_compression(left, right);
            self.put_node(current_hash, Node::Internal { left, right });
        }

        self.root = current_hash;

        Ok(SMTResult {
            old_root,
            new_root: self.root,
            siblings: find_result.siblings,
            old_key: *key,
            old_value,
            new_key: *key,
            new_value: *new_value,
            is_old0: false,
        })
    }
}

/// WASM-friendly Sparse Merkle Tree wrapper
#[wasm_bindgen]
pub struct WasmSparseMerkleTree {
    inner: SparseMerkleTree,
}

#[wasm_bindgen]
impl WasmSparseMerkleTree {
    /// Create a new empty sparse merkle tree
    #[wasm_bindgen(constructor)]
    pub fn new() -> WasmSparseMerkleTree {
        WasmSparseMerkleTree {
            inner: SparseMerkleTree::new(),
        }
    }

    /// Get the current root as bytes (32 bytes, Little-Endian)
    #[wasm_bindgen]
    pub fn root(&self) -> Vec<u8> {
        scalar_to_bytes(&self.inner.root())
    }

    /// Insert a key-value pair into the tree
    ///
    /// # Arguments
    /// * `key_bytes` - Key as 32 bytes (Little-Endian)
    /// * `value_bytes` - Value as 32 bytes (Little-Endian)
    #[wasm_bindgen]
    pub fn insert(
        &mut self,
        key_bytes: &[u8],
        value_bytes: &[u8],
    ) -> Result<WasmSMTResult, JsValue> {
        let key = bytes_to_scalar(key_bytes)?;
        let value = bytes_to_scalar(value_bytes)?;

        let result = self.inner.insert(&key, &value).map_err(JsValue::from_str)?;

        Ok(WasmSMTResult::from_result(&result))
    }

    /// Update a key's value in the tree
    #[wasm_bindgen]
    pub fn update(
        &mut self,
        key_bytes: &[u8],
        new_value_bytes: &[u8],
    ) -> Result<WasmSMTResult, JsValue> {
        let key = bytes_to_scalar(key_bytes)?;
        let new_value = bytes_to_scalar(new_value_bytes)?;

        let result = self
            .inner
            .update(&key, &new_value)
            .map_err(JsValue::from_str)?;

        Ok(WasmSMTResult::from_result(&result))
    }

    /// Find a key in the tree and get a membership/non-membership proof
    #[wasm_bindgen]
    pub fn find(&self, key_bytes: &[u8]) -> Result<WasmFindResult, JsValue> {
        let key = bytes_to_scalar(key_bytes)?;

        let result = self.inner.find(&key).map_err(JsValue::from_str)?;

        Ok(WasmFindResult::from_result(&result, &self.inner.root()))
    }

    /// Get a proof for a key, padded to max_levels
    #[wasm_bindgen]
    pub fn get_proof(&self, key_bytes: &[u8], max_levels: usize) -> Result<WasmSMTProof, JsValue> {
        let key = bytes_to_scalar(key_bytes)?;

        let find_result = self.inner.find(&key).map_err(JsValue::from_str)?;

        // Pad siblings to max_levels
        let mut siblings = find_result.siblings.clone();
        while siblings.len() < max_levels {
            siblings.push(Scalar::from(0u64));
        }

        Ok(WasmSMTProof {
            found: find_result.found,
            siblings: siblings.iter().flat_map(scalar_to_bytes).collect(),
            found_value: scalar_to_bytes(&find_result.found_value),
            not_found_key: scalar_to_bytes(&find_result.not_found_key),
            not_found_value: scalar_to_bytes(&find_result.not_found_value),
            is_old0: find_result.is_old0,
            root: scalar_to_bytes(&self.inner.root()),
            num_siblings: siblings.len(),
        })
    }
}

impl Default for WasmSparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of SMT operations (insert/update/delete)
#[wasm_bindgen]
pub struct WasmSMTResult {
    old_root: Vec<u8>,
    new_root: Vec<u8>,
    siblings: Vec<u8>,
    old_key: Vec<u8>,
    old_value: Vec<u8>,
    new_key: Vec<u8>,
    new_value: Vec<u8>,
    is_old0: bool,
    num_siblings: usize,
}

#[wasm_bindgen]
impl WasmSMTResult {
    /// Get the old root before the operation
    #[wasm_bindgen(getter)]
    pub fn old_root(&self) -> Vec<u8> {
        self.old_root.clone()
    }

    /// Get the new root after the operation
    #[wasm_bindgen(getter)]
    pub fn new_root(&self) -> Vec<u8> {
        self.new_root.clone()
    }

    /// Get siblings as flat bytes
    #[wasm_bindgen(getter)]
    pub fn siblings(&self) -> Vec<u8> {
        self.siblings.clone()
    }

    /// Get number of siblings
    #[wasm_bindgen(getter)]
    pub fn num_siblings(&self) -> usize {
        self.num_siblings
    }

    /// Get the old key
    #[wasm_bindgen(getter)]
    pub fn old_key(&self) -> Vec<u8> {
        self.old_key.clone()
    }

    /// Get the old value
    #[wasm_bindgen(getter)]
    pub fn old_value(&self) -> Vec<u8> {
        self.old_value.clone()
    }

    /// Get the new key
    #[wasm_bindgen(getter)]
    pub fn new_key(&self) -> Vec<u8> {
        self.new_key.clone()
    }

    /// Get the new value
    #[wasm_bindgen(getter)]
    pub fn new_value(&self) -> Vec<u8> {
        self.new_value.clone()
    }

    /// Whether old value was zero
    #[wasm_bindgen(getter)]
    pub fn is_old0(&self) -> bool {
        self.is_old0
    }
}

impl WasmSMTResult {
    fn from_result(r: &SMTResult) -> Self {
        WasmSMTResult {
            old_root: scalar_to_bytes(&r.old_root),
            new_root: scalar_to_bytes(&r.new_root),
            siblings: r.siblings.iter().flat_map(scalar_to_bytes).collect(),
            old_key: scalar_to_bytes(&r.old_key),
            old_value: scalar_to_bytes(&r.old_value),
            new_key: scalar_to_bytes(&r.new_key),
            new_value: scalar_to_bytes(&r.new_value),
            is_old0: r.is_old0,
            num_siblings: r.siblings.len(),
        }
    }
}

/// Result of SMT find operation
#[wasm_bindgen]
pub struct WasmFindResult {
    found: bool,
    siblings: Vec<u8>,
    found_value: Vec<u8>,
    not_found_key: Vec<u8>,
    not_found_value: Vec<u8>,
    is_old0: bool,
    root: Vec<u8>,
    num_siblings: usize,
}

#[wasm_bindgen]
impl WasmFindResult {
    /// Whether the key was found
    #[wasm_bindgen(getter)]
    pub fn found(&self) -> bool {
        self.found
    }

    /// Get siblings as flat bytes
    #[wasm_bindgen(getter)]
    pub fn siblings(&self) -> Vec<u8> {
        self.siblings.clone()
    }

    /// Get number of siblings
    #[wasm_bindgen(getter)]
    pub fn num_siblings(&self) -> usize {
        self.num_siblings
    }

    /// Get found value (if found)
    #[wasm_bindgen(getter)]
    pub fn found_value(&self) -> Vec<u8> {
        self.found_value.clone()
    }

    /// Get the key that was found at collision (if not found)
    #[wasm_bindgen(getter)]
    pub fn not_found_key(&self) -> Vec<u8> {
        self.not_found_key.clone()
    }

    /// Get the value at collision (if not found)
    #[wasm_bindgen(getter)]
    pub fn not_found_value(&self) -> Vec<u8> {
        self.not_found_value.clone()
    }

    /// Whether the path ended at zero
    #[wasm_bindgen(getter)]
    pub fn is_old0(&self) -> bool {
        self.is_old0
    }

    /// Get the current root
    #[wasm_bindgen(getter)]
    pub fn root(&self) -> Vec<u8> {
        self.root.clone()
    }
}

impl WasmFindResult {
    fn from_result(r: &FindResult, root: &Scalar) -> Self {
        WasmFindResult {
            found: r.found,
            siblings: r.siblings.iter().flat_map(scalar_to_bytes).collect(),
            found_value: scalar_to_bytes(&r.found_value),
            not_found_key: scalar_to_bytes(&r.not_found_key),
            not_found_value: scalar_to_bytes(&r.not_found_value),
            is_old0: r.is_old0,
            root: scalar_to_bytes(root),
            num_siblings: r.siblings.len(),
        }
    }
}

/// SMT Proof for circuit inputs
#[wasm_bindgen]
pub struct WasmSMTProof {
    found: bool,
    siblings: Vec<u8>,
    found_value: Vec<u8>,
    not_found_key: Vec<u8>,
    not_found_value: Vec<u8>,
    is_old0: bool,
    root: Vec<u8>,
    num_siblings: usize,
}

#[wasm_bindgen]
impl WasmSMTProof {
    /// Whether the key was found
    #[wasm_bindgen(getter)]
    pub fn found(&self) -> bool {
        self.found
    }

    /// Get siblings as flat bytes (padded to max_levels)
    #[wasm_bindgen(getter)]
    pub fn siblings(&self) -> Vec<u8> {
        self.siblings.clone()
    }

    /// Get number of siblings
    #[wasm_bindgen(getter)]
    pub fn num_siblings(&self) -> usize {
        self.num_siblings
    }

    /// Get found value
    #[wasm_bindgen(getter)]
    pub fn found_value(&self) -> Vec<u8> {
        self.found_value.clone()
    }

    /// Get not found key
    #[wasm_bindgen(getter)]
    pub fn not_found_key(&self) -> Vec<u8> {
        self.not_found_key.clone()
    }

    /// Get not found value
    #[wasm_bindgen(getter)]
    pub fn not_found_value(&self) -> Vec<u8> {
        self.not_found_value.clone()
    }

    /// Whether old value was zero
    #[wasm_bindgen(getter)]
    pub fn is_old0(&self) -> bool {
        self.is_old0
    }

    /// Get root
    #[wasm_bindgen(getter)]
    pub fn root(&self) -> Vec<u8> {
        self.root.clone()
    }
}

/// Compute Poseidon2 compression hash of two field elements
#[wasm_bindgen]
pub fn smt_hash_pair(left: &[u8], right: &[u8]) -> Result<Vec<u8>, JsValue> {
    let l = bytes_to_scalar(left)?;
    let r = bytes_to_scalar(right)?;
    let result = poseidon2_compression(l, r);
    Ok(scalar_to_bytes(&result))
}

/// Compute Poseidon2 hash for leaf nodes: hash(key, value, 1)
#[wasm_bindgen]
pub fn smt_hash_leaf(key: &[u8], value: &[u8]) -> Result<Vec<u8>, JsValue> {
    let k = bytes_to_scalar(key)?;
    let v = bytes_to_scalar(value)?;
    let result = poseidon2_hash_leaf(k, v);
    Ok(scalar_to_bytes(&result))
}
