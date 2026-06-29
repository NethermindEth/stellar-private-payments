//! Sparse Merkle Tree utilities for WASM (no_std compatible)
//!
//! Provides sparse merkle tree functionality using BTreeMap for no_std
//! compatibility.
//!
//! Equivalent functionality to `circuits::test::utils::sparse_merkle_tree` in
//! the circuit crate. But without std dependencies: Bigint and Hashmap
//! dependencies mostly. SMT interface.

use alloc::{collections::BTreeMap, vec::Vec};

use anyhow::{Result, anyhow};
use zkhash::{ark_ff::PrimeField, fields::bn256::FpBN256 as Scalar};

use crate::{
    crypto::{poseidon2_compression, poseidon2_hash2_internal},
    serialization::{field_to_scalar, scalar_to_field},
};
use types::Field;

/// Poseidon2 hash for leaf nodes: Poseidon2(key, value, domain=1)
fn poseidon2_hash_leaf(key: Field, value: Field) -> Field {
    let key_s = field_to_scalar(&key);
    let value_s = field_to_scalar(&value);
    let hashed = poseidon2_hash2_internal(key_s, value_s, Some(Scalar::from(1u64)));
    scalar_to_field(&hashed)
}

fn field_to_key(field: &Field) -> [u8; 32] {
    field.to_le_bytes()
}

/// Split a field element into 256 bits (LSB first)
fn field_to_bits(field: &Field) -> Vec<bool> {
    let scalar = field_to_scalar(field);
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
    Leaf { key: Field, value: Field },
    /// Internal node containing (left_child_hash, right_child_hash)
    Internal { left: Field, right: Field },
}

/// Result of SMT find operation
#[derive(Clone, Debug)]
pub struct FindResult {
    /// Whether the key was found
    pub found: bool,
    /// Sibling hashes along the path
    pub siblings: Vec<Field>,
    /// The found value (if found)
    pub found_value: Field,
    /// The key that was not found (for collision detection)
    pub not_found_key: Field,
    /// The value at collision (if not found)
    pub not_found_value: Field,
    /// Whether the path ended at zero
    pub is_old0: bool,
}

/// Result of SMT operations (insert/update/delete)
#[derive(Clone, Debug)]
pub struct SMTResult {
    /// The old root before the operation
    pub old_root: Field,
    /// The new root after the operation
    pub new_root: Field,
    /// Sibling hashes along the path
    pub siblings: Vec<Field>,
    /// The old key
    pub old_key: Field,
    /// The old value
    pub old_value: Field,
    /// The new key
    pub new_key: Field,
    /// The new value
    pub new_value: Field,
    /// Whether the old value was zero
    pub is_old0: bool,
}

/// Sparse Merkle Tree using BTreeMap for no_std compatibility
pub struct SparseMerkleTree {
    /// Database storing nodes by their hash
    db: BTreeMap<[u8; 32], Node>,
    /// Current root hash
    root: Field,
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
            root: Field::ZERO,
        }
    }

    /// Get the current root
    pub fn root(&self) -> Field {
        self.root
    }

    /// Convert field to bytes for use as BTreeMap key
    fn field_to_key(s: &Field) -> [u8; 32] {
        field_to_key(s)
    }

    /// Get a node from the database
    fn get_node(&self, hash: &Field) -> Option<&Node> {
        if *hash == Field::ZERO {
            return Some(&Node::Empty);
        }
        self.db.get(&Self::field_to_key(hash))
    }

    /// Store a node in the database
    fn put_node(&mut self, hash: Field, node: Node) {
        if hash != Field::ZERO {
            self.db.insert(Self::field_to_key(&hash), node);
        }
    }

    /// Find a key in the tree
    pub fn find(&self, key: &Field) -> Result<FindResult, &'static str> {
        let key_bits = field_to_bits(key);
        let mut result = self.find_internal(key, &key_bits, &self.root, 0)?;
        result.siblings.reverse();
        Ok(result)
    }

    fn find_internal(
        &self,
        key: &Field,
        key_bits: &[bool],
        current_hash: &Field,
        level: usize,
    ) -> Result<FindResult, &'static str> {
        if level >= 256 {
            return Err("Maximum tree depth exceeded");
        }

        if *current_hash == Field::ZERO {
            return Ok(FindResult {
                found: false,
                siblings: Vec::new(),
                found_value: Field::ZERO,
                not_found_key: *key,
                not_found_value: Field::ZERO,
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
                        not_found_key: Field::ZERO,
                        not_found_value: Field::ZERO,
                        is_old0: false,
                    })
                } else {
                    Ok(FindResult {
                        found: false,
                        siblings: Vec::new(),
                        found_value: Field::ZERO,
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
                result.siblings.push(*sibling);
                Ok(result)
            }
            Some(Node::Empty) => Ok(FindResult {
                found: false,
                siblings: Vec::new(),
                found_value: Field::ZERO,
                not_found_key: *key,
                not_found_value: Field::ZERO,
                is_old0: true,
            }),
            None => Err("Node not found in database"),
        }
    }

    /// Insert a key-value pair
    pub fn insert(&mut self, key: &Field, value: &Field) -> Result<SMTResult, &'static str> {
        let find_result = self.find(key)?;

        if find_result.found {
            return Err("Key already exists");
        }

        let old_root = self.root;
        let key_bits = field_to_bits(key);

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
            let old_key_bits = field_to_bits(&find_result.not_found_key);

            // Find where the paths diverge
            let mut diverge_level = siblings.len();
            while diverge_level < 256 && old_key_bits[diverge_level] == key_bits[diverge_level] {
                siblings.push(Field::ZERO);
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

            current_hash = smt_hash_pair_field(left, right);
            self.put_node(current_hash, Node::Internal { left, right });
        }

        self.root = current_hash;

        // Trim trailing zeros from siblings for the result
        let mut result_siblings = siblings;
        while result_siblings.last() == Some(&Field::ZERO) {
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
    pub fn update(&mut self, key: &Field, new_value: &Field) -> Result<SMTResult, &'static str> {
        let find_result = self.find(key)?;

        if !find_result.found {
            return Err("Key does not exist");
        }

        let old_root = self.root;
        let old_value = find_result.found_value;
        let key_bits = field_to_bits(key);

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

            current_hash = smt_hash_pair_field(left, right);
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
pub struct WasmSparseMerkleTree {
    inner: SparseMerkleTree,
}

impl WasmSparseMerkleTree {
    /// Create a new empty sparse merkle tree
    pub fn new() -> WasmSparseMerkleTree {
        WasmSparseMerkleTree {
            inner: SparseMerkleTree::new(),
        }
    }

    /// Get the current root as bytes (32 bytes, Little-Endian)
    pub fn root(&self) -> Vec<u8> {
        self.inner.root().to_le_bytes().to_vec()
    }

    /// Insert a key-value pair into the tree
    ///
    /// # Arguments
    /// * `key_bytes` - Key as 32 bytes (Little-Endian)
    /// * `value_bytes` - Value as 32 bytes (Little-Endian)
    pub fn insert(&mut self, key_bytes: &[u8], value_bytes: &[u8]) -> Result<WasmSMTResult> {
        let key = bytes_to_field(key_bytes)?;
        let value = bytes_to_field(value_bytes)?;

        let result = self.inner.insert(&key, &value).map_err(|e| anyhow!(e))?;

        Ok(WasmSMTResult::from_result(&result))
    }

    /// Update a key's value in the tree
    pub fn update(&mut self, key_bytes: &[u8], new_value_bytes: &[u8]) -> Result<WasmSMTResult> {
        let key = bytes_to_field(key_bytes)?;
        let new_value = bytes_to_field(new_value_bytes)?;

        let result = self
            .inner
            .update(&key, &new_value)
            .map_err(|e| anyhow!(e))?;

        Ok(WasmSMTResult::from_result(&result))
    }

    /// Find a key in the tree and get a membership/non-membership proof
    pub fn find(&self, key_bytes: &[u8]) -> Result<WasmFindResult> {
        let key = bytes_to_field(key_bytes)?;

        let result = self.inner.find(&key).map_err(|e| anyhow!(e))?;

        Ok(WasmFindResult::from_result(&result, &self.inner.root()))
    }

    /// Get a proof for a key, padded to max_levels
    pub fn get_proof(&self, key_bytes: &[u8], max_levels: usize) -> Result<SMTProof> {
        let key = bytes_to_field(key_bytes)?;

        let find_result = self.inner.find(&key).map_err(|e| anyhow!(e))?;

        // Pad siblings to max_levels
        let mut siblings = find_result.siblings.clone();
        while siblings.len() < max_levels {
            siblings.push(Field::ZERO);
        }

        Ok(SMTProof {
            found: find_result.found,
            siblings: siblings.iter().flat_map(|s| s.to_le_bytes()).collect(),
            found_value: find_result.found_value.to_le_bytes().to_vec(),
            not_found_key: find_result.not_found_key.to_le_bytes().to_vec(),
            not_found_value: find_result.not_found_value.to_le_bytes().to_vec(),
            is_old0: find_result.is_old0,
            root: self.inner.root().to_le_bytes().to_vec(),
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

impl WasmSMTResult {
    /// Get the old root before the operation
    pub fn old_root(&self) -> Vec<u8> {
        self.old_root.clone()
    }

    /// Get the new root after the operation
    pub fn new_root(&self) -> Vec<u8> {
        self.new_root.clone()
    }

    /// Get siblings as flat bytes
    pub fn siblings(&self) -> Vec<u8> {
        self.siblings.clone()
    }

    /// Get number of siblings
    pub fn num_siblings(&self) -> usize {
        self.num_siblings
    }

    /// Get the old key
    pub fn old_key(&self) -> Vec<u8> {
        self.old_key.clone()
    }

    /// Get the old value
    pub fn old_value(&self) -> Vec<u8> {
        self.old_value.clone()
    }

    /// Get the new key
    pub fn new_key(&self) -> Vec<u8> {
        self.new_key.clone()
    }

    /// Get the new value
    pub fn new_value(&self) -> Vec<u8> {
        self.new_value.clone()
    }

    /// Whether old value was zero
    pub fn is_old0(&self) -> bool {
        self.is_old0
    }
}

impl WasmSMTResult {
    fn from_result(r: &SMTResult) -> Self {
        WasmSMTResult {
            old_root: r.old_root.to_le_bytes().to_vec(),
            new_root: r.new_root.to_le_bytes().to_vec(),
            siblings: r.siblings.iter().flat_map(|s| s.to_le_bytes()).collect(),
            old_key: r.old_key.to_le_bytes().to_vec(),
            old_value: r.old_value.to_le_bytes().to_vec(),
            new_key: r.new_key.to_le_bytes().to_vec(),
            new_value: r.new_value.to_le_bytes().to_vec(),
            is_old0: r.is_old0,
            num_siblings: r.siblings.len(),
        }
    }
}

/// Result of SMT find operation
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

impl WasmFindResult {
    /// Whether the key was found
    pub fn found(&self) -> bool {
        self.found
    }

    /// Get siblings as flat bytes
    pub fn siblings(&self) -> Vec<u8> {
        self.siblings.clone()
    }

    /// Get number of siblings
    pub fn num_siblings(&self) -> usize {
        self.num_siblings
    }

    /// Get found value (if found)
    pub fn found_value(&self) -> Vec<u8> {
        self.found_value.clone()
    }

    /// Get the key that was found at collision (if not found)
    pub fn not_found_key(&self) -> Vec<u8> {
        self.not_found_key.clone()
    }

    /// Get the value at collision (if not found)
    pub fn not_found_value(&self) -> Vec<u8> {
        self.not_found_value.clone()
    }

    /// Whether the path ended at zero
    pub fn is_old0(&self) -> bool {
        self.is_old0
    }

    /// Get the current root
    pub fn root(&self) -> Vec<u8> {
        self.root.clone()
    }
}

impl WasmFindResult {
    fn from_result(r: &FindResult, root: &Field) -> Self {
        WasmFindResult {
            found: r.found,
            siblings: r.siblings.iter().flat_map(|s| s.to_le_bytes()).collect(),
            found_value: r.found_value.to_le_bytes().to_vec(),
            not_found_key: r.not_found_key.to_le_bytes().to_vec(),
            not_found_value: r.not_found_value.to_le_bytes().to_vec(),
            is_old0: r.is_old0,
            root: root.to_le_bytes().to_vec(),
            num_siblings: r.siblings.len(),
        }
    }
}

fn smt_hash_pair_field(left: Field, right: Field) -> Field {
    let left_s = field_to_scalar(&left);
    let right_s = field_to_scalar(&right);
    let hashed = poseidon2_compression(left_s, right_s);
    scalar_to_field(&hashed)
}

fn bytes_to_field(bytes: &[u8]) -> Result<Field> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| anyhow!("expected 32 bytes"))?;
    Field::try_from_le_bytes(arr)
}

/// SMT Proof for circuit inputs
pub struct SMTProof {
    found: bool,
    siblings: Vec<u8>,
    found_value: Vec<u8>,
    not_found_key: Vec<u8>,
    not_found_value: Vec<u8>,
    is_old0: bool,
    root: Vec<u8>,
    num_siblings: usize,
}

impl SMTProof {
    /// Whether the key was found
    pub fn found(&self) -> bool {
        self.found
    }

    /// Get siblings as flat bytes (padded to max_levels)
    pub fn siblings(&self) -> Vec<u8> {
        self.siblings.clone()
    }

    /// Get number of siblings
    pub fn num_siblings(&self) -> usize {
        self.num_siblings
    }

    /// Get found value
    pub fn found_value(&self) -> Vec<u8> {
        self.found_value.clone()
    }

    /// Get not found key
    pub fn not_found_key(&self) -> Vec<u8> {
        self.not_found_key.clone()
    }

    /// Get not found value
    pub fn not_found_value(&self) -> Vec<u8> {
        self.not_found_value.clone()
    }

    /// Whether old value was zero
    pub fn is_old0(&self) -> bool {
        self.is_old0
    }

    /// Get root
    pub fn root(&self) -> Vec<u8> {
        self.root.clone()
    }
}

/// Compute Poseidon2 compression hash of two field elements
pub fn smt_hash_pair(left: &[u8], right: &[u8]) -> Result<Vec<u8>> {
    let l = bytes_to_field(left)?;
    let r = bytes_to_field(right)?;
    let result = smt_hash_pair_field(l, r);
    Ok(result.to_le_bytes().to_vec())
}

/// Compute Poseidon2 hash for leaf nodes: hash(key, value, 1)
pub fn smt_hash_leaf(key: &[u8], value: &[u8]) -> Result<Vec<u8>> {
    let k = bytes_to_field(key)?;
    let v = bytes_to_field(value)?;
    let result = poseidon2_hash_leaf(k, v);
    Ok(result.to_le_bytes().to_vec())
}
