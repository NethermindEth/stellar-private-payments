//! Sparse Merkle Tree implementation compatible with circomlibjs/smt.js
//!
//! This is a Rust port of the Sparse Merkle Tree implementation from:
//! - JavaScript: https://github.com/iden3/circomlibjs/blob/main/src/smt.js
//!
//! This implementation uses Poseidon2 hash function for compatibility with
//! circomlib circuits.
use crate::test::utils::general::{
    poseidon2_compression as poseidon2_compression_bn256, poseidon2_hash2 as poseidon2_hash2_bn256,
};
use anyhow::{Result, anyhow};
use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use std::collections::HashMap;
use std::ops::Shr;
use zkhash::{
    ark_ff::{BigInteger, PrimeField},
    fields::bn256::FpBN256,
};
/// Reduce a num_bigint::BigInt modulo the BN256 field modulus and convert to FpBN256.
/// Circom circuits operate inside the BN256 scalar field, so every BigInt we hash must be reduced.
fn big_int_to_fp(x: &BigInt) -> FpBN256 {
    // Get the field modulus as a num_bigint::BigInt
    let modulus_bytes = FpBN256::MODULUS.to_bytes_be();
    let modulus_bigint = BigInt::from_bytes_be(num_bigint::Sign::Plus, &modulus_bytes);

    // Floor-mod reduce into [0, modulus)
    let reduced = x.mod_floor(&modulus_bigint);

    // Convert non-negative BigInt to BigUint, then into FpBN256
    let (_sign, bytes) = reduced.to_bytes_be();
    let as_biguint = BigUint::from_bytes_be(&bytes);

    FpBN256::from(as_biguint)
}

/// Poseidon2 hash of two field elements. Optimized compression mode. For use with BigInts.
/// Only to be used with inner nodes of the tree
pub fn poseidon2_compression_sparse(left: &BigInt, right: &BigInt) -> BigInt {
    let left_fp = big_int_to_fp(left);
    let right_fp = big_int_to_fp(right);

    let perm = poseidon2_compression_bn256(left_fp, right_fp);

    fp_bn256_to_big_int(&perm)
}

/// Poseidon2 hash function for 3 inputs (key, value, 1) - hash1 for leaf nodes
/// Mirrors circomlibjs "hash1" so a root generated here matches the JS prover/test tooling.
pub fn poseidon2_hash3_sparse(key: &BigInt, value: &BigInt) -> BigInt {
    let key_fp = big_int_to_fp(key);
    let value_fp = big_int_to_fp(value);
    let one_fp = FpBN256::from(1u64);

    let result = poseidon2_hash2_bn256(key_fp, value_fp, Some(one_fp));

    fp_bn256_to_big_int(&result)
}

/// Convert FpBN256 to BigInt
fn fp_bn256_to_big_int(fp: &FpBN256) -> BigInt {
    let bytes = fp.into_bigint().to_bytes_be();
    BigInt::from_bytes_be(num_bigint::Sign::Plus, &bytes)
}

/// Database trait for SMT storage
pub trait SMTDatabase {
    /// Get a value from the database
    fn get(&self, key: &BigInt) -> Option<Vec<BigInt>>;
    /// Set a value in the database
    #[allow(dead_code)]
    fn set(&mut self, key: BigInt, value: Vec<BigInt>);
    /// Delete a value from the database
    #[allow(dead_code)]
    fn delete(&mut self, key: &BigInt);
    /// Get the current root
    fn get_root(&self) -> BigInt;
    /// Set the current root
    fn set_root(&mut self, root: BigInt);
    /// Insert multiple values
    fn multi_ins(&mut self, inserts: Vec<(BigInt, Vec<BigInt>)>);
    /// Delete multiple values
    fn multi_del(&mut self, deletes: Vec<BigInt>);
}

/// In-memory database implementation
/// Stores every node (leaves and internal nodes) as raw BigInt vectors, matching circomlibjs layout.
pub struct SMTMemDB {
    data: HashMap<BigInt, Vec<BigInt>>, // key -> [value, sibling1, sibling2, ...]
    root: BigInt,
}

impl SMTMemDB {
    /// Create a new in-memory database
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
            root: BigInt::from(0u32),
        }
    }
}
impl Default for SMTMemDB {
    fn default() -> Self {
        Self::new()
    }
}

impl SMTDatabase for SMTMemDB {
    fn get(&self, key: &BigInt) -> Option<Vec<BigInt>> {
        self.data.get(key).cloned()
    }

    fn set(&mut self, key: BigInt, value: Vec<BigInt>) {
        self.data.insert(key, value);
    }

    fn delete(&mut self, key: &BigInt) {
        self.data.remove(key);
    }

    fn get_root(&self) -> BigInt {
        self.root.clone()
    }

    fn set_root(&mut self, root: BigInt) {
        self.root = root;
    }

    fn multi_ins(&mut self, inserts: Vec<(BigInt, Vec<BigInt>)>) {
        for (key, value) in inserts {
            self.data.insert(key, value);
        }
    }

    fn multi_del(&mut self, deletes: Vec<BigInt>) {
        for key in deletes {
            self.data.remove(&key);
        }
    }
}

/// Sparse Merkle Tree implementation matching circomlibjs/smt.js
/// Provides insert/update/delete/find helpers that operate entirely over BigInts so test harnesses
/// can generate witnesses identical to the JavaScript reference implementation.
pub struct SparseMerkleTree<DB: SMTDatabase> {
    db: DB,
    root: BigInt,
}

/// Result of SMT operations
#[derive(Debug, Clone)]
pub struct SMTResult {
    /// The old root before the operation
    pub old_root: BigInt,
    /// The new root after the operation
    pub new_root: BigInt,
    /// Sibling hashes along the path
    pub siblings: Vec<BigInt>,
    /// The old key
    pub old_key: BigInt,
    /// The old value
    pub old_value: BigInt,
    /// The new key
    pub new_key: BigInt,
    /// The new value
    pub new_value: BigInt,
    /// Whether the old value was zero
    pub is_old0: bool,
}

/// Find result for internal operations
#[derive(Debug, Clone)]
pub struct FindResult {
    /// Whether the key was found
    pub found: bool,
    /// Sibling hashes along the path
    pub siblings: Vec<BigInt>,
    /// The found value
    pub found_value: BigInt,
    /// The key that was not found (for collision detection)
    pub not_found_key: BigInt,
    /// The value that was not found
    pub not_found_value: BigInt,
    /// Whether the old value was zero
    pub is_old0: bool,
}

impl<DB: SMTDatabase> SparseMerkleTree<DB> {
    /// Create a new Sparse Merkle Tree
    pub fn new(db: DB, root: BigInt) -> Self {
        Self { db, root }
    }

    /// Get the current root
    pub fn root(&self) -> &BigInt {
        &self.root
    }

    /// Split key into bits (256 bits total)
    /// This should match the JavaScript implementation which uses Scalar.bits()
    /// so we traverse identical paths for a given key.
    fn split_bits(&self, key: &BigInt) -> Vec<bool> {
        let mut bits = Vec::with_capacity(256);
        let mut key = key.clone();

        // Extract bits from LSB to MSB (same as JavaScript Scalar.bits())
        for _ in 0..256 {
            bits.push(key.bit(0));
            key = key.shr(1u32);
        }

        bits
    }

    /// Update a key-value pair in the tree
    /// Recomputes all nodes along the path and persists them in the backing database.
    /// This mirrors circomlibjs' update logic where we first delete the old leaf and then
    /// rebuild the path with the new value while tracking every intermediate node for witnesses.
    pub fn update(&mut self, key: &BigInt, new_value: &BigInt) -> Result<SMTResult> {
        let res_find = self.find(key)?;
        let mut res = SMTResult {
            old_root: self.root.clone(),
            new_root: BigInt::from(0u32),
            siblings: res_find.siblings.clone(),
            old_key: key.clone(),
            old_value: res_find.found_value.clone(),
            new_key: key.clone(),
            new_value: new_value.clone(),
            is_old0: res_find.is_old0,
        };

        let mut inserts = Vec::new();
        let mut deletes = Vec::new();

        let rt_old = poseidon2_hash3_sparse(key, &res_find.found_value);
        let rt_new = poseidon2_hash3_sparse(key, new_value);
        inserts.push((
            rt_new.clone(),
            vec![BigInt::from(1u32), key.clone(), new_value.clone()],
        ));
        deletes.push(rt_old.clone());

        let key_bits = self.split_bits(key);
        let mut current_rt_old = rt_old;
        let mut current_rt_new = rt_new;

        for level in (0..res_find.siblings.len()).rev() {
            let sibling = &res_find.siblings[level];
            // Rebuild nodes from the bottom up; depending on the bit we decide left/right order.
            let (old_node, new_node) = if key_bits[level] {
                (
                    vec![sibling.clone(), current_rt_old.clone()],
                    vec![sibling.clone(), current_rt_new.clone()],
                )
            } else {
                (
                    vec![current_rt_old.clone(), sibling.clone()],
                    vec![current_rt_new.clone(), sibling.clone()],
                )
            };

            current_rt_old = poseidon2_compression_sparse(&old_node[0], &old_node[1]);
            current_rt_new = poseidon2_compression_sparse(&new_node[0], &new_node[1]);
            deletes.push(current_rt_old.clone());
            inserts.push((current_rt_new.clone(), new_node));
        }

        res.new_root = current_rt_new.clone();

        self.db.multi_del(deletes);
        self.db.multi_ins(inserts);
        self.db.set_root(current_rt_new.clone());
        self.root = current_rt_new;

        Ok(res)
    }

    /// Delete a key from the tree
    /// Handles both sparse branches (single child) and mixed branches (two populated children).
    /// The logic follows smt.js closely: collapse empty branches while keeping collision nodes.
    pub fn delete(&mut self, key: &BigInt) -> Result<SMTResult> {
        let res_find = self.find(key)?;
        if !res_find.found {
            return Err(anyhow!("Key does not exist"));
        }

        let mut res = SMTResult {
            old_root: self.root.clone(),
            new_root: BigInt::from(0u32),
            siblings: Vec::new(),
            old_key: key.clone(),
            old_value: res_find.found_value.clone(),
            new_key: key.clone(),
            new_value: BigInt::from(0u32),
            is_old0: false,
        };

        let mut deletes = Vec::new();
        let mut inserts = Vec::new();
        let mut rt_old = poseidon2_hash3_sparse(key, &res_find.found_value);
        let mut rt_new;
        deletes.push(rt_old.clone());

        let key_bits = self.split_bits(key);
        let mut mixed = false;

        if let Some(last_sibling) = res_find.siblings.last() {
            if let Some(record) = self.db.get(last_sibling) {
                if record.len() == 3 && record[0] == BigInt::from(1u32) {
                    mixed = false;
                    res.old_key = record[1].clone();
                    res.old_value = record[2].clone();
                    res.is_old0 = false;
                    rt_new = last_sibling.clone();
                } else if record.len() == 2 {
                    mixed = true;
                    res.old_key = key.clone();
                    res.old_value = BigInt::from(0u32);
                    res.is_old0 = true;
                    rt_new = BigInt::from(0u32);
                } else {
                    return Err(anyhow!("Invalid node. Database corrupted"));
                }
            } else {
                return Err(anyhow!("Sibling not found"));
            }
        } else {
            rt_new = BigInt::from(0u32);
            res.old_key = key.clone();
            res.is_old0 = true;
        }

        for level in (0..res_find.siblings.len()).rev() {
            let mut new_sibling = res_find.siblings[level].clone();
            if Some(level) == res_find.siblings.len().checked_sub(1) && !res.is_old0 {
                new_sibling = BigInt::from(0u32);
            }
            let old_sibling = res_find.siblings[level].clone();

            // Remove the old branch hash because the leaf is being deleted.
            if key_bits[level] {
                rt_old = poseidon2_compression_sparse(&old_sibling, &rt_old);
            } else {
                rt_old = poseidon2_compression_sparse(&rt_old, &old_sibling);
            }
            deletes.push(rt_old.clone());

            if new_sibling != BigInt::from(0u32) {
                mixed = true;
            }

            if mixed {
                // Once we hit a mixed branch we need to keep rebuilding upwards.
                res.siblings.insert(0, res_find.siblings[level].clone());
                let new_node = if key_bits[level] {
                    vec![new_sibling, rt_new.clone()]
                } else {
                    vec![rt_new.clone(), new_sibling]
                };
                rt_new = poseidon2_compression_sparse(&new_node[0], &new_node[1]);
                inserts.push((rt_new.clone(), new_node));
            }
        }

        self.db.multi_ins(inserts);
        self.db.set_root(rt_new.clone());
        self.root = rt_new.clone();
        self.db.multi_del(deletes);

        res.new_root = rt_new;
        res.old_root = rt_old;

        Ok(res)
    }

    /// Insert a new key-value pair
    /// Builds any missing intermediate nodes so the resulting tree mirrors the JS SMT.
    pub fn insert(&mut self, key: &BigInt, value: &BigInt) -> Result<SMTResult> {
        let mut res = SMTResult {
            old_root: self.root.clone(),
            new_root: BigInt::from(0u32),
            siblings: Vec::new(),
            old_key: key.clone(),
            old_value: BigInt::from(0u32),
            new_key: key.clone(),
            new_value: value.clone(),
            is_old0: false,
        };
        res.old_root = self.root.clone();
        let new_key_bits = self.split_bits(key);
        let res_find = self.find(key)?;

        if res_find.found {
            return Err(anyhow!("Key already exists"));
        }

        res.siblings = res_find.siblings.clone();
        let mut mixed = false;
        let mut rt_old = BigInt::from(0u32);
        let mut added_one = false;

        if !res_find.is_old0 {
            let old_key_bits = self.split_bits(&res_find.not_found_key);
            let mut i = res.siblings.len();
            while i < old_key_bits.len() && old_key_bits[i] == new_key_bits[i] {
                res.siblings.push(BigInt::from(0u32));
                i = i.saturating_add(1);
            }
            rt_old = poseidon2_hash3_sparse(&res_find.not_found_key, &res_find.not_found_value);
            res.siblings.push(rt_old.clone());
            added_one = true;
            mixed = false;
        } else if !res.siblings.is_empty() {
            mixed = true;
            rt_old = BigInt::from(0u32);
        }

        let mut inserts = Vec::new();
        let mut deletes = Vec::new();

        let mut rt = poseidon2_hash3_sparse(key, value);
        inserts.push((
            rt.clone(),
            vec![BigInt::from(1u32), key.clone(), value.clone()],
        ));

        for (i, sibling) in res.siblings.iter().enumerate().rev() {
            if i < res.siblings.len().saturating_sub(1) && sibling != &BigInt::from(0u32) {
                mixed = true;
            }

            if mixed {
                let old_sibling = res_find.siblings[i].clone();
                if new_key_bits[i] {
                    rt_old = poseidon2_compression_sparse(&old_sibling, &rt_old);
                } else {
                    rt_old = poseidon2_compression_sparse(&rt_old, &old_sibling);
                }
                deletes.push(rt_old.clone());
            }

            let new_rt = if new_key_bits[i] {
                poseidon2_compression_sparse(&res.siblings[i], &rt)
            } else {
                poseidon2_compression_sparse(&rt, &res.siblings[i])
            };
            let new_node = if new_key_bits[i] {
                vec![res.siblings[i].clone(), rt.clone()]
            } else {
                vec![rt.clone(), res.siblings[i].clone()]
            };
            inserts.push((new_rt.clone(), new_node));
            rt = new_rt;
        }

        if added_one {
            res.siblings.pop();
        }
        while res
            .siblings
            .last()
            .is_some_and(|s| s == &BigInt::from(0u32))
        {
            res.siblings.pop();
        }

        res.old_key = res_find.not_found_key;
        res.old_value = res_find.not_found_value;
        res.new_root = rt.clone();
        res.is_old0 = res_find.is_old0;

        self.db.multi_ins(inserts);
        self.db.set_root(rt.clone());
        self.root = rt;
        self.db.multi_del(deletes);
        Ok(res)
    }

    /// Find a key in the tree
    /// Returns the Merkle siblings required to reconstruct the path in circuits/tests.
    /// Also surfaces whether the path ended in a leaf collision (non-existent key with same path).
    pub fn find(&self, key: &BigInt) -> Result<FindResult> {
        let key_bits = self.split_bits(key);
        self._find(key, &key_bits, &self.root, 0)
    }

    /// Internal find method
    /// Recurses through the DB-stored nodes, replicating smt.js behavior exactly.
    /// It walks the tree using the bit-decomposed key, returning collision data when the search
    /// stops early (i.e. we reached a leaf whose key differs from the query).
    fn _find(
        &self,
        key: &BigInt,
        key_bits: &[bool],
        root: &BigInt,
        level: usize,
    ) -> Result<FindResult> {
        if *root == BigInt::from(0u32) {
            return Ok(FindResult {
                found: false,
                siblings: Vec::new(),
                found_value: BigInt::from(0u32),
                not_found_key: key.clone(),
                not_found_value: BigInt::from(0u32),
                is_old0: true,
            });
        }

        if let Some(record) = self.db.get(root) {
            if record.len() == 3 && record[0] == BigInt::from(1u32) {
                if record[1] == *key {
                    Ok(FindResult {
                        found: true,
                        siblings: Vec::new(),
                        found_value: record[2].clone(),
                        not_found_key: BigInt::from(0u32),
                        not_found_value: BigInt::from(0u32),
                        is_old0: false,
                    })
                } else {
                    Ok(FindResult {
                        found: false,
                        siblings: Vec::new(),
                        found_value: BigInt::from(0u32),
                        not_found_key: record[1].clone(),
                        not_found_value: record[2].clone(),
                        is_old0: false,
                    })
                }
            } else if record.len() == 2 {
                let next_level = level
                    .checked_add(1)
                    .expect("tree level overflow in sparse_merkle_tree::_find");
                let mut res = if !key_bits[level] {
                    self._find(key, key_bits, &record[0], next_level)?
                } else {
                    self._find(key, key_bits, &record[1], next_level)?
                };
                res.siblings.insert(
                    0,
                    if !key_bits[level] {
                        record[1].clone()
                    } else {
                        record[0].clone()
                    },
                );
                Ok(res)
            } else {
                Err(anyhow!("Invalid record format"))
            }
        } else {
            Err(anyhow!("Node not found in database"))
        }
    }
}

/// Proof data tailored for Circom inputs (BigInt-based).
#[derive(Clone, Debug)]
pub struct SMTProof {
    pub found: bool,
    pub siblings: Vec<BigInt>,
    pub found_value: BigInt,
    pub not_found_key: BigInt,
    pub not_found_value: BigInt,
    pub is_old0: bool,
    pub root: BigInt,
}

fn finalize_proof(tree: &SparseMerkleTree<SMTMemDB>, key: &BigInt, max_levels: usize) -> SMTProof {
    let find_result = tree.find(key).expect("Failed to find key");

    // Pad siblings with zeros to reach max_levels
    let mut siblings = find_result.siblings.clone();
    while siblings.len() < max_levels {
        siblings.push(BigInt::from(0u32));
    }

    SMTProof {
        found: find_result.found,
        siblings,
        found_value: find_result.found_value,
        not_found_key: find_result.not_found_key,
        not_found_value: find_result.not_found_value,
        is_old0: find_result.is_old0,
        root: tree.root().clone(),
    }
}

/// Prepare an SMT proof after pre-populating the tree with values 0..100.
pub fn prepare_smt_proof(key: &BigInt, max_levels: usize) -> SMTProof {
    let db = SMTMemDB::new();
    let mut smt = SparseMerkleTree::new(db, BigInt::from(0u32));

    // Tree can address at most 2^max_levels leaves.
    let max_leaves = 1usize
        .checked_shl(u32::try_from(max_levels).expect("Failed to cast max_levels to u32"))
        .unwrap_or(usize::MAX);

    let num_leaves = 100usize.min(max_leaves);

    for i in 0..num_leaves {
        let bi = BigInt::from(i);
        smt.insert(&bi, &bi).expect("Failed to insert key");
    }

    finalize_proof(&smt, key, max_levels)
}

/// Build a sparse SMT from `overrides` and return a proof for `key`.
/// `overrides` is (key, value) pairs already reduced modulo field.
pub fn prepare_smt_proof_with_overrides(
    key: &BigInt,
    overrides: &[(BigInt, BigInt)],
    max_levels: usize,
) -> SMTProof {
    let db = SMTMemDB::new();
    let mut smt = SparseMerkleTree::new(db, BigInt::from(0u32));

    for (k, v) in overrides {
        smt.insert(k, v).expect("SMT insert failed");
    }

    finalize_proof(&smt, key, max_levels)
}

/// Create a new empty SMT with an in-memory database
pub fn new_mem_empty_trie() -> SparseMerkleTree<SMTMemDB> {
    let db = SMTMemDB::new();
    let root = db.get_root();
    SparseMerkleTree::new(db, root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigInt;
    use std::str::FromStr;

    #[test]
    fn test_smt_creation() {
        let smt = new_mem_empty_trie();
        assert_eq!(*smt.root(), BigInt::from(0u32));
    }

    #[test]
    fn test_smt_insert() {
        let mut smt = new_mem_empty_trie();
        let key = BigInt::from(1u32);
        let value = BigInt::from(42u32);

        let result = smt.insert(&key, &value).expect("Insert method failed");
        assert_eq!(result.new_key, key);
        assert_eq!(result.new_value, value);
        assert!(result.is_old0); // First insert should be old0
    }

    #[test]
    fn test_smt_update() {
        let mut smt = new_mem_empty_trie();
        let key = BigInt::from(42u32);
        let value1 = BigInt::from(42u32);
        let value2 = BigInt::from(100u32);

        smt.insert(&key, &value1).expect("Insert method failed");
        let result = smt.update(&key, &value2).expect("Update method failed");

        assert_eq!(result.old_value, value1);
        assert_eq!(result.new_value, value2);
        assert!(!result.is_old0); // Update should not be old0
    }

    #[test]
    fn test_smt_delete() {
        let mut smt = new_mem_empty_trie();
        let key = BigInt::from(1u32);
        let value = BigInt::from(42u32);

        smt.insert(&key, &value).expect("Insert method failed");
        let result = smt.delete(&key).expect("Delete method failed");

        assert_eq!(result.old_key, key);
        assert_eq!(result.old_value, value);
    }

    #[test]
    fn test_smt_find() {
        let mut smt = new_mem_empty_trie();
        let key = BigInt::from(1u32);
        let value = BigInt::from(42u32);

        smt.insert(&key, &value).expect("Insert method failed");
        let find_result = smt.find(&key).expect("Find method failed");

        assert!(find_result.found);
        assert_eq!(find_result.found_value, value);
    }

    #[test]
    fn test_smt_multiple_keys() {
        let mut smt = new_mem_empty_trie();
        let keys = [
            BigInt::from(1u32),
            BigInt::from(2u32),
            BigInt::from(3u32),
            BigInt::from(100u32),
        ];

        for (i, key) in keys.iter().enumerate() {
            let value =
                BigInt::from(u32::try_from((i + 1) * 10).expect("Could not convert into u32"));
            smt.insert(key, &value).expect("Insert method failed");
        }

        for (i, key) in keys.iter().enumerate() {
            let find_result = smt.find(key).expect("Find method failed");
            assert!(find_result.found);
            assert_eq!(
                find_result.found_value,
                BigInt::from(u32::try_from((i + 1) * 10).expect("Could not convert into u32"))
            );
        }
    }

    #[test]
    fn test_smt_duplicate_insert() {
        let mut smt = new_mem_empty_trie();
        let key = BigInt::from(1u32);
        let value = BigInt::from(42u32);

        smt.insert(&key, &value).expect("Insert method failed");
        let result = smt.insert(&key, &value);

        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected error")
                .to_string()
                .contains("Key already exists")
        );
    }

    #[test]
    fn test_smt_delete_nonexistent() {
        let mut smt = new_mem_empty_trie();
        let key = BigInt::from(1u32);

        let result = smt.delete(&key);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("Expected error")
                .to_string()
                .contains("Key does not exist")
        );
    }

    // Test to verify our SMT implementation works correctly
    // Expected values are extracted from the original JS implementation
    #[test]
    fn test_new_tree() {
        let mut smt = new_mem_empty_trie();
        assert_eq!(*smt.root(), BigInt::from(0u32));

        let result = smt
            .insert(&BigInt::from(1u32), &BigInt::from(42u32))
            .expect("Insert method failed");

        // The root should change after insertion
        assert_ne!(result.old_root, result.new_root);
        assert_eq!(result.old_root, BigInt::from(0u32));

        // For the first insertion, the root should be
        let expected_root = BigInt::from_str(
            "16367784008464358864143154554494062552082491393210070322357217564588163898018",
        )
        .expect("Could not transform expected root into str");
        assert_eq!(result.new_root, expected_root);

        // Test update
        let result = smt
            .update(&BigInt::from(1u32), &BigInt::from(100u32))
            .expect("Update method failed");

        // Root should change after update
        assert_ne!(result.old_root, result.new_root);
        let expected_root = BigInt::from_str(
            "12569474685065514766800302626776627658362290519786081498087070427717152263146",
        )
        .expect("Could not transform expected root into str");
        assert_eq!(result.new_root, expected_root);

        // Verify we can find the updated value
        let find_result = smt.find(&BigInt::from(1u32)).expect("Find method failed");
        assert!(find_result.found);
        assert_eq!(find_result.found_value, BigInt::from(100u32));
        assert!(find_result.found);
        assert_eq!(find_result.found_value, BigInt::from(100u32));

        // Add a new leaf
        let result = smt
            .insert(&BigInt::from(2u32), &BigInt::from(324u32))
            .expect("Insert method failed");
        let expected_root = BigInt::from_str(
            "3902199042378325593738217753401508381332249645815458444537710669740236044308",
        )
        .expect("Could not transform expected root into str");
        assert_eq!(result.new_root, expected_root);
    }
    // Test to verify our SMT implementation works correctly
    // Expected values are extracted from the original JS implementation
    #[test]
    fn test_tree_proofs() {
        let mut smt = new_mem_empty_trie();
        assert_eq!(*smt.root(), BigInt::from(0u32));

        // Add some leaves
        smt.insert(&BigInt::from(1u32), &BigInt::from(1u32))
            .expect("Insert method failed");

        let find_result = smt.find(&BigInt::from(1u32)).expect("Find method failed");
        assert!(find_result.found);
        assert_eq!(find_result.found_value, BigInt::from(1u32));
        assert_eq!(find_result.siblings.len(), 0);
        assert!(!find_result.is_old0);

        // Let's try to find a non-existent key
        let find_result = smt.find(&BigInt::from(999u32)).expect("Find method failed");
        assert!(!find_result.found);
        assert_eq!(find_result.found_value, BigInt::from(0u32));
        assert_eq!(find_result.siblings.len(), 0);
        assert!(!find_result.is_old0);

        // Add more keys
        for i in 2u32..100 {
            smt.insert(&BigInt::from(i), &BigInt::from(i))
                .expect("Insert method failed");
        }

        // Check that we can find some of the keys
        let find_result = smt.find(&BigInt::from(77u32)).expect("Find method failed");
        assert!(find_result.found);
        assert_eq!(find_result.found_value, BigInt::from(77u32));
        assert_eq!(find_result.siblings.len(), 7);
        assert_eq!(
            find_result.siblings,
            vec![
                BigInt::from_str(
                    "13574531720454277968647792690830483941675832953896828594235298772144774821296"
                )
                .expect("Could not transform sibling into str"),
                BigInt::from_str(
                    "21822809487696252201955801325867744685997250399099680635153759270255930459663"
                )
                .expect("Could not transform sibling into str"),
                BigInt::from_str(
                    "2754153135680204810467520704946512020375848021263220175499310526007694622282"
                )
                .expect("Could not transform sibling into str"),
                BigInt::from_str(
                    "10988861352769866873810486166013377894828418574939430507195536235545006158559"
                )
                .expect("Could not transform sibling into str"),
                BigInt::from_str(
                    "8745716775239175067716679510281198940457427271514031231047764147465936999003"
                )
                .expect("Could not transform sibling into str"),
                BigInt::from_str(
                    "10575429519408550180427558328500068421272775679345567502048077733404168359774"
                )
                .expect("Could not transform sibling into str"),
                BigInt::from_str(
                    "2497489782201357981070733885197437403126039517543044119147834407389467335082"
                )
                .expect("Could not transform sibling into str"),
            ]
        );
        assert!(!find_result.is_old0);

        // Look for a non-existing key
        let find_result = smt.find(&BigInt::from(127u32)).expect("Find method failed");
        assert!(!find_result.found);
        assert_eq!(find_result.found_value, BigInt::from(0u32));
        assert_eq!(find_result.not_found_key, BigInt::from(63u32));
        assert_eq!(find_result.siblings.len(), 6);
        assert_eq!(
            find_result.siblings,
            vec![
                BigInt::from_str(
                    "13574531720454277968647792690830483941675832953896828594235298772144774821296"
                )
                .expect("Could not transform sibling into str"),
                BigInt::from_str(
                    "1861627833931474771540567070469758409892599524239975114190647783254280704182"
                )
                .expect("Could not transform sibling into str"),
                BigInt::from_str(
                    "6337427217730761905851800753670222511821931828056363511575004194996678792977"
                )
                .expect("Could not transform sibling into str"),
                BigInt::from_str(
                    "142387899434338503423141257579632358202650467916673674727273804791475103923"
                )
                .expect("Could not transform sibling into str"),
                BigInt::from_str(
                    "6499651114777582205199364701529028639517158867351868744143839420261663269505"
                )
                .expect("Could not transform sibling into str"),
                BigInt::from_str(
                    "4733877433413380505912252732407068279835546218946596975085447307151515063172"
                )
                .expect("Could not transform sibling into str"),
            ]
        );
        assert!(!find_result.is_old0);
    }

    #[test]
    fn test_hash_direct() {
        use zkhash::{
            fields::bn256::FpBN256,
            poseidon2::{
                poseidon2::Poseidon2,
                poseidon2_instance_bn256::{POSEIDON2_BN256_PARAMS_2, POSEIDON2_BN256_PARAMS_3},
            },
        };
        let hash_result = poseidon2_hash3_sparse(&BigInt::from(0u32), &BigInt::from(1u32));
        let hash_result2 = poseidon2_compression_sparse(&BigInt::from(0u32), &BigInt::from(1u32));

        type Scalar = FpBN256;
        // T = 2
        let poseidon2 = Poseidon2::new(&POSEIDON2_BN256_PARAMS_2);
        let input: Vec<Scalar> = vec![Scalar::from(0u64), Scalar::from(1u64)];
        let perm = poseidon2.permutation(&input);

        assert_eq!(perm[0].to_string(), hash_result2.to_string());

        // T = 3
        let poseidon2 = Poseidon2::new(&POSEIDON2_BN256_PARAMS_3);
        let input: Vec<Scalar> = vec![Scalar::from(0u64), Scalar::from(1u64), Scalar::from(1u64)];
        let perm = poseidon2.permutation(&input);
        assert_eq!(perm[0].to_string(), hash_result.to_string());
    }
}
