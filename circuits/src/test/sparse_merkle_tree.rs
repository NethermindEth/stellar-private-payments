//! Sparse Merkle Tree implementation compatible with circomlibjs/smt.js
//!
//! This is a Rust port of the Sparse Merkle Tree implementation from:
//! - JavaScript: https://github.com/iden3/circomlibjs/blob/main/src/smt.js
//!
//! This implementation uses Poseidon2 hash function for compatibility with
//! circomlib circuits.

#![allow(clippy::arithmetic_side_effects)]
use anyhow::{Result, anyhow};
use num_bigint::BigUint;
use std::collections::HashMap;
use zkhash::{
    ark_ff::{BigInteger, Fp256, PrimeField},
    fields::bn256::FpBN256,
    poseidon2::{
        poseidon2::Poseidon2,
        poseidon2_instance_bn256::{POSEIDON2_BN256_PARAMS_2, POSEIDON2_BN256_PARAMS_3},
    },
};

/// Main function for testing
pub fn main() {
    let db = SMTMemDB::new();
    let root = BigUint::from(0u32);
    let mut tree = SparseMerkleTree::new(db, root);

    let key = BigUint::from(1u32);
    let value = BigUint::from(2u32);
    let _ = tree.update(&key, &value).expect("Update failed");
}
/// Poseidon2 hash function for 2 inputs (left, right) - hash0
pub fn poseidon2_hash_2(left: &BigUint, right: &BigUint) -> BigUint {
    let poseidon2 = Poseidon2::new(&POSEIDON2_BN256_PARAMS_2);

    // Convert BigUint to FpBN256
    let left_fp = Fp256::from(left.clone());
    let right_fp = Fp256::from(right.clone());

    let input = vec![left_fp, right_fp];
    let result = poseidon2.permutation(&input);

    // Convert result back to BigUint
    fp_bn256_to_big_uint(&result[0])
}

/// Poseidon2 hash function for 3 inputs (key, value, 1) - hash1 for leaf nodes
pub fn poseidon2_hash_3(key: &BigUint, value: &BigUint) -> BigUint {
    let poseidon2 = Poseidon2::new(&POSEIDON2_BN256_PARAMS_3);

    // Convert BigUint to FpBN256
    let key_fp = Fp256::from(key.clone());
    let value_fp = Fp256::from(value.clone());
    let one_fp = FpBN256::from(1u64);

    let input = vec![key_fp, value_fp, one_fp];
    let result = poseidon2.permutation(&input);

    // Convert result back to BigUint
    fp_bn256_to_big_uint(&result[0])
}

/// Convert FpBN256 to BigUint
fn fp_bn256_to_big_uint(fp: &FpBN256) -> BigUint {
    // Convert FpBN256 to bytes and then to BigUint
    let bytes = fp.into_bigint().to_bytes_be();
    BigUint::from_bytes_be(&bytes)
}

/// Database trait for SMT storage
pub trait SMTDatabase {
    /// Get a value from the database
    fn get(&self, key: &BigUint) -> Option<Vec<BigUint>>;
    /// Set a value in the database
    fn set(&mut self, key: BigUint, value: Vec<BigUint>);
    /// Delete a value from the database
    fn delete(&mut self, key: &BigUint);
    /// Get the current root
    fn get_root(&self) -> BigUint;
    /// Set the current root
    fn set_root(&mut self, root: BigUint);
    /// Insert multiple values
    fn multi_ins(&mut self, inserts: Vec<(BigUint, Vec<BigUint>)>);
    /// Delete multiple values
    fn multi_del(&mut self, deletes: Vec<BigUint>);
}

/// In-memory database implementation
pub struct SMTMemDB {
    data: HashMap<BigUint, Vec<BigUint>>, // key -> [value, sibling1, sibling2, ...]
    root: BigUint,
}

impl SMTMemDB {
    /// Create a new in-memory database
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
            root: BigUint::from(0u32),
        }
    }
}
impl Default for SMTMemDB {
    fn default() -> Self {
        Self::new()
    }
}

impl SMTDatabase for SMTMemDB {
    fn get(&self, key: &BigUint) -> Option<Vec<BigUint>> {
        self.data.get(key).cloned()
    }

    fn set(&mut self, key: BigUint, value: Vec<BigUint>) {
        self.data.insert(key, value);
    }

    fn delete(&mut self, key: &BigUint) {
        self.data.remove(key);
    }

    fn get_root(&self) -> BigUint {
        self.root.clone()
    }

    fn set_root(&mut self, root: BigUint) {
        self.root = root;
    }

    fn multi_ins(&mut self, inserts: Vec<(BigUint, Vec<BigUint>)>) {
        for (key, value) in inserts {
            self.data.insert(key, value);
        }
    }

    fn multi_del(&mut self, deletes: Vec<BigUint>) {
        for key in deletes {
            self.data.remove(&key);
        }
    }
}

/// Sparse Merkle Tree implementation matching circomlibjs/smt.js
pub struct SparseMerkleTree<DB: SMTDatabase> {
    db: DB,
    root: BigUint,
}

/// Result of SMT operations
#[derive(Debug, Clone)]
pub struct SMTResult {
    /// The old root before the operation
    pub old_root: BigUint,
    /// The new root after the operation
    pub new_root: BigUint,
    /// Sibling hashes along the path
    pub siblings: Vec<BigUint>,
    /// The old key
    pub old_key: BigUint,
    /// The old value
    pub old_value: BigUint,
    /// The new key
    pub new_key: BigUint,
    /// The new value
    pub new_value: BigUint,
    /// Whether the old value was zero
    pub is_old0: bool,
}

/// Find result for internal operations
#[derive(Debug, Clone)]
pub struct FindResult {
    /// Whether the key was found
    pub found: bool,
    /// Sibling hashes along the path
    pub siblings: Vec<BigUint>,
    /// The found value
    pub found_value: BigUint,
    /// The key that was not found (for collision detection)
    pub not_found_key: BigUint,
    /// The value that was not found
    pub not_found_value: BigUint,
    /// Whether the old value was zero
    pub is_old0: bool,
}

impl<DB: SMTDatabase> SparseMerkleTree<DB> {
    /// Create a new Sparse Merkle Tree
    pub fn new(db: DB, root: BigUint) -> Self {
        Self { db, root }
    }

    /// Get the current root
    pub fn root(&self) -> &BigUint {
        &self.root
    }

    /// Split key into bits (256 bits total)
    /// This should match the JavaScript implementation which uses Scalar.bits()
    fn split_bits(&self, key: &BigUint) -> Vec<bool> {
        let mut bits = Vec::with_capacity(256);
        let mut key = key.clone();

        // Extract bits from LSB to MSB (same as JavaScript Scalar.bits())
        for _ in 0..256 {
            bits.push(key.bit(0));
            key >>= 1;
        }

        bits
    }

    /// Update a key-value pair in the tree
    pub fn update(&mut self, key: &BigUint, new_value: &BigUint) -> Result<SMTResult> {
        let res_find = self.find(key)?;
        let mut res = SMTResult {
            old_root: self.root.clone(),
            new_root: BigUint::from(0u32),
            siblings: res_find.siblings.clone(),
            old_key: key.clone(),
            old_value: res_find.found_value.clone(),
            new_key: key.clone(),
            new_value: new_value.clone(),
            is_old0: res_find.is_old0,
        };

        let mut inserts = Vec::new();
        let mut deletes = Vec::new();

        let rt_old = poseidon2_hash_3(key, &res_find.found_value);
        let rt_new = poseidon2_hash_3(key, new_value);
        inserts.push((
            rt_new.clone(),
            vec![BigUint::from(1u32), key.clone(), new_value.clone()],
        ));
        deletes.push(rt_old.clone());

        let key_bits = self.split_bits(key);
        let mut current_rt_old = rt_old;
        let mut current_rt_new = rt_new;

        for level in (0..res_find.siblings.len()).rev() {
            let sibling = &res_find.siblings[level];
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

            current_rt_old = poseidon2_hash_2(&old_node[0], &old_node[1]);
            current_rt_new = poseidon2_hash_2(&new_node[0], &new_node[1]);
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
    pub fn delete(&mut self, key: &BigUint) -> Result<SMTResult> {
        let res_find = self.find(key)?;
        if !res_find.found {
            return Err(anyhow!("Key does not exist"));
        }

        let mut res = SMTResult {
            old_root: self.root.clone(),
            new_root: BigUint::from(0u32),
            siblings: Vec::new(),
            old_key: key.clone(),
            old_value: res_find.found_value.clone(),
            new_key: key.clone(),
            new_value: BigUint::from(0u32),
            is_old0: false,
        };

        let mut deletes = Vec::new();
        let mut inserts = Vec::new();
        let mut rt_old = poseidon2_hash_3(key, &res_find.found_value);
        let mut rt_new;
        deletes.push(rt_old.clone());

        let key_bits = self.split_bits(key);
        let mut mixed = false;

        if !res_find.siblings.is_empty() {
            if let Some(record) = self.db.get(&res_find.siblings[res_find.siblings.len() - 1]) {
                if record.len() == 3 && record[0] == BigUint::from(1u32) {
                    mixed = false;
                    res.old_key = record[1].clone();
                    res.old_value = record[2].clone();
                    res.is_old0 = false;
                    rt_new = res_find.siblings[res_find.siblings.len() - 1].clone();
                } else if record.len() == 2 {
                    mixed = true;
                    res.old_key = key.clone();
                    res.old_value = BigUint::from(0u32);
                    res.is_old0 = true;
                    rt_new = BigUint::from(0u32);
                } else {
                    return Err(anyhow!("Invalid node. Database corrupted"));
                }
            } else {
                return Err(anyhow!("Sibling not found"));
            }
        } else {
            rt_new = BigUint::from(0u32);
            res.old_key = key.clone();
            res.is_old0 = true;
        }

        for level in (0..res_find.siblings.len()).rev() {
            let mut new_sibling = res_find.siblings[level].clone();
            if level == res_find.siblings.len() - 1 && !res.is_old0 {
                new_sibling = BigUint::from(0u32);
            }
            let old_sibling = res_find.siblings[level].clone();

            if key_bits[level] {
                rt_old = poseidon2_hash_2(&old_sibling, &rt_old);
            } else {
                rt_old = poseidon2_hash_2(&rt_old, &old_sibling);
            }
            deletes.push(rt_old.clone());

            if new_sibling != BigUint::from(0u32) {
                mixed = true;
            }

            if mixed {
                res.siblings.insert(0, res_find.siblings[level].clone());
                let new_node = if key_bits[level] {
                    vec![new_sibling, rt_new.clone()]
                } else {
                    vec![rt_new.clone(), new_sibling]
                };
                rt_new = poseidon2_hash_2(&new_node[0], &new_node[1]);
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
    pub fn insert(&mut self, key: &BigUint, value: &BigUint) -> Result<SMTResult> {
        let mut res = SMTResult {
            old_root: self.root.clone(),
            new_root: BigUint::from(0u32),
            siblings: Vec::new(),
            old_key: key.clone(),
            old_value: BigUint::from(0u32),
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
        let mut rt_old = BigUint::from(0u32);
        let mut added_one = false;

        if !res_find.is_old0 {
            let old_key_bits = self.split_bits(&res_find.not_found_key);
            let mut i = res.siblings.len();
            while i < old_key_bits.len() && old_key_bits[i] == new_key_bits[i] {
                res.siblings.push(BigUint::from(0u32));
                i += 1;
            }
            rt_old = poseidon2_hash_3(&res_find.not_found_key, &res_find.not_found_value);
            res.siblings.push(rt_old.clone());
            added_one = true;
            mixed = false;
        } else if !res.siblings.is_empty() {
            mixed = true;
            rt_old = BigUint::from(0u32);
        }

        let mut inserts = Vec::new();
        let mut deletes = Vec::new();

        let mut rt = poseidon2_hash_3(key, value);
        inserts.push((
            rt.clone(),
            vec![BigUint::from(1u32), key.clone(), value.clone()],
        ));

        for i in (0..res.siblings.len()).rev() {
            if i < res.siblings.len() - 1 && res.siblings[i] != BigUint::from(0u32) {
                mixed = true;
            }

            if mixed {
                let old_sibling = res_find.siblings[i].clone();
                if new_key_bits[i] {
                    rt_old = poseidon2_hash_2(&old_sibling, &rt_old);
                } else {
                    rt_old = poseidon2_hash_2(&rt_old, &old_sibling);
                }
                deletes.push(rt_old.clone());
            }

            let new_rt = if new_key_bits[i] {
                poseidon2_hash_2(&res.siblings[i], &rt)
            } else {
                poseidon2_hash_2(&rt, &res.siblings[i])
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
        while !res.siblings.is_empty()
            && res.siblings[res.siblings.len() - 1] == BigUint::from(0u32)
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
    pub fn find(&self, key: &BigUint) -> Result<FindResult> {
        let key_bits = self.split_bits(key);
        self._find(key, &key_bits, &self.root, 0)
    }

    /// Internal find method
    fn _find(
        &self,
        key: &BigUint,
        key_bits: &[bool],
        root: &BigUint,
        level: usize,
    ) -> Result<FindResult> {
        if *root == BigUint::from(0u32) {
            return Ok(FindResult {
                found: false,
                siblings: Vec::new(),
                found_value: BigUint::from(0u32),
                not_found_key: key.clone(),
                not_found_value: BigUint::from(0u32),
                is_old0: true,
            });
        }

        if let Some(record) = self.db.get(root) {
            if record.len() == 3 && record[0] == BigUint::from(1u32) {
                if record[1] == *key {
                    Ok(FindResult {
                        found: true,
                        siblings: Vec::new(),
                        found_value: record[2].clone(),
                        not_found_key: BigUint::from(0u32),
                        not_found_value: BigUint::from(0u32),
                        is_old0: false,
                    })
                } else {
                    Ok(FindResult {
                        found: false,
                        siblings: Vec::new(),
                        found_value: BigUint::from(0u32),
                        not_found_key: record[1].clone(),
                        not_found_value: record[2].clone(),
                        is_old0: false,
                    })
                }
            } else if record.len() == 2 {
                let mut res = if !key_bits[level] {
                    self._find(key, key_bits, &record[0], level + 1)?
                } else {
                    self._find(key, key_bits, &record[1], level + 1)?
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

/// Create a new empty SMT with an in-memory database
pub fn new_mem_empty_trie() -> SparseMerkleTree<SMTMemDB> {
    let db = SMTMemDB::new();
    let root = db.get_root();
    SparseMerkleTree::new(db, root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::{BigUint, ToBigInt};
    use std::str::FromStr;

    #[test]
    fn test_smt_creation() {
        let smt = new_mem_empty_trie();
        assert_eq!(*smt.root(), BigUint::from(0u32));
    }

    #[test]
    fn test_smt_insert() {
        let mut smt = new_mem_empty_trie();
        let key = BigUint::from(1u32);
        let value = BigUint::from(42u32);

        let result = smt.insert(&key, &value).expect("Insert method failed");
        assert_eq!(result.new_key, key);
        assert_eq!(result.new_value, value);
        assert!(result.is_old0); // First insert should be old0
    }

    #[test]
    fn test_smt_update() {
        let mut smt = new_mem_empty_trie();
        let key = BigUint::from(42u32);
        let value1 = BigUint::from(42u32);
        let value2 = BigUint::from(100u32);

        smt.insert(&key, &value1).expect("Insert method failed");
        let result = smt.update(&key, &value2).expect("Update method failed");

        assert_eq!(result.old_value, value1);
        assert_eq!(result.new_value, value2);
        assert!(!result.is_old0); // Update should not be old0
    }

    #[test]
    fn test_smt_delete() {
        let mut smt = new_mem_empty_trie();
        let key = BigUint::from(1u32);
        let value = BigUint::from(42u32);

        smt.insert(&key, &value).expect("Insert method failed");
        let result = smt.delete(&key).expect("Delete method failed");

        assert_eq!(result.old_key, key);
        assert_eq!(result.old_value, value);
    }

    #[test]
    fn test_smt_find() {
        let mut smt = new_mem_empty_trie();
        let key = BigUint::from(1u32);
        let value = BigUint::from(42u32);

        smt.insert(&key, &value).expect("Insert method failed");
        let find_result = smt.find(&key).expect("Find method failed");

        assert!(find_result.found);
        assert_eq!(find_result.found_value, value);
    }

    #[test]
    fn test_smt_multiple_keys() {
        let mut smt = new_mem_empty_trie();
        let keys = [
            BigUint::from(1u32),
            BigUint::from(2u32),
            BigUint::from(3u32),
            BigUint::from(100u32),
        ];

        for (i, key) in keys.iter().enumerate() {
            let value =
                BigUint::from(u32::try_from((i + 1) * 10).expect("Could not convert into u32"));
            smt.insert(key, &value).expect("Insert method failed");
        }

        for (i, key) in keys.iter().enumerate() {
            let find_result = smt.find(key).expect("Find method failed");
            assert!(find_result.found);
            assert_eq!(
                find_result.found_value,
                BigUint::from(u32::try_from((i + 1) * 10).expect("Could not convert into u32"))
            );
        }
    }

    #[test]
    fn test_smt_duplicate_insert() {
        let mut smt = new_mem_empty_trie();
        let key = BigUint::from(1u32);
        let value = BigUint::from(42u32);

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
        let key = BigUint::from(1u32);

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
        assert_eq!(*smt.root(), BigUint::from(0u32));

        let result = smt
            .insert(&BigUint::from(1u32), &BigUint::from(42u32))
            .expect("Insert method failed");

        // The root should change after insertion
        assert_ne!(result.old_root, result.new_root);
        assert_eq!(result.old_root, BigUint::from(0u32));

        // For the first insertion, the root should be
        let expected_root = BigUint::from_str(
            "16367784008464358864143154554494062552082491393210070322357217564588163898018",
        )
        .expect("Could not transform expected root into str");
        assert_eq!(result.new_root, expected_root);

        // Test update
        let result = smt
            .update(&BigUint::from(1u32), &BigUint::from(100u32))
            .expect("Update method failed");

        // Root should change after update
        assert_ne!(result.old_root, result.new_root);
        let expected_root = BigUint::from_str(
            "12569474685065514766800302626776627658362290519786081498087070427717152263146",
        )
        .expect("Could not transform expected root into str");
        assert_eq!(result.new_root, expected_root);

        // Verify we can find the updated value
        let find_result = smt.find(&BigUint::from(1u32)).expect("Find method failed");
        assert!(find_result.found);
        assert_eq!(find_result.found_value, BigUint::from(100u32));
        assert!(find_result.found);
        assert_eq!(find_result.found_value, BigUint::from(100u32));

        // Add a new leaf
        let result = smt
            .insert(&BigUint::from(2u32), &BigUint::from(324u32))
            .expect("Insert method failed");
        let expected_root = BigUint::from_str(
            "13721430606214473784210748322771049059587409085681494932247814833036842469183",
        )
        .expect("Could not transform expected root into str");
        assert_eq!(result.new_root, expected_root);
    }
    // Test to verify our SMT implementation works correctly
    // Expected values are extracted from the original JS implementation
    #[test]
    fn test_tree_proofs() {
        let mut smt = new_mem_empty_trie();
        assert_eq!(*smt.root(), BigUint::from(0u32));

        // Add some leaves
        smt.insert(&BigUint::from(1u32), &BigUint::from(1u32))
            .expect("Insert method failed");

        let find_result = smt.find(&BigUint::from(1u32)).expect("Find method failed");
        assert!(find_result.found);
        assert_eq!(find_result.found_value, BigUint::from(1u32));
        assert_eq!(find_result.siblings.len(), 0);
        assert!(!find_result.is_old0);

        // Let's try to find a non-existent key
        let find_result = smt
            .find(&BigUint::from(999u32))
            .expect("Find method failed");
        assert!(!find_result.found);
        assert_eq!(find_result.found_value, BigUint::from(0u32));
        assert_eq!(find_result.siblings.len(), 0);
        assert!(!find_result.is_old0);

        // Add more keys
        for i in 2u32..100 {
            smt.insert(&BigUint::from(i), &BigUint::from(i))
                .expect("Insert method failed");
        }

        // Check that we can find some of the keys
        let find_result = smt.find(&BigUint::from(77u32)).expect("Find method failed");
        assert!(find_result.found);
        assert_eq!(find_result.found_value, BigUint::from(77u32));
        assert_eq!(find_result.siblings.len(), 7);
        assert_eq!(
            find_result.siblings,
            vec![
                BigUint::from_str(
                    "18001364035378701276654838573729843872118344251098890017664318456831338682915"
                )
                .expect("Could not transform sibling into str"),
                BigUint::from_str(
                    "7038461515186380356972482065826990678027071056420028822404624728029290741398"
                )
                .expect("Could not transform sibling into str"),
                BigUint::from_str(
                    "5355661679688155050582380201632249214542300996120959660326266586645038859069"
                )
                .expect("Could not transform sibling into str"),
                BigUint::from_str(
                    "10932817550203138464236988095552506649318094587459797132194816589551233877274"
                )
                .expect("Could not transform sibling into str"),
                BigUint::from_str(
                    "12415874803161218002586616801064519780202140362773818607137499639372156553670"
                )
                .expect("Could not transform sibling into str"),
                BigUint::from_str(
                    "10575429519408550180427558328500068421272775679345567502048077733404168359774"
                )
                .expect("Could not transform sibling into str"),
                BigUint::from_str(
                    "2497489782201357981070733885197437403126039517543044119147834407389467335082"
                )
                .expect("Could not transform sibling into str"),
            ]
        );
        assert!(!find_result.is_old0);

        // Look for a non-existing key
        let find_result = smt
            .find(&BigUint::from(127u32))
            .expect("Find method failed");
        assert!(!find_result.found);
        assert_eq!(find_result.found_value, BigUint::from(0u32));
        assert_eq!(find_result.not_found_key, BigUint::from(63u32));
        assert_eq!(find_result.siblings.len(), 6);
        assert_eq!(
            find_result.siblings,
            vec![
                BigUint::from_str(
                    "18001364035378701276654838573729843872118344251098890017664318456831338682915"
                )
                .expect("Could not transform sibling into str"),
                BigUint::from_str(
                    "16670196950377750979639744727913904867276363859476671003203442710920257775644"
                )
                .expect("Could not transform sibling into str"),
                BigUint::from_str(
                    "2656865691394026186020538621074834161764236767099567445743020690179155608304"
                )
                .expect("Could not transform sibling into str"),
                BigUint::from_str(
                    "15135662244973144170490539328743418723015464256278866695178079470229676468740"
                )
                .expect("Could not transform sibling into str"),
                BigUint::from_str(
                    "2214982880516384550536262847617704529824432811971065318643115114470961110593"
                )
                .expect("Could not transform sibling into str"),
                BigUint::from_str(
                    "16589074329529517589291571372694136384503643071367722157138405341606810121079"
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
        let hash_result = poseidon2_hash_3(&BigUint::from(0u32), &BigUint::from(1u32));
        let hash_result2 = poseidon2_hash_2(&BigUint::from(0u32), &BigUint::from(1u32));

        type Scalar = FpBN256;
        // T = 2
        let poseidon2 = Poseidon2::new(&POSEIDON2_BN256_PARAMS_2);
        let input: Vec<Scalar> = vec![Scalar::from(0u64), Scalar::from(1u64)];
        let perm = poseidon2.permutation(&input);

        assert_eq!(
            perm[0].to_string(),
            hash_result2
                .to_bigint()
                .expect("Could not transform Poseidon outputs to BigInts")
                .to_string()
        );

        // T = 3
        let poseidon2 = Poseidon2::new(&POSEIDON2_BN256_PARAMS_3);
        let input: Vec<Scalar> = vec![Scalar::from(0u64), Scalar::from(1u64), Scalar::from(1u64)];
        let perm = poseidon2.permutation(&input);
        assert_eq!(
            perm[0].to_string(),
            hash_result
                .to_bigint()
                .expect("Could not transform Poseidon inputs to BigInts")
                .to_string()
        );
    }
}
