//! Sparse Merkle Tree implementation
//!
//! This is a Soroban-compatible port of the Sparse Merkle Tree implementation from:
//! - circuits/src/test/utils/sparse_merkle_tree.rs (Rust reference implementation)
//! - circomlibjs: <https://github.com/iden3/circomlibjs/blob/main/src/smt.js>
//!
//! This implementation uses Poseidon2 hash function for compatibility with the
//! circomlib circuits
//!
//! # Design Considerations
//!
//! This is a full on-chain implementation where all tree nodes are stored in contract storage.
//! While not the most cost-efficient approach, it provides:
//! - Easy interaction and verification for users
//! - Complete on-chain state for non-membership proofs
//! - Flexibility to migrate to IPFS-based storage later if needed
//!
//! For scalability with large blocked key lists, consider the hybrid approach from:
//! <https://www.newswise.com/pdf_docs/170903654855378_1-s2.0-S2096720923000519-main.pdf>
//! We still present this implementation, as it allows making the decision to switch to IPFS-based storage later if needed.

#![no_std]
use soroban_sdk::{
    Address, Env, U256, Vec, contract, contracterror, contractevent, contractimpl, contracttype,
    vec,
};
use soroban_utils::{poseidon2_compress, poseidon2_hash2};
#[contracttype]
#[derive(Clone, Debug)]
enum DataKey {
    Admin,
    Root,
    Node(U256), // Node hash -> U256 (value)
}

/// Result of a find operation in the sparse Merkle tree
#[contracttype]
#[derive(Clone, Debug)]
pub struct FindResult {
    /// Whether the key was found in the tree
    pub found: bool,
    /// Sibling hashes along the path from root to leaf
    pub siblings: Vec<U256>,
    /// Value associated with the key (if found), zero otherwise
    pub found_value: U256,
    /// Key at the collision point
    pub not_found_key: U256,
    /// Value at the collision point
    pub not_found_value: U256,
    /// True if the path ended at an empty branch, false if collision with existing leaf
    pub is_old0: bool,
}

// Errors
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotAuthorized = 1,
    KeyNotFound = 2,
    KeyAlreadyExists = 3,
    InvalidProof = 4,
    AlreadyInitialized = 5,
    NotInitialized = 6,
}

// Events
#[contractevent(topics = ["LeafInserted"])]
struct LeafInsertedEvent {
    key: U256,
    value: U256,
    root: U256,
}

#[contractevent(topics = ["LeafUpdated"])]
struct LeafUpdatedEvent {
    key: U256,
    old_value: U256,
    new_value: U256,
    root: U256,
}

#[contractevent(topics = ["LeafDeleted"])]
struct LeafDeletedEvent {
    key: U256,
    root: U256,
}

#[contract]
pub struct ASPNonMembership;

#[contractimpl]
impl ASPNonMembership {
    /// Initialize the contract with an admin address and an empty tree
    ///
    /// Sets up the contract with the specified admin and initializes an empty
    /// Sparse Merkle Tree with root = 0. This function can only be called once.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `admin` - Address that will have permission to modify the tree
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success, or `Error::AlreadyInitialized` if the contract
    /// has already been initialized.
    pub fn init(env: Env, admin: Address) -> Result<(), Error> {
        let store = env.storage().persistent();
        // Contract can only be initialized once
        if store.has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        store.set(&DataKey::Admin, &admin);
        // Initialize with empty root (zero)
        let zero = U256::from_u32(&env, 0u32);
        store.set(&DataKey::Root, &zero);
        Ok(())
    }

    /// Update the admin address
    ///
    /// Transfers administrative control to a new address. Requires authorization
    /// from the current admin.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `new_admin` - New address that will have permission to modify the tree
    pub fn update_admin(env: Env, new_admin: Address) {
        soroban_utils::update_admin(&env, &DataKey::Admin, &new_admin);
    }

    /// Hash a leaf node using Poseidon2
    ///
    /// Computes the hash for leaf nodes using Poseidon2 with three inputs:
    /// hash(key, value, 1). The domain separator of 1 distinguishes leaf nodes
    /// from internal nodes. Mirrors circomlibjs "hash1" function so roots generated
    /// here match the circuits.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `key` - Leaf key as U256
    /// * `value` - Leaf value as U256
    ///
    /// # Returns
    ///
    /// Returns the leaf hash as a U256 value
    fn hash_leaf(env: &Env, key: U256, value: U256) -> U256 {
        let one = U256::from_u32(env, 1u32);
        poseidon2_hash2(env, key, value, Some(one))
    }

    /// Hash an internal node using Poseidon2 compression
    ///
    /// Computes the hash for internal nodes using Poseidon2 compression mode
    /// with two inputs: hash(left, right). This is the standard hash function
    /// for inner nodes of the Sparse Merkle tree.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `left` - Left child hash as U256
    /// * `right` - Right child hash as U256
    ///
    /// # Returns
    ///
    /// Returns the internal node hash as a U256 value
    fn hash_internal(env: &Env, left: U256, right: U256) -> U256 {
        poseidon2_compress(env, left, right)
    }

    /// Split a key into 256 bits from LSB to MSB
    ///
    /// Extracts the binary representation of a key for tree path traversal.
    /// Bits are ordered from least significant (index 0) to most significant (index 255)
    /// to match the circuits implementation.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `key` - Key to split into bits
    ///
    /// # Returns
    ///
    /// Returns a vector of 256 boolean values representing the key's bits
    fn split_bits(env: &Env, key: &U256) -> Vec<bool> {
        let mut bits = Vec::new(env);
        let mut k = key.clone();
        let two = U256::from_u32(env, 2u32);

        for _ in 0..256 {
            let rem = k.rem_euclid(&two);
            bits.push_back(rem == U256::from_u32(env, 1u32));
            k = k.div(&two);
        }

        bits
    }

    /// Internal recursive find method
    ///
    /// Traverses the tree from the given root to find a key, collecting sibling hashes
    /// along the path. Returns detailed information about the search result including
    /// whether the key was found, collision information for non-membership proofs,
    /// and siblings required for witness generation.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `store` - Persistent storage reference
    /// * `key` - Key to search for
    /// * `key_bits` - Pre-computed bits of the key
    /// * `root` - Root hash to start search from
    /// * `level` - Current tree level (0 = root)
    ///
    /// # Returns
    ///
    /// Returns `Ok(FindResult)` containing search results and path information,
    /// or `Error::KeyNotFound` if database operations fail.
    fn find_key_internal(
        env: &Env,
        store: &soroban_sdk::storage::Persistent,
        key: &U256,
        key_bits: &Vec<bool>,
        root: &U256,
        level: u32,
    ) -> Result<FindResult, Error> {
        let zero = U256::from_u32(env, 0u32);
        // Empty tree
        if *root == zero {
            return Ok(FindResult {
                found: false,
                siblings: Vec::new(env),
                found_value: zero.clone(),
                not_found_key: key.clone(),
                not_found_value: zero.clone(),
                is_old0: true,
            });
        }

        // Get node from storage
        let node_key = DataKey::Node(root.clone());
        let node_data: Vec<U256> = store.get(&node_key).ok_or(Error::KeyNotFound)?;

        // Check if it's a leaf node (3 elements: [1, key, value])
        if node_data.len() == 3 && node_data.get(0).unwrap() == U256::from_u32(env, 1u32) {
            let stored_key = node_data.get(1).unwrap();
            let stored_value = node_data.get(2).unwrap();
            if stored_key == *key {
                // Key found
                return Ok(FindResult {
                    found: true,
                    siblings: Vec::new(env),
                    found_value: stored_value,
                    not_found_key: zero.clone(),
                    not_found_value: zero.clone(),
                    is_old0: false,
                });
            } else {
                // Different key at leaf (collision)
                return Ok(FindResult {
                    found: false,
                    siblings: Vec::new(env),
                    found_value: zero.clone(),
                    not_found_key: stored_key,
                    not_found_value: stored_value,
                    is_old0: false,
                });
            }
        } else if node_data.len() == 2 {
            // Internal node (2 elements: [left, right])
            let left = node_data.get(0).unwrap();
            let right = node_data.get(1).unwrap();

            let level_idx = level;
            let mut result = if !key_bits.get(level_idx).unwrap() {
                // Go left
                Self::find_key_internal(env, store, key, key_bits, &left, level + 1)?
            } else {
                // Go right
                Self::find_key_internal(env, store, key, key_bits, &right, level + 1)?
            };

            // Add sibling to path
            let sibling = if !key_bits.get(level_idx).unwrap() {
                right.clone()
            } else {
                left.clone()
            };
            result.siblings.push_front(sibling);

            return Ok(result);
        }
        Err(Error::KeyNotFound)
    }

    /// Find a key in the tree
    ///
    /// Public entry point for searching the tree. Returns comprehensive information
    /// about the key including whether it exists, its value, and the Merkle path
    /// siblings required for proof generation.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `key` - Key to search for in the tree
    ///
    /// # Returns
    ///
    /// Returns `Ok(FindResult)` containing whether the key was found, siblings along
    /// the path, and collision information for non-membership proofs, or an error
    /// if database operations fail.
    ///
    /// # Errors
    ///
    /// * `Error::KeyNotFound` - Database operations failed or invalid node structure
    pub fn find_key(env: Env, key: U256) -> Result<FindResult, Error> {
        let store = env.storage().persistent();
        let root: U256 = store
            .get(&DataKey::Root)
            .unwrap_or(U256::from_u32(&env, 0u32));
        let key_bits = Self::split_bits(&env, &key);
        Self::find_key_internal(&env, &store, &key, &key_bits, &root, 0u32)
    }

    /// Insert a new key-value pair into the tree
    ///
    /// Adds a new leaf to the Sparse Merkle tree, building any missing intermediate
    /// nodes. Handles collision cases where a new key shares a path prefix with an
    /// existing leaf by extending the tree depth. Requires admin authorization.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `key` - Key to insert
    /// * `value` - Value to associate with the key
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success, emitting a `LeafInsertedEvent` with the new root.
    ///
    /// # Errors
    ///
    /// * `Error::KeyAlreadyExists` - Key already exists in the tree
    /// * `Error::KeyNotFound` - Database operations failed
    pub fn insert_leaf(env: Env, key: U256, value: U256) -> Result<(), Error> {
        let store = env.storage().persistent();
        let admin: Address = store.get(&DataKey::Admin).unwrap();
        admin.require_auth();

        let root: U256 = store
            .get(&DataKey::Root)
            .unwrap_or(U256::from_u32(&env, 0u32));

        // Compute key bits
        let key_bits = Self::split_bits(&env, &key);

        // Find the key
        let find_result = Self::find_key_internal(&env, &store, &key, &key_bits, &root, 0u32)?;

        if find_result.found {
            return Err(Error::KeyAlreadyExists);
        }

        let zero = U256::from_u32(&env, 0u32);
        let mut siblings = find_result.siblings.clone();
        let mut mixed = false;
        let mut rt_old = zero.clone();
        let mut added_one = false;

        // Handle collision case: extend siblings for a common prefix and add old leaf
        if !find_result.is_old0 {
            let old_key_bits = Self::split_bits(&env, &find_result.not_found_key);
            let mut i = siblings.len();
            // Extend siblings with zeros for common prefix bits
            while i < old_key_bits.len()
                && i < key_bits.len()
                && old_key_bits.get(i).unwrap() == key_bits.get(i).unwrap()
            {
                siblings.push_back(zero.clone());
                i += 1;
            }
            rt_old = Self::hash_leaf(
                &env,
                find_result.not_found_key.clone(),
                find_result.not_found_value.clone(),
            );
            siblings.push_back(rt_old.clone());
            added_one = true;
            mixed = false;
        } else if !siblings.is_empty() {
            mixed = true;
            rt_old = zero.clone();
        }

        // Insert the new leaf
        let mut rt = Self::hash_leaf(&env, key.clone(), value.clone());
        let leaf_node = vec![&env, U256::from_u32(&env, 1u32), key.clone(), value.clone()];
        store.set(&DataKey::Node(rt.clone()), &leaf_node);

        // Build up the tree from leaf to root (process siblings in reverse)
        // Siblings are stored from root level (index 0) to leaf level (last index)
        let siblings_len = siblings.len();
        for (i, sibling) in siblings.iter().enumerate().rev() {
            // Check if we need to delete old nodes (mixed case)
            // Skip the last index if added_one=true (it's the old leaf, not an internal node)
            let is_last_added_leaf = added_one && (i == (siblings_len - 1) as usize);
            if !is_last_added_leaf
                && (i as u32) < siblings_len.saturating_sub(1)
                && sibling.clone() != zero
            {
                mixed = true;
            }

            if mixed && !is_last_added_leaf {
                let old_sibling = if (i as u32) < find_result.siblings.len() {
                    find_result.siblings.get(i as u32).unwrap().clone()
                } else {
                    zero.clone()
                };
                let bit = key_bits.get(i as u32).unwrap();
                rt_old = if bit {
                    Self::hash_internal(&env, old_sibling.clone(), rt_old.clone())
                } else {
                    Self::hash_internal(&env, rt_old.clone(), old_sibling.clone())
                };
                store.remove(&DataKey::Node(rt_old.clone()));
            }

            // Build a new internal node
            let bit = key_bits.get(i as u32).unwrap();
            let (left_hash, right_hash) = if bit {
                (sibling.clone(), rt.clone())
            } else {
                (rt.clone(), sibling.clone())
            };

            rt = Self::hash_internal(&env, left_hash.clone(), right_hash.clone());

            // Store internal node
            let internal_node = vec![&env, left_hash, right_hash];
            store.set(&DataKey::Node(rt.clone()), &internal_node);
        }

        // Remove the temporary sibling if we added one for collision
        if added_one {
            siblings.pop_back();
        }
        // Remove trailing zeros from siblings
        while !siblings.is_empty() {
            let last_idx = siblings.len() - 1;
            if siblings.get(last_idx).unwrap() == zero {
                siblings.pop_back();
            } else {
                break;
            }
        }

        // Update root
        store.set(&DataKey::Root, &rt);

        // Emit event
        LeafInsertedEvent {
            key: key.clone(),
            value: value.clone(),
            root: rt,
        }
        .publish(&env);

        Ok(())
    }

    /// Delete a key from the tree
    ///
    /// Removes a leaf from the Sparse Merkle tree, handling both sparse branches
    /// (single child) and mixed branches (two populated children). When a leaf is deleted,
    /// its sibling may be promoted to replace the parent node, collapsing the tree structure.
    /// Requires admin authorization.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `key` - Key to delete from the tree
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success, emitting a `LeafDeletedEvent` with the new root.
    ///
    /// # Errors
    ///
    /// * `Error::KeyNotFound` - Key does not exist in the tree or database operations failed
    pub fn delete_leaf(env: Env, key: U256) -> Result<(), Error> {
        let store = env.storage().persistent();
        let admin: Address = store.get(&DataKey::Admin).unwrap();
        admin.require_auth();
        let root: U256 = store.get(&DataKey::Root).unwrap();

        // Compute key bits once for both find and delete operations
        let key_bits = Self::split_bits(&env, &key);

        // Find the key
        let find_result = Self::find_key_internal(&env, &store, &key, &key_bits, &root, 0u32)?;

        if !find_result.found {
            return Err(Error::KeyNotFound);
        }

        let zero = U256::from_u32(&env, 0u32);
        let one = U256::from_u32(&env, 1u32);

        // Track nodes to delete (old path if any)
        let mut rt_old = Self::hash_leaf(&env, key.clone(), find_result.found_value.clone());
        store.remove(&DataKey::Node(rt_old.clone()));

        let mut rt_new: U256;
        let mut siblings_to_use = find_result.siblings.clone();

        // Check if the last sibling is a leaf that should be promoted
        if let Some(last_sibling) = find_result.siblings.last() {
            let node_key = DataKey::Node(last_sibling.clone());
            if let Some(node_data) = store.get::<DataKey, Vec<U256>>(&node_key) {
                // Check if it's a leaf node (3 elements: [1, key, value])
                if node_data.len() == 3 && node_data.get(0).unwrap() == one {
                    // Last sibling is a leaf - promote it
                    rt_new = last_sibling.clone();
                    // Remove the last sibling from the list since we're promoting it
                    siblings_to_use.pop_back();
                } else if node_data.len() == 2 {
                    // Last sibling is an internal node - replace with zero
                    rt_new = zero.clone();
                } else {
                    return Err(Error::KeyNotFound); // Invalid node
                }
            } else {
                return Err(Error::KeyNotFound); // Sibling not found
            }
        } else {
            // No siblings - The tree becomes empty
            rt_new = zero.clone();
        }

        // Rebuild the tree from the deletion point upwards
        let mut mixed = false;
        let siblings_len = siblings_to_use.len();

        for level_idx in 0..siblings_len {
            let level = siblings_len - 1 - level_idx; // Process from leaf to root
            let sibling = siblings_to_use.get(level).unwrap();

            // Use actual sibling value
            let new_sibling = sibling.clone();

            // Delete old internal node along the old path
            let bit = key_bits.get(level).unwrap();
            rt_old = if bit {
                Self::hash_internal(&env, sibling.clone(), rt_old)
            } else {
                Self::hash_internal(&env, rt_old, sibling.clone())
            };
            store.remove(&DataKey::Node(rt_old.clone()));

            // Check if we need to continue rebuilding
            if new_sibling != zero {
                mixed = true;
            }

            if mixed {
                // Build new internal node
                let (left_hash, right_hash) = if bit {
                    (new_sibling, rt_new.clone())
                } else {
                    (rt_new.clone(), new_sibling)
                };

                // Create and store new internal node
                rt_new = Self::hash_internal(&env, left_hash.clone(), right_hash.clone());
                let internal_node = vec![&env, left_hash, right_hash];
                store.set(&DataKey::Node(rt_new.clone()), &internal_node);
            }
        }

        // Update root
        store.set(&DataKey::Root, &rt_new);

        // Emit event
        LeafDeletedEvent {
            key: key.clone(),
            root: rt_new,
        }
        .publish(&env);

        Ok(())
    }

    /// Update a key-value pair in the tree
    ///
    /// Changes the value associated with an existing key. Recomputes all nodes along
    /// the path from the leaf to the root, removing old nodes and creating new ones.
    /// Requires admin authorization.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `key` - Key to update
    /// * `new_value` - New value to associate with the key
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success, emitting a `LeafUpdatedEvent` with the new root.
    ///
    /// # Errors
    ///
    /// * `Error::KeyNotFound` - Key does not exist in the tree or database operations failed
    pub fn update_leaf(env: Env, key: U256, new_value: U256) -> Result<(), Error> {
        let store = env.storage().persistent();
        let admin: Address = store.get(&DataKey::Admin).unwrap();
        admin.require_auth();
        let root: U256 = store
            .get(&DataKey::Root)
            .unwrap_or(U256::from_u32(&env, 0u32));

        // Compute key bits once
        let key_bits = Self::split_bits(&env, &key);

        // Find the key
        let find_result = Self::find_key_internal(&env, &store, &key, &key_bits, &root, 0u32)?;

        if !find_result.found {
            return Err(Error::KeyNotFound);
        }
        // Update the leaf
        let old_leaf_hash = Self::hash_leaf(&env, key.clone(), find_result.found_value.clone());
        let new_leaf_hash = Self::hash_leaf(&env, key.clone(), new_value.clone());
        // Update leaf node
        let leaf_node = vec![
            &env,
            U256::from_u32(&env, 1u32),
            key.clone(),
            new_value.clone(),
        ];
        store.set(&DataKey::Node(new_leaf_hash.clone()), &leaf_node);

        // Remove old leaf
        store.remove(&DataKey::Node(old_leaf_hash.clone()));

        // Rebuild path from leaf to root (process siblings in reverse)
        let mut current_hash = new_leaf_hash;
        let mut old_current_hash = old_leaf_hash;

        let siblings_len = find_result.siblings.len();
        for level_idx in 0..siblings_len {
            let level = siblings_len - 1 - level_idx; // Reverse: process from leaf to root
            let sibling = find_result.siblings.get(level).unwrap();
            let bit = key_bits.get(level).unwrap();

            let (left_hash, right_hash) = if bit {
                (sibling.clone(), current_hash)
            } else {
                (current_hash, sibling.clone())
            };

            let (old_left_hash, old_right_hash) = if bit {
                (sibling.clone(), old_current_hash)
            } else {
                (old_current_hash, sibling.clone())
            };

            current_hash = Self::hash_internal(&env, left_hash.clone(), right_hash.clone());
            old_current_hash = Self::hash_internal(&env, old_left_hash, old_right_hash);

            // Update internal node
            let internal_node = vec![&env, left_hash, right_hash];
            store.set(&DataKey::Node(current_hash.clone()), &internal_node);

            // Remove old internal node
            store.remove(&DataKey::Node(old_current_hash.clone()));
        }

        // Update root
        store.set(&DataKey::Root, &current_hash);

        // Emit event
        LeafUpdatedEvent {
            key: key.clone(),
            old_value: find_result.found_value,
            new_value: new_value.clone(),
            root: current_hash,
        }
        .publish(&env);

        Ok(())
    }

    /// Verify non-membership proof for a key
    ///
    /// Verifies that a key is NOT in the tree by checking the provided Merkle proof.
    /// The proof includes siblings along the path and collision information
    /// (not_found_key/value at the leaf). Reconstructs the root from the proof
    /// and compares it with the stored root.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `key` - Key to verify is not in the tree
    /// * `siblings` - Sibling hashes along the path from root to leaf
    /// * `not_found_key` - Key at the collision point (or queried key if empty path)
    /// * `not_found_value` - Value at the collision point (or zero if empty path)
    ///
    /// # Returns
    ///
    /// Returns `Ok(true)` if non-membership is verified, `Ok(false)` if the key
    /// actually exists in the tree.
    pub fn verify_non_membership(
        env: Env,
        key: U256,
        siblings: Vec<U256>,
        not_found_key: U256,
        not_found_value: U256,
    ) -> Result<bool, Error> {
        let store = env.storage().persistent();
        let root: U256 = store
            .get(&DataKey::Root)
            .unwrap_or(U256::from_u32(&env, 0u32));

        // Compute key bits once
        let key_bits = Self::split_bits(&env, &key);

        // Find the key
        let find_result = Self::find_key_internal(&env, &store, &key, &key_bits, &root, 0u32)?;

        if find_result.found {
            return Ok(false); // Key exists, so non-membership is false
        }

        // Verify the proof: check that siblings match and not_found_key/value match
        if find_result.siblings.len() != siblings.len() {
            return Err(Error::InvalidProof);
        }

        for (i, sibling) in siblings.iter().enumerate() {
            let expected = find_result.siblings.get(i as u32).unwrap();
            if sibling != expected {
                return Err(Error::InvalidProof);
            }
        }

        if find_result.not_found_key != not_found_key
            || find_result.not_found_value != not_found_value
        {
            return Err(Error::InvalidProof);
        }

        // Reconstruct root from proof (process siblings in reverse: leaf to root)
        let mut computed_root =
            if not_found_key != key && not_found_value != U256::from_u32(&env, 0u32) {
                Self::hash_leaf(&env, not_found_key, not_found_value)
            } else {
                U256::from_u32(&env, 0u32)
            };

        let siblings_len = siblings.len();
        for level_idx in 0..siblings_len {
            let level = siblings_len - 1 - level_idx; // Reverse: process from leaf to root
            let sibling = siblings.get(level).unwrap();
            let bit = key_bits.get(level).unwrap();

            computed_root = if bit {
                Self::hash_internal(&env, sibling.clone(), computed_root)
            } else {
                Self::hash_internal(&env, computed_root, sibling.clone())
            };
        }

        if computed_root != root {
            return Err(Error::InvalidProof);
        }

        Ok(true) // Non-membership verified
    }

    /// Get the current root of the tree
    ///
    /// Returns the root hash of the Sparse Merkle tree. Returns zero if the tree
    /// is empty or hasn't been initialized yet.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    ///
    /// # Returns
    ///
    /// Returns the current root hash as a U256 value, or zero if empty
    pub fn get_root(env: Env) -> Result<U256, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Root)
            .ok_or(Error::NotInitialized)
    }
}

mod test;
