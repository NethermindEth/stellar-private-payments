//! Merkle Tree with History Module
//!
//! This module implements a fixed-depth binary Merkle tree with root history
//! for privacy-preserving transactions. It uses the Poseidon2 hash function
//! for ZK-circuit compatibility.
//!
//! - Maintains a ring buffer of recent roots for membership proof verification
//! - Compatible with the ASP membership Merkle tree implementation
//!
//! This module is designed to be used internally by the pool contract.
//! Authorization should be handled by the calling main contract before invoking
//! these functions.

use soroban_sdk::{Env, U256, Vec, contracttype};
use soroban_utils::{get_zeroes, poseidon2_compress};

/// Number of roots kept in history for proof verification
const ROOT_HISTORY_SIZE: u32 = 100;

// Errors
#[derive(Clone, Debug)]
pub enum Error {
    AlreadyInitialized,
    WrongLevels,
    MerkleTreeFull,
    NextIndexNotEven,
    NotInitialized,
}
/// Storage keys for Merkle tree persistent data
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MerkleDataKey {
    /// Number of levels in the Merkle tree
    Levels,
    /// Current position in the root history ring buffer
    CurrentRootIndex,
    /// Next available index for leaf insertion
    NextIndex,
    /// Subtree hashes at each level (indexed by level)
    FilledSubtree(u32),
    /// Zero hash values for each level (indexed by level)
    Zeroes(u32),
    /// Historical roots ring buffer
    Root(u32),
}

/// Merkle Tree with root history for privacy-preserving transactions
///
/// This struct provides methods to manage a fixed-depth binary Merkle tree
/// that maintains a history of recent roots. When the tree is modified,
/// it automatically preserves previous roots for membership proof verification.
pub struct MerkleTreeWithHistory;

impl MerkleTreeWithHistory {
    /// Initialize the Merkle tree with history
    ///
    /// Creates a new Merkle tree with the specified number of levels. The tree
    /// is initialized with precomputed zero hashes at each level, and the initial
    /// root is set to the zero hash at the top level.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `levels` - Number of levels in the Merkle tree (must be in range [1..32])
    ///
    /// # Panics
    ///
    /// * Panics if `levels` is 0 or greater than 32
    /// * Panics if the tree has already been initialized
    pub fn init(env: &Env, levels: u32) -> Result<(), Error> {
        if levels == 0 || levels > 32 {
            return Err(Error::WrongLevels);
        }
        let storage = env.storage().persistent();

        // Prevent reinitialization
        if storage.has(&MerkleDataKey::CurrentRootIndex) {
            return Err(Error::AlreadyInitialized);
        }

        // Store levels
        storage.set(&MerkleDataKey::Levels, &levels);

        // Initialize with precomputed zero hashes
        let zeros: Vec<U256> = get_zeroes(env);

        // Initialize filledSubtrees[i] = zeros(i) for each level
        for i in 0..levels + 1 {
            let z: U256 = zeros.get(i).ok_or(Error::NotInitialized)?;
            storage.set(&MerkleDataKey::FilledSubtree(i), &z);
            storage.set(&MerkleDataKey::Zeroes(i), &z);
        }

        // Set initial root to zero hash at top level
        let root_0: U256 = zeros.get(levels).ok_or(Error::NotInitialized)?;
        storage.set(&MerkleDataKey::Root(0), &root_0);
        storage.set(&MerkleDataKey::CurrentRootIndex, &0u32);
        storage.set(&MerkleDataKey::NextIndex, &0u64);

        Ok(())
    }

    /// Insert two leaves into the Merkle tree as siblings
    ///
    /// Adds 2 new leaves to the Merkle tree and updates the root. The leaves are
    /// inserted at the next available index, and the tree is updated efficiently
    /// by only recomputing the hashes along the path to the root.
    ///
    /// When the tree is modified, a new root is automatically created in
    /// the next history slot. The previous root remains valid for proof
    /// verification until it is overwritten after `ROOT_HISTORY_SIZE` rotations.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `leaf_1` - The left leaf value to insert (at even index)
    /// * `leaf_2` - The right leaf value to insert (at odd index)
    ///
    /// # Returns
    ///
    /// Returns the indexes where leaves were inserted
    pub fn insert_two_leaves(env: &Env, leaf_1: U256, leaf_2: U256) -> Result<(u32, u32), Error> {
        let storage = env.storage().persistent();

        let levels: u32 = storage
            .get(&MerkleDataKey::Levels)
            .ok_or(Error::NotInitialized)?;
        let next_index: u64 = storage
            .get(&MerkleDataKey::NextIndex)
            .ok_or(Error::NotInitialized)?;
        let mut root_index: u32 = storage
            .get(&MerkleDataKey::CurrentRootIndex)
            .ok_or(Error::NotInitialized)?;
        let max_leaves = 1u64.checked_shl(levels).ok_or(Error::WrongLevels)?;

        // NextIndex must be even for two-leaf insertion
        if next_index % 2 != 0 {
            return Err(Error::NextIndexNotEven);
        }

        if (next_index + 2) > max_leaves {
            return Err(Error::MerkleTreeFull);
        }

        // Hash the two leaves to form their parent node at level 1
        let mut current_hash = poseidon2_compress(env, leaf_1, leaf_2);

        // Calculate the parent index at level 1 (since we already hashed the two leaves)
        let mut current_index = next_index >> 1;

        // Update the tree by recomputing hashes along the path to root
        // Start at level 1 since current_hash is already the parent of the two leaves
        for lvl in 1..levels {
            let is_right = current_index & 1 == 1;
            if is_right {
                // Leaf is right child, get the stored left sibling
                let left: U256 = storage
                    .get(&MerkleDataKey::FilledSubtree(lvl))
                    .ok_or(Error::NotInitialized)?;
                current_hash = poseidon2_compress(env, left, current_hash);
            } else {
                // Leaf is left child, store it and pair with zero hash
                storage.set(&MerkleDataKey::FilledSubtree(lvl), &current_hash);
                let zero_val: U256 = storage
                    .get(&MerkleDataKey::Zeroes(lvl))
                    .ok_or(Error::NotInitialized)?;
                current_hash = poseidon2_compress(env, current_hash, zero_val);
            }
            current_index >>= 1;
        }

        // Update the root history index
        root_index = (root_index + 1) % ROOT_HISTORY_SIZE;
        // Update the root with the computed hash
        storage.set(&MerkleDataKey::Root(root_index), &current_hash);
        storage.set(&MerkleDataKey::CurrentRootIndex, &root_index);

        // Update NextIndex
        storage.set(&MerkleDataKey::NextIndex, &(next_index + 2));

        // Return the index of the left leaf
        Ok((next_index as u32, (next_index + 1) as u32))
    }

    /// Check if a root exists in the recent history
    ///
    /// Searches the root history ring buffer to verify if a given root is valid.
    /// This allows proofs generated against recent tree states to be verified,
    /// providing some tolerance for latency between proof generation and submission.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `root` - The Merkle root to check
    ///
    /// # Returns
    ///
    /// Returns `true` if the root exists in the history buffer, `false` otherwise.
    /// Zero root always returns `false`.
    ///
    /// # Panics
    ///
    /// * Panics if the tree has not been initialized
    pub fn is_known_root(env: &Env, root: &U256) -> Result<bool, Error> {
        // Zero root is never valid as define zero in a different way
        if *root == U256::from_u32(env, 0u32) {
            return Ok(false);
        }

        let storage = env.storage().persistent();
        let current_root_index: u32 = storage
            .get(&MerkleDataKey::CurrentRootIndex)
            .ok_or(Error::NotInitialized)?;

        // Search the ring buffer for the root
        let mut i = current_root_index;
        loop {
            // roots[i]
            if let Some(r) = storage.get::<MerkleDataKey, U256>(&MerkleDataKey::Root(i)) {
                if &r == root {
                    return Ok(true);
                }
            }
            i = (i + 1) % ROOT_HISTORY_SIZE;
            if i == current_root_index {
                // Break after seeing all roots
                break;
            }
        }
        Ok(false)
    }

    /// Get the current Merkle root
    ///
    /// Returns the most recent root hash of the Merkle tree.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    ///
    /// # Returns
    ///
    /// Returns the current Merkle root as U256
    ///
    /// # Panics
    ///
    /// * Panics if the tree has not been initialized
    pub fn get_last_root(env: &Env) -> Result<U256, Error> {
        let storage = env.storage().persistent();
        let current_root_index: u32 = storage
            .get(&MerkleDataKey::CurrentRootIndex)
            .ok_or(Error::NotInitialized)?;

        storage
            .get(&MerkleDataKey::Root(current_root_index))
            .ok_or(Error::NotInitialized)
    }

    /// Hash two U256 values using Poseidon2 compression
    ///
    /// Computes the Poseidon2 hash of two field elements in compression mode.
    /// This is the core hashing function used for Merkle tree operations.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment
    /// * `left` - Left input value
    /// * `right` - Right input value
    ///
    /// # Returns
    /// The Poseidon2 hash result as U256
    pub fn hash_pair(env: &Env, left: U256, right: U256) -> U256 {
        poseidon2_compress(env, left, right)
    }
}
