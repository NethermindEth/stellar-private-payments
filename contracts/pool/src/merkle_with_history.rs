//! Merkle Tree with History Module
//!
//! This module implements a fixed-depth binary Merkle tree with root history
//! for privacy-preserving transactions.
//!
//! - Maintains a ring buffer of recent roots for membership proof verification
//! - Auto-expands to new trees when capacity is reached
//! - Compatible with the ASP membership Merkle tree implementation
//!
//! This module is designed to be used internally by the pool contract.
//! Authorization should be handled by the calling main contract before invoking
//! these functions.

use soroban_sdk::{contracttype, Env, U256, Vec};
use soroban_utils::{get_zeroes, poseidon2_compress};

/// Number of roots kept in history for proof verification
const ROOT_HISTORY_SIZE: u32 = 100;

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
/// that maintains a history of recent roots. When the tree reaches capacity,
/// it automatically creates a new tree in the next history slot while
/// preserving previous roots for membership proof verification.
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
    pub fn init(env: &Env, levels: u32) {
        if levels == 0 || levels > 32 {
            panic!("Levels must be within the range [1..32]");
        }
        let storage = env.storage().persistent();

        // Prevent reinitialization
        if storage.has(&MerkleDataKey::CurrentRootIndex) {
            panic!("Set of trees already initialized");
        }

        // Store levels
        storage.set(&MerkleDataKey::Levels, &levels);

        // Initialize with precomputed zero hashes
        let zeros: Vec<U256> = get_zeroes(env);

        // Initialize filledSubtrees[i] = zeros(i) for each level
        for i in 0..levels + 1 {
            let z: U256 = zeros.get(i).expect("Zero hash missing");
            storage.set(&MerkleDataKey::FilledSubtree(i), &z);
            storage.set(&MerkleDataKey::Zeroes(i), &z);
        }

        // Set initial root to zero hash at top level
        let root_0: U256 = zeros.get(levels).expect("Zero hash for root missing");
        storage.set(&MerkleDataKey::Root(0), &root_0);
        storage.set(&MerkleDataKey::CurrentRootIndex, &0u32);
        storage.set(&MerkleDataKey::NextIndex, &0u64);
    }

    /// Insert a new leaf into the Merkle tree
    ///
    /// Adds a new leaf to the Merkle tree and updates the root. The leaf is
    /// inserted at the next available index, and the tree is updated efficiently
    /// by only recomputing the hashes along the path to the root.
    ///
    /// When the current tree is full, a new tree is automatically created in
    /// the next history slot. The previous root remains valid for proof
    /// verification until it is overwritten after `ROOT_HISTORY_SIZE` rotations.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `leaf` - The leaf value to insert (typically a commitment hash)
    ///
    /// # Returns
    ///
    /// Returns the index at which the leaf was inserted
    pub fn insert_leaf(env: &Env, leaf: U256) -> u32 {
        let storage = env.storage().persistent();

        let levels: u32 = storage
            .get(&MerkleDataKey::Levels)
            .expect("Tree not initialized");
        let mut next_index: u64 = storage
            .get(&MerkleDataKey::NextIndex)
            .expect("Tree not initialized");
        let mut root_index: u32 = storage
            .get(&MerkleDataKey::CurrentRootIndex)
            .expect("Tree not initialized");
        let max_leaves = 1u64.checked_shl(levels).expect("Levels too large");

        let mut current_hash = leaf.clone();

        if next_index >= max_leaves {
            // Tree is full - create a new tree in next history slot
            root_index = (root_index + 1) % ROOT_HISTORY_SIZE;
            storage.set(&MerkleDataKey::CurrentRootIndex, &root_index);

            // Reset filled subtrees to zero values for the new empty tree
            for lvl in 0..levels + 1 {
                let zero_val: U256 = storage
                    .get(&MerkleDataKey::Zeroes(lvl))
                    .expect("Zero hash missing");
                storage.set(&MerkleDataKey::FilledSubtree(lvl), &zero_val);
            }

            // Reset index for the new tree
            next_index = 0;
        }

        let mut current_index = next_index;

        // Update the tree by recomputing hashes along the path to root
        for lvl in 0..levels {
            let is_right = current_index & 1 == 1;
            if is_right {
                // Leaf is a right child, get the stored left sibling
                let left: U256 = storage
                    .get(&MerkleDataKey::FilledSubtree(lvl))
                    .expect("Filled subtree missing");
                current_hash = poseidon2_compress(env, left, current_hash);
            } else {
                // Leaf is left child, store it and pair with zero hash
                storage.set(&MerkleDataKey::FilledSubtree(lvl), &current_hash);
                let zero_val: U256 = storage
                    .get(&MerkleDataKey::Zeroes(lvl))
                    .expect("Zero hash missing");
                current_hash = poseidon2_compress(env, current_hash, zero_val);
            }
            current_index >>= 1;
        }

        // Update the root with the computed hash
        storage.set(&MerkleDataKey::Root(root_index), &current_hash);

        // Update NextIndex
        storage.set(&MerkleDataKey::NextIndex, &(next_index + 1));

        // Return the index at which the leaf was inserted
        next_index as u32
    }

    /// Check if a root exists in the recent history
    ///
    /// Searches the root history ring buffer to verify if a given root is valid.
    /// This allows proofs generated against recent three states to be verified,
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
    /// Zero roots always return `false`.
    pub fn is_known_root(env: &Env, root: &U256) -> bool {
        // Zero root is never valid
        if *root == U256::from_u32(env, 0u32) {
            return false;
        }

        let storage = env.storage().persistent();
        let current_root_index: u32 = storage
            .get(&MerkleDataKey::CurrentRootIndex)
            .expect("Tree not initialized");

        // Search the ring buffer for the root
        let mut i = current_root_index;
        loop {
            // roots[i]
            if let Some(r) = storage.get(&MerkleDataKey::Root(i)) {
                if &r == root {
                    return true;
                }
            }
            i = (i + 1) % ROOT_HISTORY_SIZE;
            if i == current_root_index {
                // Break after seeing all roots
                break;
            }
        }
        false
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
    pub fn get_last_root(env: &Env) -> U256 {
        let storage = env.storage().persistent();
        let current_root_index: u32 = storage
            .get(&MerkleDataKey::CurrentRootIndex)
            .expect("Tree not initialized");

        storage
            .get(&MerkleDataKey::Root(current_root_index))
            .expect("Root not set")
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
