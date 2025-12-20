//! ASP Membership Contract
//!
//! This contract implements a Merkle tree-based membership system using Poseidon2
//! hash function for Anonymous Service Provider (ASP) membership tracking.
//! The contract maintains a Merkle tree where each leaf represents a member,
//! and the root serves as a commitment to the entire membership set.
#![no_std]
use soroban_sdk::{
    Address, Env, U256, Vec, contract, contracterror, contractevent, contractimpl, contracttype,
};
use soroban_utils::{get_zeroes, poseidon2_compress};

/// Storage keys for contract persistent data
#[contracttype]
#[derive(Clone, Debug)]
enum DataKey {
    /// Administrator address with permissions to modify the tree
    Admin,
    /// Filled subtree hashes at each level (indexed by level)
    FilledSubtrees(u32),
    /// Zero hash values for each level (indexed by level)
    Zeroes(u32),
    /// Number of levels in the Merkle tree
    Levels,
    /// Next available index for leaf insertion
    NextIndex,
    /// Current Merkle root
    Root,
}

/// Contract error types
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// Caller is not authorized to perform this operation
    NotAuthorized = 1,
    /// Merkle tree has reached maximum capacity
    MerkleTreeFull = 2,
    /// Contract has already been initialized
    AlreadyInitialized = 3,
    /// Wrong Number of levels specified
    WrongLevels = 4,
    /// The contract has not been yet initialized
    NotInitialized = 5,
}

/// Event emitted when a new leaf is added to the Merkle tree
#[contractevent(topics = ["LeafAdded"])]
struct LeafAddedEvent {
    /// The leaf value that was inserted
    leaf: U256,
    /// Index position where the leaf was inserted
    index: u64,
    /// New Merkle root after insertion
    root: U256,
}

/// ASP Membership contract
#[contract]
pub struct ASPMembership;

#[contractimpl]
impl ASPMembership {
    /// Constructor: initialize the ASP Membership contract
    ///
    /// Creates a new Merkle tree with the specified number of levels and sets
    /// the admin address. The tree is initialized with zero hashes at each level.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment
    /// * `admin` - Address of the contract administrator
    /// * `levels` - Number of levels in the Merkle tree (must be in range [1..32])
    ///
    /// # Returns
    /// Returns `Ok(())` on success, or an error if already initialized
    ///
    /// # Panics
    /// Panics if levels is 0 or greater than 32
    pub fn __constructor(env: Env, admin: Address, levels: u32) -> Result<(), Error> {
        let store = env.storage().persistent();

        // Check if the contract is already initialized
        if store.has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }

        if levels == 0 || levels > 32 {
            return Err(Error::WrongLevels);
        }

        // Initialize admin and tree parameters
        store.set(&DataKey::Admin, &admin);
        store.set(&DataKey::Levels, &levels);
        store.set(&DataKey::NextIndex, &0u64);

        // Initialize an empty tree with zero hashes at each level
        let zeros: Vec<U256> = get_zeroes(&env);
        for lvl in 0..levels + 1 {
            let zero_val = zeros.get(lvl).unwrap();
            store.set(&DataKey::FilledSubtrees(lvl), &zero_val);
            store.set(&DataKey::Zeroes(lvl), &zero_val);
        }

        // Set initial root to the zero hash at the top level
        let root_val = zeros.get(levels).unwrap();
        store.set(&DataKey::Root, &root_val);

        Ok(())
    }

    /// Update the contract administrator
    ///
    /// Changes the admin address to a new address. Only the current admin
    /// can call this function.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment
    /// * `new_admin` - Address of the new administrator
    pub fn update_admin(env: Env, new_admin: Address) -> Result<(), Error> {
        if !env.storage().persistent().has(&DataKey::Admin) {
            return Err(Error::NotInitialized);
        }
        soroban_utils::update_admin(&env, &DataKey::Admin, &new_admin);
        Ok(())
    }

    /// Get the current Merkle root
    ///
    /// Returns the current root hash of the Merkle tree.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment
    ///
    /// # Returns
    /// The current Merkle root as U256
    ///
    /// # Panics
    /// Panics if the contract has not been initialized
    pub fn get_root(env: Env) -> Result<U256, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Root)
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

    /// Insert a new leaf into the Merkle tree
    ///
    /// Adds a new member to the Merkle tree and updates the root. The leaf is
    /// inserted at the next available index and the tree is updated efficiently
    /// by only recomputing the hashes along the path to the root. Only the admin
    /// can insert leaves.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment
    /// * `leaf` - The leaf value to insert (typically a commitment or hash)
    ///
    /// # Returns
    /// Returns `Ok(())` on success, or `MerkleTreeFull` if the tree is at capacity
    pub fn insert_leaf(env: Env, leaf: U256) -> Result<(), Error> {
        let store = env.storage().persistent();
        let admin: Address = store.get(&DataKey::Admin).unwrap();
        admin.require_auth();

        let levels: u32 = store.get(&DataKey::Levels).unwrap();
        let actual_index: u64 = store.get(&DataKey::NextIndex).unwrap();
        let mut current_index = actual_index;

        // Check if tree is full (capacity is 2^levels leaves)
        if current_index >= (1 << levels) {
            return Err(Error::MerkleTreeFull);
        }
        let mut current_hash = leaf.clone();

        // Update tree by recomputing hashes along the path to root
        for lvl in 0..levels {
            let is_right = current_index & 1 == 1;
            if is_right {
                // Leaf is right child, get the stored left sibling
                let left: U256 = store.get(&DataKey::FilledSubtrees(lvl)).unwrap();
                current_hash = poseidon2_compress(&env, left, current_hash);
            } else {
                // Leaf is left child, store it and pair with zero hash
                store.set(&DataKey::FilledSubtrees(lvl), &current_hash);
                let zero_val: U256 = store.get(&DataKey::Zeroes(lvl)).unwrap();
                current_hash = poseidon2_compress(&env, current_hash, zero_val);
            }
            current_index >>= 1;
        }

        // Update the root with the computed hash
        store.set(&DataKey::Root, &current_hash);

        // Emit event with leaf details
        LeafAddedEvent {
            leaf: leaf.clone(),
            index: actual_index,
            root: current_hash,
        }
        .publish(&env);

        // Update NextIndex
        store.set(&DataKey::NextIndex, &(actual_index + 1));
        Ok(())
    }
}

mod test;
