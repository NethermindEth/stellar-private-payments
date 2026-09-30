//! ASP Membership Contract
//!
//! This contract implements a Merkle tree-based membership system using
//! Poseidon2 hash function for Association Set Provider (ASP) membership
//! tracking. The contract maintains a Merkle tree where each leaf represents a
//! member, and the root serves as a commitment to the entire membership set.
#![no_std]
use soroban_sdk::{
    Address, Env, U256, Vec, contract, contracterror, contractevent, contractimpl, contracttype,
};
use soroban_utils::{poseidon2_compress, zero_hash};

/// Storage keys for contract data
///
/// [`DataKey::Levels`] and [`DataKey::Root`] are instance keys.
/// [`DataKey::Admin`], [`DataKey::NextIndex`], and [`DataKey::FilledSubtrees`]
/// are persistent keys.
#[contracttype]
#[derive(Clone, Debug)]
enum DataKey {
    /// Administrator address with permissions to modify the tree
    Admin,
    /// Left-sibling hashes along the insertion path, element `i` holding the
    /// hash at level `i`
    FilledSubtrees,
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
    /// Wrong Number of levels specified
    WrongLevels = 3,
    /// The contract has not been yet initialized
    NotInitialized = 4,
    /// Arithmetic overflow occurred
    Overflow = 5,
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
    /// the admin address. The tree is initialized with zero hashes at each
    /// level.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment
    /// * `admin` - Address of the contract administrator
    /// * `levels` - Number of levels in the Merkle tree (must be in range
    ///   [1..32])
    ///
    /// # Returns
    /// Returns `Ok(())` on success
    ///
    /// # Errors
    ///
    /// Returns [`Error::WrongLevels`] if `levels` is zero or above 32, and
    /// [`Error::NotInitialized`] if the zero hash table has no entry for a
    /// level the tree needs.
    pub fn __constructor(env: Env, admin: Address, levels: u32) -> Result<(), Error> {
        let store = env.storage().persistent();

        if levels == 0 || levels > 32 {
            return Err(Error::WrongLevels);
        }

        // Initialize admin and tree parameters
        store.set(&DataKey::Admin, &admin);
        let instance = env.storage().instance();
        instance.set(&DataKey::Levels, &levels);
        store.set(&DataKey::NextIndex, &0u64);

        // The top level is the root itself and is never read back as a
        // sibling, so it is not written.
        let mut filled = Vec::new(&env);
        for lvl in 0..levels {
            filled.push_back(zero_hash(&env, lvl).ok_or(Error::NotInitialized)?);
        }
        store.set(&DataKey::FilledSubtrees, &filled);

        // Set initial root to the zero hash at the top level
        let root_val = zero_hash(&env, levels).ok_or(Error::NotInitialized)?;
        instance.set(&DataKey::Root, &root_val);

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
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotInitialized`] if the contract has no admin address
    /// stored.
    pub fn update_admin(env: Env, new_admin: Address) -> Result<(), Error> {
        soroban_utils::update_admin(&env, &DataKey::Admin, &new_admin)
            .map_err(|soroban_utils::AdminError::NotInitialized| Error::NotInitialized)
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
    /// # Errors
    ///
    /// Returns [`Error::NotInitialized`] if the constructor has not run.
    pub fn get_root(env: Env) -> Result<U256, Error> {
        env.storage()
            .instance()
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
    /// by only recomputing the hashes along the path to the root. The admin
    /// must authorize the call.
    ///
    /// # Arguments
    /// * `env` - The Soroban environment
    /// * `leaf` - The leaf value to insert (typically a commitment or hash)
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotInitialized`] if the contract is missing the admin
    /// address or any tree state the insertion reads,
    /// [`Error::MerkleTreeFull`] if the tree is at capacity, and
    /// [`Error::Overflow`] if the next leaf index would exceed `u64::MAX`.
    pub fn insert_leaf(env: Env, leaf: U256) -> Result<(), Error> {
        let store = env.storage().persistent();
        let admin: Address = store.get(&DataKey::Admin).ok_or(Error::NotInitialized)?;
        admin.require_auth();

        let instance = env.storage().instance();
        let levels: u32 = instance
            .get(&DataKey::Levels)
            .ok_or(Error::NotInitialized)?;
        let actual_index: u64 = store
            .get(&DataKey::NextIndex)
            .ok_or(Error::NotInitialized)?;
        let mut current_index = actual_index;

        // Check if tree is full (capacity is 2^levels leaves)
        if current_index >= 1u64.checked_shl(levels).ok_or(Error::MerkleTreeFull)? {
            return Err(Error::MerkleTreeFull);
        }
        let mut current_hash = leaf.clone();

        let mut filled: Vec<U256> = store
            .get(&DataKey::FilledSubtrees)
            .ok_or(Error::NotInitialized)?;

        // Update tree by recomputing hashes along the path to root
        for lvl in 0..levels {
            let is_right = current_index & 1 == 1;
            if is_right {
                // Leaf is right child, get the stored left sibling
                let left = filled.get(lvl).ok_or(Error::NotInitialized)?;
                current_hash = poseidon2_compress(&env, left, current_hash);
            } else {
                // Leaf is left child, store it and pair with zero hash
                filled.set(lvl, current_hash.clone());
                let zero_val = zero_hash(&env, lvl).ok_or(Error::NotInitialized)?;
                current_hash = poseidon2_compress(&env, current_hash, zero_val);
            }
            current_index >>= 1;
        }

        // The last leaf of a full tree is a right child at every level and
        // leaves `filled` untouched. Skipping the write there would save one
        // write once in the tree's life, which is not worth the branch.
        store.set(&DataKey::FilledSubtrees, &filled);

        // Update the root with the computed hash
        instance.set(&DataKey::Root, &current_hash);

        // Emit event with leaf details
        LeafAddedEvent {
            leaf: leaf.clone(),
            index: actual_index,
            root: current_hash,
        }
        .publish(&env);

        // Update NextIndex
        store.set(
            &DataKey::NextIndex,
            &(actual_index.checked_add(1).ok_or(Error::Overflow)?),
        );
        Ok(())
    }
}

mod test;
