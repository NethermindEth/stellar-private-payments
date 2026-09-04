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
use soroban_utils::{
    bump_entry, bump_instance, get_zeroes,
    pausable::{self, PauseError, PauseState},
    poseidon2_compress,
};

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
    /// Wrong Number of levels specified
    WrongLevels = 3,
    /// The contract has not been yet initialized
    NotInitialized = 4,
    /// Arithmetic overflow occurred
    Overflow = 5,
    /// Tree mutations are paused.
    Paused = 6,
    /// Pause flags were zero, or held a bit the contract does not recognize.
    InvalidPauseFlags = 7,
    /// A timed pause is in force, and a second one would move its deadline.
    TimedPauseArmed = 8,
}

impl From<PauseError> for Error {
    fn from(e: PauseError) -> Self {
        match e {
            PauseError::InvalidFlags => Error::InvalidPauseFlags,
            PauseError::TimedPauseArmed => Error::TimedPauseArmed,
        }
    }
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
    /// Returns `Ok(())` on success, or an error if already initialized
    ///
    /// # Panics
    /// Panics if levels is 0 or greater than 32
    pub fn __constructor(env: Env, admin: Address, levels: u32) -> Result<(), Error> {
        let store = env.storage().persistent();

        if levels == 0 || levels > 32 {
            return Err(Error::WrongLevels);
        }

        // Initialize admin and tree parameters
        store.set(&DataKey::Admin, &admin);
        store.set(&DataKey::Levels, &levels);
        store.set(&DataKey::NextIndex, &0u64);

        // Initialize an empty tree with zero hashes at each level
        let zeros: Vec<U256> = get_zeroes(&env);
        for lvl in 0..=levels {
            let zero_val = zeros.get(lvl).ok_or(Error::NotInitialized)?;
            store.set(&DataKey::FilledSubtrees(lvl), &zero_val);
            store.set(&DataKey::Zeroes(lvl), &zero_val);
        }

        // Set initial root to the zero hash at the top level
        let root_val = zeros.get(levels).ok_or(Error::NotInitialized)?;
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
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotInitialized`] if the contract has no admin address
    /// stored.
    pub fn update_admin(env: Env, new_admin: Address) -> Result<(), Error> {
        bump_instance(&env);
        soroban_utils::update_admin(&env, &DataKey::Admin, &new_admin)
            .map_err(|soroban_utils::AdminError::NotInitialized| Error::NotInitialized)
    }

    /// Reads the stored administrator and extends the entry's lifetime.
    fn get_admin(env: &Env) -> Result<Address, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Admin)
            .inspect(|_| bump_entry(env, &DataKey::Admin))
            .ok_or(Error::NotInitialized)
    }

    /// Pauses tree mutations.
    ///
    /// The only bit the contract honors is `MUTATIONS` from
    /// [`soroban_utils::pausable`], and it does not expire, so `until` only
    /// arms the timed pause the module refuses to move. Requires admin
    /// authorization.
    ///
    /// A pause stops `insert_leaf` and nothing else. `update_admin`,
    /// `unpause`, `get_root`, and `hash_pair` answer while the contract is
    /// paused, so an operator can hand over a paused contract.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotInitialized`] if the contract has no admin address
    /// stored, [`Error::InvalidPauseFlags`] if `flags` is zero or holds a bit
    /// other than `MUTATIONS`, and [`Error::TimedPauseArmed`] if `until` is
    /// `Some` while a timed pause is already in force.
    ///
    /// # Events
    ///
    /// Publishes [`soroban_utils::pausable::PauseChanged`] from the contract.
    pub fn pause(env: Env, flags: u32, until: Option<u32>) -> Result<(), Error> {
        bump_instance(&env);
        Self::get_admin(&env)?.require_auth();
        Ok(pausable::pause(&env, flags, until, pausable::MUTATIONS)?)
    }

    /// Clears the pause bits named by `flags`.
    ///
    /// Clearing bits that are not set is accepted, and any unpause also clears
    /// a timed pause. Requires admin authorization.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotInitialized`] if the contract has no admin address
    /// stored, and [`Error::InvalidPauseFlags`] if `flags` is zero or holds a
    /// bit other than `MUTATIONS`.
    ///
    /// # Events
    ///
    /// Publishes [`soroban_utils::pausable::PauseChanged`] from the contract.
    pub fn unpause(env: Env, flags: u32) -> Result<(), Error> {
        bump_instance(&env);
        Self::get_admin(&env)?.require_auth();
        Ok(pausable::unpause(&env, flags, pausable::MUTATIONS)?)
    }

    /// Returns the contract's pause bits.
    pub fn get_pause_state(env: Env) -> PauseState {
        bump_instance(&env);
        pausable::get_state(&env)
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
    /// Returns [`Error::NotInitialized`] if no root is stored.
    pub fn get_root(env: Env) -> Result<U256, Error> {
        bump_instance(&env);
        env.storage()
            .persistent()
            .get(&DataKey::Root)
            .inspect(|_| bump_entry(&env, &DataKey::Root))
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
        bump_instance(env);
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
    /// address or any tree state the insertion reads, [`Error::Paused`] if
    /// mutations are paused, [`Error::MerkleTreeFull`] if the tree is at
    /// capacity, and [`Error::Overflow`] if the next leaf index would exceed
    /// `u64::MAX`.
    pub fn insert_leaf(env: Env, leaf: U256) -> Result<(), Error> {
        bump_instance(&env);
        Self::get_admin(&env)?.require_auth();
        if pausable::is_paused(&env, pausable::MUTATIONS) {
            return Err(Error::Paused);
        }

        let store = env.storage().persistent();
        let levels: u32 = store.get(&DataKey::Levels).ok_or(Error::NotInitialized)?;
        bump_entry(&env, &DataKey::Levels);
        let actual_index: u64 = store
            .get(&DataKey::NextIndex)
            .ok_or(Error::NotInitialized)?;
        bump_entry(&env, &DataKey::NextIndex);
        let mut current_index = actual_index;

        // Check if tree is full (capacity is 2^levels leaves)
        if current_index >= 1u64.checked_shl(levels).ok_or(Error::MerkleTreeFull)? {
            return Err(Error::MerkleTreeFull);
        }
        let mut current_hash = leaf.clone();

        // Update tree by recomputing hashes along the path to root
        for lvl in 0..levels {
            let is_right = current_index & 1 == 1;
            let subtree_key = DataKey::FilledSubtrees(lvl);
            if is_right {
                // Leaf is right child, get the stored left sibling
                let left: U256 = store.get(&subtree_key).ok_or(Error::NotInitialized)?;
                bump_entry(&env, &subtree_key);
                current_hash = poseidon2_compress(&env, left, current_hash);
            } else {
                // Leaf is left child, store it and pair with zero hash
                store.set(&subtree_key, &current_hash);
                bump_entry(&env, &subtree_key);
                let zero_key = DataKey::Zeroes(lvl);
                let zero_val: U256 = store.get(&zero_key).ok_or(Error::NotInitialized)?;
                bump_entry(&env, &zero_key);
                current_hash = poseidon2_compress(&env, current_hash, zero_val);
            }
            current_index >>= 1;
        }

        // Update the root with the computed hash
        store.set(&DataKey::Root, &current_hash);
        bump_entry(&env, &DataKey::Root);

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
