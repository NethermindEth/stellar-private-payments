//! Merkle Tree with History Module
//!
//! This module implements a fixed-depth binary Merkle tree with root history
//! for privacy-preserving transactions. It uses the Poseidon2 hash function
//! for ZK-circuit compatibility.
//!
//! - Maintains a ring buffer of recent roots for membership proof verification
//! - Compatible with the ASP membership Merkle tree implementation
//!
//! Tree state is packed into one ledger entry ([`TreeState`]) rather than
//! split across per-level and per-slot keys: a transaction's footprint is
//! frozen at simulation, so per-index keys shift with the tree's state and a
//! transaction applied after another one lands reaches for a key it never
//! declared. Packing keeps the footprint fixed at `MerkleDataKey::State`.
//!
//! This module is designed to be used internally by the pool contract.
//! Authorization should be handled by the calling main contract before invoking
//! these functions.

use soroban_sdk::{Env, U256, Vec, contracttype};
use soroban_utils::{get_zeroes, poseidon2_compress};

/// Ring size for the root history packed into [`TreeState`]; bigger means
/// more stale-proof tolerance at the cost of a larger entry.
pub const ROOT_HISTORY_SIZE: u32 = 64;

// Errors
#[derive(Clone, Debug)]
pub enum Error {
    AlreadyInitialized,
    WrongLevels,
    MerkleTreeFull,
    NextIndexNotEven,
    NotInitialized,
    Overflow,
}

/// All mutable Merkle tree state, packed into one ledger entry (see module
/// docs for why splitting this back into per-key fields is a footprint
/// hazard).
#[contracttype]
#[derive(Clone, Debug)]
pub struct TreeState {
    /// Number of levels in the tree, fixed at [`MerkleTreeWithHistory::init`].
    pub levels: u32,
    /// Next available index for leaf insertion.
    pub next_index: u64,
    /// Filled subtree hash at each level, indexed `0..=levels`.
    pub filled_subtrees: Vec<U256>,
    /// Root history ring buffer, fixed at [`ROOT_HISTORY_SIZE`] from `init`
    /// onward so this entry's size never changes.
    pub roots: Vec<U256>,
}

/// Storage keys for Merkle tree persistent data
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MerkleDataKey {
    /// The single packed [`TreeState`] entry.
    State,
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
    /// is initialized with precomputed zero hashes at each level, and the
    /// initial root is set to the zero hash at the top level.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `levels` - Number of levels in the Merkle tree (must be in range
    ///   [1..32])
    pub fn init(env: &Env, levels: u32) -> Result<(), Error> {
        if levels == 0 || levels > 32 {
            return Err(Error::WrongLevels);
        }
        let storage = env.storage().persistent();

        // Prevent reinitialization
        if storage.has(&MerkleDataKey::State) {
            return Err(Error::AlreadyInitialized);
        }

        // Zero hashes are a fixed table (see `get_zeroes`), so they are
        // computed on demand rather than stored: a value that never changes
        // costs nothing to recompute, and never needs a TTL of its own.
        let zeros: Vec<U256> = get_zeroes(env);

        // filledSubtrees[i] = zeros(i) for each level
        let mut filled_subtrees: Vec<U256> = Vec::new(env);
        for i in 0..=levels {
            let z: U256 = zeros.get(i).ok_or(Error::NotInitialized)?;
            filled_subtrees.push_back(z);
        }

        // Every slot starts at `root_0` — valid for the tree's whole
        // pre-insert history — so the entry is full size from block one.
        let root_0: U256 = zeros.get(levels).ok_or(Error::NotInitialized)?;
        let mut roots: Vec<U256> = Vec::new(env);
        for _ in 0..ROOT_HISTORY_SIZE {
            roots.push_back(root_0.clone());
        }

        storage.set(
            &MerkleDataKey::State,
            &TreeState {
                levels,
                next_index: 0,
                filled_subtrees,
                roots,
            },
        );

        Ok(())
    }

    /// Insert two leaves into the Merkle tree as siblings
    ///
    /// Adds 2 new leaves to the Merkle tree and updates the root. The leaves
    /// are inserted at the next available index, and the tree is updated
    /// efficiently by only recomputing the hashes along the path to the
    /// root.
    ///
    /// When the tree is modified, a new root is automatically created in
    /// the next history slot. The previous root remains valid for proof
    /// verification until it is overwritten after `ROOT_HISTORY_SIZE`
    /// rotations.
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
        let mut state: TreeState = storage
            .get(&MerkleDataKey::State)
            .ok_or(Error::NotInitialized)?;

        let next_index = state.next_index;
        let max_leaves = 1u64.checked_shl(state.levels).ok_or(Error::WrongLevels)?;

        // NextIndex must be even for two-leaf insertion
        if !next_index.is_multiple_of(2) {
            return Err(Error::NextIndexNotEven);
        }

        if next_index.checked_add(2).ok_or(Error::Overflow)? > max_leaves {
            return Err(Error::MerkleTreeFull);
        }

        // Hash the two leaves to form their parent node at level 1
        let mut current_hash = poseidon2_compress(env, leaf_1, leaf_2);

        // Calculate the parent index at level 1 (since we already hashed the
        // two leaves)
        let mut current_index = next_index >> 1;

        let zeros: Vec<U256> = get_zeroes(env);

        // Update the tree by recomputing hashes along the path to root
        // Start at level 1 since current_hash is already the parent of the two
        // leaves
        for lvl in 1..state.levels {
            let is_right = current_index & 1 == 1;
            if is_right {
                // Leaf is right child, get the stored left sibling
                let left: U256 = state
                    .filled_subtrees
                    .get(lvl)
                    .ok_or(Error::NotInitialized)?;
                current_hash = poseidon2_compress(env, left, current_hash);
            } else {
                // Leaf is left child, store it and pair with zero hash
                state.filled_subtrees.set(lvl, current_hash.clone());
                let zero_val: U256 = zeros.get(lvl).ok_or(Error::NotInitialized)?;
                current_hash = poseidon2_compress(env, current_hash, zero_val);
            }
            current_index >>= 1;
        }

        // Update NextIndex
        state.next_index = next_index.checked_add(2).ok_or(Error::Overflow)?;

        // Ring is always full size (see `init`); always overwrite, never grow.
        let ring_index = Self::ring_index(state.next_index)?;
        state.roots.set(ring_index, current_hash);

        storage.set(&MerkleDataKey::State, &state);

        // Return the index of the left leaf
        Ok((
            u32::try_from(next_index).map_err(|_| Error::MerkleTreeFull)?,
            u32::try_from(next_index.checked_add(1).ok_or(Error::Overflow)?)
                .map_err(|_| Error::MerkleTreeFull)?,
        ))
    }

    /// Check if a root exists in the recent history
    ///
    /// Searches the root history ring buffer to verify if a given root is
    /// valid. This allows proofs generated against recent tree states to be
    /// verified, providing some tolerance for latency between proof
    /// generation and submission.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `root` - The Merkle root to check
    ///
    /// # Returns
    ///
    /// Returns `true` if the root exists in the history buffer, `false`
    /// otherwise. Zero root always returns `false`.
    pub fn is_known_root(env: &Env, root: &U256) -> Result<bool, Error> {
        // Zero root is never valid as define zero in a different way
        if *root == U256::from_u32(env, 0u32) {
            return Ok(false);
        }

        let state: TreeState = env
            .storage()
            .persistent()
            .get(&MerkleDataKey::State)
            .ok_or(Error::NotInitialized)?;

        let len = state.roots.len();
        if len == 0 {
            return Ok(false);
        }
        let current_index = Self::ring_index(state.next_index)?;

        // Search the ring buffer for the root, newest first: the newest
        // root is the overwhelmingly common case, so it should be the
        // cheapest to find rather than the most expensive.
        let mut i = current_index;
        let mut visited: u32 = 0;
        loop {
            if let Some(r) = state.roots.get(i)
                && &r == root
            {
                return Ok(true);
            }
            visited = visited.checked_add(1).ok_or(Error::Overflow)?;
            if visited >= len {
                break;
            }
            i = if i == 0 {
                len.checked_sub(1).ok_or(Error::Overflow)?
            } else {
                i.checked_sub(1).ok_or(Error::Overflow)?
            };
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
    pub fn get_last_root(env: &Env) -> Result<U256, Error> {
        let state: TreeState = env
            .storage()
            .persistent()
            .get(&MerkleDataKey::State)
            .ok_or(Error::NotInitialized)?;

        let current_index = Self::ring_index(state.next_index)?;
        state.roots.get(current_index).ok_or(Error::NotInitialized)
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

    /// Ring slot for the root at `next_index`; derived rather than stored
    /// since it always tracks `next_index` in lockstep.
    fn ring_index(next_index: u64) -> Result<u32, Error> {
        let logical_index = next_index >> 1;
        let wrapped = logical_index
            .checked_rem(u64::from(ROOT_HISTORY_SIZE))
            .ok_or(Error::Overflow)?;
        u32::try_from(wrapped).map_err(|_| Error::Overflow)
    }
}
