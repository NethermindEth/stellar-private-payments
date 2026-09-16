//! Merkle Tree with History Module
//!
//! This module implements a fixed-depth binary Merkle tree with root history
//! for privacy-preserving transactions. It uses the Poseidon2 hash function
//! for ZK-circuit compatibility.
//!
//! - Maintains a ring buffer of recent roots for membership proof verification
//! - Compatible with the ASP membership Merkle tree implementation
//!
//! Everything an insertion mutates lives in one persistent entry,
//! [`TreeState`], whose size is fixed at [`MerkleTreeWithHistory::init`]. A
//! Soroban transaction declares the ledger keys it touches and the bytes it
//! writes when it is simulated, and the host fails it at apply time if it
//! reaches outside that declaration. A key or an entry size that depended on
//! the leaf count would change whenever another transaction landed first, so
//! the second of two transactions simulated against one ledger would fail.
//! Splitting a field of [`TreeState`] back out into its own entry reintroduces
//! that failure.
//!
//! This module is designed to be used internally by the pool contract.
//! Authorization should be handled by the calling main contract before invoking
//! these functions.

use soroban_sdk::{Env, U256, Vec, contracttype};
use soroban_utils::{poseidon2_compress, zero_hash};

/// Number of roots kept in history for proof verification
const ROOT_HISTORY_SIZE: u32 = 90;

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

/// The tree state an insertion mutates, kept in one persistent entry.
///
/// The entry's size is fixed at [`MerkleTreeWithHistory::init`]: `roots`
/// holds `ROOT_HISTORY_SIZE` slots from the first ledger on, and
/// `filled_subtrees` holds one hash per level below the root. For the reason
/// the fields share one entry, see the module documentation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeState {
    /// Next available index for leaf insertion.
    pub next_index: u64,
    /// Left-sibling hashes along the insertion path, element `i` holding
    /// the hash at level `i + 1`.
    pub filled_subtrees: Vec<U256>,
    /// Root history ring, `ROOT_HISTORY_SIZE` slots from `init` onward.
    pub roots: Vec<U256>,
}

/// Storage keys for Merkle tree data
///
/// [`MerkleDataKey::Levels`] is an instance key, so the depth rides the
/// contract instance's lifetime. [`MerkleDataKey::State`] is a persistent
/// key.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MerkleDataKey {
    /// Number of levels in the Merkle tree
    Levels,
    /// The [`TreeState`] entry
    State,
}

/// Returns the root history slot that holds the root produced by the insertion
/// that set the leaf counter to `next_index`.
fn root_index_for(next_index: u64) -> Result<u32, Error> {
    let slot = (next_index / 2)
        .checked_rem(u64::from(ROOT_HISTORY_SIZE))
        .ok_or(Error::Overflow)?;
    u32::try_from(slot).map_err(|_| Error::Overflow)
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
    /// Creates a new Merkle tree with the specified number of levels. Each
    /// left sibling starts at the zero hash of its level, and every root
    /// history slot starts at the zero hash of the top level, which is the
    /// empty tree's root.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `levels` - Number of levels in the Merkle tree (must be in range
    ///   [1..32])
    ///
    /// # Errors
    ///
    /// Returns [`Error::WrongLevels`] if `levels` is zero or above 32,
    /// [`Error::AlreadyInitialized`] if the tree state entry exists, and
    /// [`Error::NotInitialized`] if the zero-hash table has no entry for a
    /// level the tree needs.
    pub fn init(env: &Env, levels: u32) -> Result<(), Error> {
        if levels == 0 || levels > 32 {
            return Err(Error::WrongLevels);
        }
        let storage = env.storage().persistent();

        // Prevent reinitialization
        if storage.has(&MerkleDataKey::State) {
            return Err(Error::AlreadyInitialized);
        }

        // Store levels
        env.storage()
            .instance()
            .set(&MerkleDataKey::Levels, &levels);

        // Only levels 1 to levels - 1 are ever read back: the leaf level is
        // hashed from the two leaves and the top level is the root itself.
        let mut filled_subtrees = Vec::new(env);
        for i in 1..levels {
            filled_subtrees.push_back(zero_hash(env, i).ok_or(Error::NotInitialized)?);
        }

        // Filling every slot fixes the entry's size before the first
        // insertion. The empty root is evicted at the ninetieth insertion
        // either way, since that insertion overwrites slot zero.
        let root_0 = zero_hash(env, levels).ok_or(Error::NotInitialized)?;
        let mut roots = Vec::new(env);
        for _ in 0..ROOT_HISTORY_SIZE {
            roots.push_back(root_0.clone());
        }

        storage.set(
            &MerkleDataKey::State,
            &TreeState {
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

        let levels: u32 = env
            .storage()
            .instance()
            .get(&MerkleDataKey::Levels)
            .ok_or(Error::NotInitialized)?;
        let mut state: TreeState = storage
            .get(&MerkleDataKey::State)
            .ok_or(Error::NotInitialized)?;
        let next_index = state.next_index;
        let max_leaves = 1u64.checked_shl(levels).ok_or(Error::WrongLevels)?;

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

        // Update the tree by recomputing hashes along the path to root
        // Start at level 1 since current_hash is already the parent of the two
        // leaves
        for lvl in 1..levels {
            let is_right = current_index & 1 == 1;
            let slot = lvl.checked_sub(1).ok_or(Error::Overflow)?;
            if is_right {
                // Leaf is right child, get the stored left sibling
                let left = state
                    .filled_subtrees
                    .get(slot)
                    .ok_or(Error::NotInitialized)?;
                current_hash = poseidon2_compress(env, left, current_hash);
            } else {
                // Leaf is left child, store it and pair with zero hash
                state.filled_subtrees.set(slot, current_hash.clone());
                let zero_val = zero_hash(env, lvl).ok_or(Error::NotInitialized)?;
                current_hash = poseidon2_compress(env, current_hash, zero_val);
            }
            current_index >>= 1;
        }

        // The new root goes in the slot the advanced leaf counter names, which
        // is the slot `current_root_index` reads back.
        state.next_index = next_index.checked_add(2).ok_or(Error::Overflow)?;
        state
            .roots
            .set(root_index_for(state.next_index)?, current_hash);
        storage.set(&MerkleDataKey::State, &state);

        // Return the index of the left leaf
        Ok((
            u32::try_from(next_index).map_err(|_| Error::MerkleTreeFull)?,
            u32::try_from(next_index.checked_add(1).ok_or(Error::Overflow)?)
                .map_err(|_| Error::MerkleTreeFull)?,
        ))
    }

    /// Returns the root history slot that holds the current root.
    ///
    /// The leaf counter starts at zero and only [`Self::insert_two_leaves`]
    /// writes it, adding two per insertion. The slot is therefore the counter
    /// halved and taken modulo the history size.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotInitialized`] if the tree has no state entry, and
    /// [`Error::Overflow`] if the counter does not fit the slot arithmetic.
    pub fn current_root_index(env: &Env) -> Result<u32, Error> {
        root_index_for(Self::state(env)?.next_index)
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
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotInitialized`] if the tree has no state entry.
    pub fn is_known_root(env: &Env, root: &U256) -> Result<bool, Error> {
        // Zero root is never valid as define zero in a different way
        if *root == U256::from_u32(env, 0u32) {
            return Ok(false);
        }

        Ok(Self::state(env)?.roots.contains(root))
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
        let state = Self::state(env)?;
        state
            .roots
            .get(root_index_for(state.next_index)?)
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

    /// Returns the tree state entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotInitialized`] if the tree has no state entry.
    fn state(env: &Env) -> Result<TreeState, Error> {
        env.storage()
            .persistent()
            .get(&MerkleDataKey::State)
            .ok_or(Error::NotInitialized)
    }
}
