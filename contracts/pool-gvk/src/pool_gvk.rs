//! Privacy Pool Contract with Global View Key (GVK) support.
//!
//! Same shape as `pool::pool::PoolContract`, extended with an immutable
//! admin view key and GVK mode stored at construction time.
//!
//! `merkle_with_history`/`policy` are local copies of `pool`'s modules
//! rather than a Cargo dependency on the `pool` crate: Soroban's
//! `#[contractimpl]` exports are never dead-code-eliminated, so depending on
//! `pool` at all would drag `PoolContract`'s own exported symbols (`get_root`,
//! `is_known_root`, ...) into this crate's wasm binary and collide at link
//! time with `PoolGvkContract`'s identically-named methods (required for
//! cross-pool-variant SDK/indexer compatibility). Duplicating this
//! infrastructure module is what keeps `contracts/pool` byte-for-byte
//! untouched.
#![allow(clippy::too_many_arguments)]
use crate::{
    gvk::{self, BabyJubJubPoint},
    merkle_with_history::{Error as MerkleError, MerkleTreeWithHistory},
    policy,
};
use soroban_sdk::{
    Address, Env, U256, contract, contractclient, contracterror, contractimpl, contracttype,
};

// Contract clients for cross-contract dependencies. Declared locally rather
// than reused from `pool` for the same reason as `merkle_with_history`/
// `policy` above: `#[contractclient]` itself exports nothing, but importing
// it from `pool` would still pull in the whole `pool` crate.
#[contractclient(crate_path = "soroban_sdk", name = "ASPMembershipClient")]
pub trait ASPMembershipInterface {
    fn get_root(env: Env) -> Result<U256, soroban_sdk::Error>;
}

#[contractclient(crate_path = "soroban_sdk", name = "ASPNonMembershipClient")]
pub trait ASPNonMembershipInterface {
    fn get_root(env: Env) -> Result<U256, soroban_sdk::Error>;
}

/// Contract error types for the GVK privacy pool.
///
/// Duplicated 1:1 from `pool::Error` plus the two GVK-specific variants.
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
    /// Invalid Merkle tree levels configuration
    WrongLevels = 4,
    /// Internal error: next leaf index is not even
    NextIndexNotEven = 5,
    /// External amount is invalid (negative or exceeds 2^248)
    WrongExtAmount = 6,
    /// Zero-knowledge proof verification failed or proof is empty
    InvalidProof = 7,
    /// Provided Merkle root is not in the recent history
    UnknownRoot = 8,
    /// Nullifier has already been spent (double-spend attempt)
    AlreadySpentNullifier = 9,
    /// External data hash does not match the provided data
    WrongExtHash = 10,
    /// Contract is not initialized
    NotInitialized = 11,
    /// Arithmetic overflow occurred
    Overflow = 12,
    /// Public input is not canonical in the BN254 scalar field
    NonCanonicalPublicInput = 13,
    /// Unsupported policy flag bits.
    InvalidPolicyFlags = 14,
    /// Unsupported GVK mode.
    InvalidGvkMode = 15,
    /// Wrong number of GVK ciphertexts for the configured mode.
    WrongGvkCiphertextCount = 16,
}

impl From<MerkleError> for Error {
    fn from(e: MerkleError) -> Self {
        match e {
            MerkleError::AlreadyInitialized => Error::AlreadyInitialized,
            MerkleError::MerkleTreeFull => Error::MerkleTreeFull,
            MerkleError::WrongLevels => Error::WrongLevels,
            MerkleError::NextIndexNotEven => Error::NextIndexNotEven,
            MerkleError::NotInitialized => Error::NotInitialized,
            MerkleError::Overflow => Error::Overflow,
        }
    }
}

/// Storage keys for contract persistent data.
///
/// Everything `pool` stores,
/// plus the immutable `AdminViewKey` and `GvkMode`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DataKey {
    /// Administrator address with permissions to modify contract settings
    Admin,
    /// Address of the token contract used for deposits/withdrawals
    Token,
    /// Address of the ZK proof verifier contract
    Verifier,
    /// Maximum allowed deposit amount per transaction
    MaximumDepositAmount,
    /// Spent nullifier marker keyed by nullifier (presence-only; value unused).
    Nullifier(U256),
    /// Address of the ASP Membership contract
    ASPMembership,
    /// Address of the ASP Non-Membership contract
    ASPNonMembership,
    /// Pool ASP policy flags (bitset; see `crate::policy`).
    PolicyFlags,
    /// Admin's Global View Key public point `D`, set once at construction.
    AdminViewKey,
    /// Global View Key mode (`gvk::VIEW_ONLY` or `gvk::TRACEABLE`).
    GvkMode,
}

/// Privacy Pool Contract with Global View Key support.
#[contract]
pub struct PoolGvkContract;

#[contractimpl]
impl PoolGvkContract {
    /// Constructor: initialize the GVK privacy pool contract.
    ///
    /// Same parameters as `pool::PoolContract::__constructor`, plus the
    /// admin view key and GVK mode. The admin view key is stored as-is and
    /// never updatable afterwards.
    pub fn __constructor(
        env: Env,
        admin: Address,
        token: Address,
        verifier: Address,
        asp_membership: Address,
        asp_non_membership: Address,
        maximum_deposit_amount: U256,
        levels: u32,
        policy_flags: u32,
        admin_view_key: BabyJubJubPoint,
        gvk_mode: u32,
    ) -> Result<(), Error> {
        if !policy::is_valid(policy_flags) {
            return Err(Error::InvalidPolicyFlags);
        }
        if !gvk::is_valid(gvk_mode) {
            return Err(Error::InvalidGvkMode);
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::Token, &token);
        env.storage()
            .persistent()
            .set(&DataKey::Verifier, &verifier);
        env.storage()
            .persistent()
            .set(&DataKey::ASPMembership, &asp_membership);
        env.storage()
            .persistent()
            .set(&DataKey::ASPNonMembership, &asp_non_membership);
        env.storage()
            .persistent()
            .set(&DataKey::MaximumDepositAmount, &maximum_deposit_amount);
        env.storage()
            .persistent()
            .set(&DataKey::PolicyFlags, &policy_flags);
        env.storage()
            .persistent()
            .set(&DataKey::AdminViewKey, &admin_view_key);
        env.storage().persistent().set(&DataKey::GvkMode, &gvk_mode);

        MerkleTreeWithHistory::init(&env, levels)?;

        Ok(())
    }

    /// Get the admin's Global View Key public point `D`.
    pub fn get_admin_view_key(env: &Env) -> Result<BabyJubJubPoint, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::AdminViewKey)
            .ok_or(Error::NotInitialized)
    }

    /// Get the Global View Key mode (`gvk::VIEW_ONLY` or `gvk::TRACEABLE`).
    pub fn get_gvk_mode(env: &Env) -> Result<u32, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::GvkMode)
            .ok_or(Error::NotInitialized)
    }

    /// Get the pool's ASP policy flags.
    pub fn get_policy_flags(env: &Env) -> Result<u32, Error> {
        Self::load_policy_flags(env)
    }

    fn load_policy_flags(env: &Env) -> Result<u32, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::PolicyFlags)
            .ok_or(Error::NotInitialized)
    }

    /// Get the latest root of the Merkle tree that defines the pool.
    pub fn get_root(env: &Env) -> Result<U256, Error> {
        Ok(MerkleTreeWithHistory::get_last_root(env)?)
    }

    /// Check whether a pool Merkle root is still in the recent root history.
    pub fn is_known_root(env: &Env, root: &U256) -> Result<bool, Error> {
        Ok(MerkleTreeWithHistory::is_known_root(env, root)?)
    }

    /// Check whether a nullifier has already been spent.
    ///
    /// Presence of the per-nullifier storage key is the spent flag.
    pub fn is_spent(env: &Env, n: &U256) -> Result<bool, Error> {
        let key = DataKey::Nullifier(n.clone());
        Ok(env.storage().persistent().has(&key))
    }

    /// Update the contract administrator. Requires authorization from the
    /// current admin.
    pub fn update_admin(env: Env, new_admin: Address) -> Result<(), Error> {
        if !env.storage().persistent().has(&DataKey::Admin) {
            return Err(Error::NotInitialized);
        }
        soroban_utils::update_admin(&env, &DataKey::Admin, &new_admin);
        Ok(())
    }

    // ========== ASP Contract Functions ==========

    /// Get the ASP Membership contract address.
    fn get_asp_membership(env: &Env) -> Result<Address, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::ASPMembership)
            .ok_or(Error::NotInitialized)
    }

    /// Get the ASP Non-Membership contract address.
    fn get_asp_non_membership(env: &Env) -> Result<Address, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::ASPNonMembership)
            .ok_or(Error::NotInitialized)
    }

    /// Get the current Merkle root from the ASP Membership contract.
    pub fn get_asp_membership_root(env: &Env) -> Result<U256, Error> {
        let asp_address = Self::get_asp_membership(env)?;
        let client = ASPMembershipClient::new(env, &asp_address);
        Ok(client.get_root())
    }

    /// Get the current Merkle root from the ASP Non-Membership contract.
    pub fn get_asp_non_membership_root(env: &Env) -> Result<U256, Error> {
        let asp_address = Self::get_asp_non_membership(env)?;
        let client = ASPNonMembershipClient::new(env, &asp_address);
        Ok(client.get_root())
    }
}
