//! Privacy Pool Contract with Global View Key (GVK) support.
//!
//! Same shape as `pool::pool::PoolContract`, extended with an immutable
//! admin view key and GVK mode stored at construction time.
//!
//! The Merkle tree, policy flags, `ExtData`, and the cross-contract client
//! traits come from `pool-core`, shared with `contracts/pool`. They live there
//! rather than in either contract crate because Soroban's `#[contractimpl]`
//! exports are never dead-code-eliminated: a dependency edge onto `pool`
//! itself would drag `PoolContract`'s exported symbols (`get_root`,
//! `is_known_root`, ...) into this crate's wasm and collide at link time with
//! `PoolGvkContract`'s identically-named methods, which must keep those names
//! for cross-pool-variant SDK/indexer compatibility. `pool-core` declares no
//! `#[contract]`/`#[contractimpl]`, so it carries no exports to collide.
#![allow(clippy::too_many_arguments)]
use crate::gvk::{self, BabyJubJubPoint, GvkCiphertext};
use contract_types::Groth16Proof;
use pool_core::{
    ASPMembershipClient, ASPNonMembershipClient, CircomGroth16VerifierClient, amounts,
    merkle_with_history::{Error as MerkleError, MerkleTreeWithHistory},
    policy,
};
use soroban_sdk::{
    Address, Bytes, BytesN, Env, I256, U256, Vec, contract, contracterror, contractevent,
    contractimpl, contracttype, crypto::bn254::Bn254Fr, token::TokenClient,
};
use soroban_utils::constants::bn256_modulus;

// Re-exported rather than merely imported so `pool_gvk::ExtData` and
// `pool_gvk::hash_ext_data` stay part of this crate's surface, mirroring
// `pool`.
pub use pool_core::{ExtData, hash_ext_data};

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
    /// Admin view key `D` is unusable as a circuit public input.
    InvalidAdminViewKey = 17,
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
/// Everything `pool` stores, plus the immutable `AdminViewKey` and `GvkMode`.
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
    ///
    /// Immutable by design (issue #220): there is no setter, and
    /// `update_admin` rotates only the admin *address*. A rotated-out admin
    /// therefore keeps the ability to decrypt every future note, and a leaked
    /// private `d` retroactively deanonymizes the pool's whole history — the
    /// only recovery is deploying a new pool and migrating. `D` is a circuit
    /// public input, so forward-only rotation would be circuit-compatible if
    /// this trade is ever revisited.
    AdminViewKey,
    /// Global View Key mode (`gvk::VIEW_ONLY` or `gvk::TRACEABLE`).
    GvkMode,
}

/// Zero-knowledge proof data for a GVK transaction.
///
/// `pool::Proof`'s fields plus the per-note GVK ciphertexts. These are proof
/// *outputs* verified by the SNARK (like `output_commitment0/1`), so they
/// belong here rather than on `ExtData`.
#[contracttype]
pub struct Proof {
    /// The serialized zero-knowledge proof
    pub proof: Groth16Proof,
    /// Merkle root the proof was generated against
    pub root: U256,
    /// Nullifiers for spent input UTXOs
    pub input_nullifiers: Vec<U256>,
    /// Commitment for the first output UTXO
    pub output_commitment0: U256,
    /// Commitment for the second output UTXO
    pub output_commitment1: U256,
    /// Net public amount
    pub public_amount: U256,
    /// Hash of the external data (binds proof to transaction parameters).
    /// Also fed into the circuit's `nonce` public input
    pub ext_data_hash: BytesN<32>,
    /// Merkle root the policy membership proof was generated against
    pub asp_membership_root: U256,
    /// Merkle root the policy NON-membership proof was generated against
    pub asp_non_membership_root: U256,
    /// GVK ciphertexts for the output notes, always present.
    pub output_gvk_ciphertexts: Vec<GvkCiphertext>,
    /// GVK ciphertexts for the input notes: present iff `gvk_mode ==
    /// TRACEABLE`, empty otherwise.
    pub input_gvk_ciphertexts: Vec<GvkCiphertext>,
}

/// Event emitted when a new commitment is added to the Merkle tree.
///
/// `pool::NewCommitmentEvent`'s fields plus `gvk_ciphertext`: unlike `pool`,
/// this crate always encrypts every output note (both `VIEW_ONLY` and
/// `TRACEABLE` modes), so the field is mandatory, not optional — there is no
/// separate trailing "memo" event, since this local copy of
/// `NewCommitmentEvent` isn't shared with non-GVK pools and carries no
/// schema-compatibility risk to protect.
#[contractevent]
#[derive(Clone)]
pub struct NewCommitmentEvent {
    /// The commitment hash added to the tree
    #[topic]
    pub commitment: U256,
    /// Index position in the Merkle tree
    pub index: u32,
    /// Encrypted output data (decryptable by the recipient)
    pub encrypted_output: Bytes,
    /// GVK ciphertext of this output note, decryptable by the pool admin
    pub gvk_ciphertext: GvkCiphertext,
}

/// Event emitted when a nullifier is spent.
///
/// `pool::NewNullifierEvent`'s field plus `gvk_ciphertext`, present (`Some`)
/// only in `TRACEABLE` mode — `VIEW_ONLY` never encrypts input notes. This is
/// the one genuinely optional piece of GVK data in this crate's events.
#[contractevent]
#[derive(Clone)]
pub struct NewNullifierEvent {
    /// The nullifier that was spent
    #[topic]
    pub nullifier: U256,
    /// GVK ciphertext of this input note, decryptable by the admin;
    /// `None` outside `TRACEABLE` mode
    pub gvk_ciphertext: Option<GvkCiphertext>,
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
        Self::validate_admin_view_key(&env, &admin_view_key)?;
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

    /// Reject an admin view key that could never produce a verifiable proof.
    ///
    /// Checked once here rather than in `verify_proof`, since `AdminViewKey`
    /// is written only by the constructor and has no setter.
    ///
    /// Two cheap checks:
    /// - canonical range
    /// - `x != 0`: the only on-curve points with `x == 0` are `(0, 1)` and `(0,
    ///   -1)`, both low-order and both already rejected in-circuit, so this
    ///   excludes nothing legitimate. It does catch the likely mistake of
    ///   deploying with an all-zero point.
    ///
    /// Full on-curve/subgroup validation is deliberately *not* done here: `D`
    /// is a circuit public input, so `BabyCheck` and the low-order guard
    /// already run on every proof.
    fn validate_admin_view_key(env: &Env, key: &BabyJubJubPoint) -> Result<(), Error> {
        let modulus = bn256_modulus(env);
        if key.x >= modulus || key.y >= modulus {
            return Err(Error::InvalidAdminViewKey);
        }
        if key.x == U256::from_u32(env, 0) {
            return Err(Error::InvalidAdminViewKey);
        }
        Ok(())
    }

    /// Get the admin's Global View Key public point `D`.
    ///
    /// Read-only and unauthenticated on purpose: `D` is a circuit public
    /// input and is published in every proof, so it is not secret. There is
    /// no corresponding setter — see [`DataKey::AdminViewKey`].
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
    //
    // `pool` also exports `update_asp_membership`/`update_asp_non_membership`;
    // this crate deliberately does not. A `pool-gvk` pool can therefore never
    // repoint its ASP contracts after construction, unlike a `pool` one — a
    // deployment-time constraint, not an oversight. Nothing in the repo calls
    // those two methods today; add them here if that changes.

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

    /// Get the token contract address.
    fn get_token(env: &Env) -> Result<Address, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Token)
            .ok_or(Error::NotInitialized)
    }

    /// Get the maximum deposit amount.
    fn get_maximum_deposit(env: &Env) -> Result<U256, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::MaximumDepositAmount)
            .ok_or(Error::NotInitialized)
    }

    /// Get the verifier contract address.
    fn get_verifier(env: &Env) -> Result<Address, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Verifier)
            .ok_or(Error::NotInitialized)
    }

    /// Convert a non-negative I256 to i128 with bounds checking.
    fn i256_to_i128_nonneg(env: &Env, v: &I256) -> Result<i128, Error> {
        amounts::i256_to_i128_nonneg(env, v).ok_or(Error::WrongExtAmount)
    }

    /// Calculate the public amount from external amount:
    /// `public_amount = ext_amount` in the BN256 field, wrapping negative
    /// values to `FIELD_SIZE - |ext_amount|`.
    fn calculate_public_amount(env: &Env, ext_amount: I256) -> Result<U256, Error> {
        amounts::calculate_public_amount(env, ext_amount).ok_or(Error::WrongExtAmount)
    }

    /// Mark a nullifier as spent. Presence of the key is the spent flag.
    fn mark_spent(env: &Env, n: &U256) -> Result<(), Error> {
        let key = DataKey::Nullifier(n.clone());
        env.storage().persistent().set(&key, &());
        Ok(())
    }

    /// Reject values outside the canonical BN254 scalar-field range.
    fn validate_bn256_public_input(value: &U256, modulus: &U256) -> Result<(), Error> {
        if amounts::is_canonical_bn256_public_input(value, modulus) {
            Ok(())
        } else {
            Err(Error::NonCanonicalPublicInput)
        }
    }

    /// Validate a ciphertext's `r.x`, `r.y`, `c1`, `c2`, `c3` fields.
    fn validate_gvk_ciphertext(ct: &GvkCiphertext, modulus: &U256) -> Result<(), Error> {
        Self::validate_bn256_public_input(&ct.r.x, modulus)?;
        Self::validate_bn256_public_input(&ct.r.y, modulus)?;
        Self::validate_bn256_public_input(&ct.c1, modulus)?;
        Self::validate_bn256_public_input(&ct.c2, modulus)?;
        Self::validate_bn256_public_input(&ct.c3, modulus)?;
        Ok(())
    }

    /// Validate every `U256` field that contributes to the verifier's public
    /// input vector: the base pool fields plus every GVK ciphertext field.
    /// The transaction path checks `ext_data_hash` against `hash_ext_data`
    /// before proof verification, so this covers the remaining public-input
    /// values.
    fn validate_bn256_public_inputs(
        _env: &Env,
        proof: &Proof,
        policy_flags: u32,
        modulus: &U256,
    ) -> Result<(), Error> {
        Self::validate_bn256_public_input(&proof.root, modulus)?;
        Self::validate_bn256_public_input(&proof.public_amount, modulus)?;
        for nullifier in proof.input_nullifiers.iter() {
            Self::validate_bn256_public_input(&nullifier, modulus)?;
        }
        Self::validate_bn256_public_input(&proof.output_commitment0, modulus)?;
        Self::validate_bn256_public_input(&proof.output_commitment1, modulus)?;
        if policy::requires_membership_proofs(policy_flags) {
            Self::validate_bn256_public_input(&proof.asp_membership_root, modulus)?;
        }
        if policy::requires_non_membership_proofs(policy_flags) {
            Self::validate_bn256_public_input(&proof.asp_non_membership_root, modulus)?;
        }
        for ct in proof.input_gvk_ciphertexts.iter() {
            Self::validate_gvk_ciphertext(&ct, modulus)?;
        }
        for ct in proof.output_gvk_ciphertexts.iter() {
            Self::validate_gvk_ciphertext(&ct, modulus)?;
        }

        Ok(())
    }

    /// Validate the ciphertext vector lengths against the configured GVK
    /// mode: `output_gvk_ciphertexts` always covers both output notes;
    /// `input_gvk_ciphertexts` covers every input note iff `gvk_mode ==
    /// TRACEABLE`, and must be empty otherwise.
    fn validate_gvk_ciphertext_counts(proof: &Proof, gvk_mode: u32) -> Result<(), Error> {
        if proof.output_gvk_ciphertexts.len() != 2 {
            return Err(Error::WrongGvkCiphertextCount);
        }
        let expected_inputs = if gvk::requires_input_encryption(gvk_mode) {
            proof.input_nullifiers.len()
        } else {
            0
        };
        if proof.input_gvk_ciphertexts.len() != expected_inputs {
            return Err(Error::WrongGvkCiphertextCount);
        }
        Ok(())
    }

    /// Verify a zero-knowledge proof.
    ///
    /// Public inputs are assembled in the order measured (not merely
    /// source-read) off `policy_tx_gvk_2_2_viewonly`/`_traceable`: the GVK
    /// ciphertext tail (an *output* signal) comes first, then the declared
    /// public inputs `D, nonce, root, publicAmount, extDataHash,
    /// inputNullifier[], outputCommitment[]`, then any ASP roots for the A/B/
    /// AB variants — see `circuits/src/test/prove_policy.rs::
    /// run_policy_gvk_public_input_order`.
    ///
    /// `D` always comes from this contract's own immutably-stored
    /// `AdminViewKey`, never from caller-supplied data — there is no `D`
    /// field on `Proof` at all, so a caller cannot influence it.
    fn verify_proof(env: &Env, proof: &Proof) -> Result<bool, Error> {
        if proof.proof.is_empty() {
            return Err(Error::InvalidProof);
        }
        let policy_flags = Self::load_policy_flags(env)?;
        let gvk_mode = Self::load_gvk_mode(env)?;
        let admin_view_key = Self::get_admin_view_key(env)?;
        let verifier = Self::get_verifier(env)?;
        let client = CircomGroth16VerifierClient::new(env, &verifier);
        Self::validate_gvk_ciphertext_counts(proof, gvk_mode)?;
        Self::validate_bn256_public_inputs(env, proof, policy_flags, &bn256_modulus(env))?;

        let mut public_inputs: Vec<Bn254Fr> = Vec::new(env);

        // Ciphertext tail: input ciphertexts (traceable only) then output
        // ciphertexts, field-major (all R pairs, then all c1s, c2s, c3s).
        let mut ciphertexts: Vec<GvkCiphertext> = Vec::new(env);
        for ct in proof.input_gvk_ciphertexts.iter() {
            ciphertexts.push_back(ct);
        }
        for ct in proof.output_gvk_ciphertexts.iter() {
            ciphertexts.push_back(ct);
        }
        for ct in ciphertexts.iter() {
            public_inputs.push_back(Bn254Fr::from_bytes(amounts::u256_to_bytes(env, &ct.r.x)));
            public_inputs.push_back(Bn254Fr::from_bytes(amounts::u256_to_bytes(env, &ct.r.y)));
        }
        for ct in ciphertexts.iter() {
            public_inputs.push_back(Bn254Fr::from_bytes(amounts::u256_to_bytes(env, &ct.c1)));
        }
        for ct in ciphertexts.iter() {
            public_inputs.push_back(Bn254Fr::from_bytes(amounts::u256_to_bytes(env, &ct.c2)));
        }
        for ct in ciphertexts.iter() {
            public_inputs.push_back(Bn254Fr::from_bytes(amounts::u256_to_bytes(env, &ct.c3)));
        }

        // Declared public inputs: D, nonce, root, publicAmount, extDataHash,
        // inputNullifier[], outputCommitment[]. `nonce` reuses
        // `ext_data_hash` (already checked equal by `internal_transact`).
        public_inputs.push_back(Bn254Fr::from_bytes(amounts::u256_to_bytes(
            env,
            &admin_view_key.x,
        )));
        public_inputs.push_back(Bn254Fr::from_bytes(amounts::u256_to_bytes(
            env,
            &admin_view_key.y,
        )));
        public_inputs.push_back(Bn254Fr::from_bytes(proof.ext_data_hash.clone()));
        public_inputs.push_back(Bn254Fr::from_bytes(amounts::u256_to_bytes(
            env,
            &proof.root,
        )));
        public_inputs.push_back(Bn254Fr::from_bytes(amounts::u256_to_bytes(
            env,
            &proof.public_amount,
        )));
        public_inputs.push_back(Bn254Fr::from_bytes(proof.ext_data_hash.clone()));
        for nullifier in proof.input_nullifiers.iter() {
            public_inputs.push_back(Bn254Fr::from_bytes(amounts::u256_to_bytes(env, &nullifier)));
        }
        public_inputs.push_back(Bn254Fr::from_bytes(amounts::u256_to_bytes(
            env,
            &proof.output_commitment0,
        )));
        public_inputs.push_back(Bn254Fr::from_bytes(amounts::u256_to_bytes(
            env,
            &proof.output_commitment1,
        )));
        if policy::requires_membership_proofs(policy_flags) {
            for _ in 0..proof.input_nullifiers.len() {
                public_inputs.push_back(Bn254Fr::from_bytes(amounts::u256_to_bytes(
                    env,
                    &proof.asp_membership_root,
                )));
            }
        }
        if policy::requires_non_membership_proofs(policy_flags) {
            for _ in 0..proof.input_nullifiers.len() {
                public_inputs.push_back(Bn254Fr::from_bytes(amounts::u256_to_bytes(
                    env,
                    &proof.asp_non_membership_root,
                )));
            }
        }

        let is_valid = client.verify(&proof.proof, &public_inputs);

        Ok(is_valid)
    }

    /// Get the GVK mode, for internal use where the getter's `Result`
    /// wrapping would otherwise need re-mapping.
    fn load_gvk_mode(env: &Env) -> Result<u32, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::GvkMode)
            .ok_or(Error::NotInitialized)
    }

    /// Execute a shielded transaction with deposit handling.
    ///
    /// If `ext_amount > 0`, tokens are transferred from the sender to the
    /// pool before processing the transaction.
    pub fn transact(
        env: &Env,
        proof: Proof,
        ext_data: ExtData,
        sender: Address,
    ) -> Result<(), Error> {
        sender.require_auth();
        let token = Self::get_token(env)?;
        let token_client = TokenClient::new(env, &token);
        let zero = I256::from_i32(env, 0);

        if ext_data.ext_amount > zero {
            let deposit_u = U256::from_be_bytes(env, &ext_data.ext_amount.to_be_bytes());
            let max = Self::get_maximum_deposit(env)?;
            if deposit_u > max {
                return Err(Error::WrongExtAmount);
            }
            let this = env.current_contract_address();
            let amount = Self::i256_to_i128_nonneg(env, &ext_data.ext_amount)?;
            token_client.transfer(&sender, &this, &amount);
        }

        Self::internal_transact(env, proof, ext_data)
    }

    /// Process a private transaction: validates the proof and all public
    /// inputs, marks nullifiers as spent, processes withdrawals, and inserts
    /// new commitments into the Merkle tree.
    fn internal_transact(env: &Env, proof: Proof, ext_data: ExtData) -> Result<(), Error> {
        // 1. Merkle root check
        if !MerkleTreeWithHistory::is_known_root(env, &proof.root)? {
            return Err(Error::UnknownRoot);
        }
        // 2. Nullifier checks (prevent double-spending)
        for n in proof.input_nullifiers.iter() {
            if Self::is_spent(env, &n)? {
                return Err(Error::AlreadySpentNullifier);
            }
        }
        // 3. External data hash check. This is also the value the circuit's
        // `nonce` public input is required to equal (see `verify_proof`),
        // which *binds* the nonce to this transaction's parameters. It does
        // not make the nonce unique: `hash_ext_data` is a deterministic
        // function of caller-chosen `ExtData`, so two transactions with
        // identical `ExtData` share a nonce. `globalViewKey.circom` asks the
        // contract for uniqueness, and this does not provide it — but the
        // property that matters is upheld elsewhere: the ciphertext's
        // ephemeral scalar is derived as
        // `H(pk, amount, blinding, salt, D, nonce, idx)`, and `blinding` is
        // fresh per output note, so colliding `(R, c)` additionally requires
        // an identical note *and* salt. Only a prover can arrange that, and
        // only against their own privacy.
        let ext_hash = hash_ext_data(env, &ext_data);
        if ext_hash != proof.ext_data_hash {
            return Err(Error::WrongExtHash);
        }

        // 4. Public amount check
        let expected_public_amount =
            Self::calculate_public_amount(env, ext_data.ext_amount.clone())?;
        if proof.public_amount != expected_public_amount {
            return Err(Error::WrongExtAmount);
        }

        // ASP root validation
        let policy_flags = Self::load_policy_flags(env)?;
        if policy::requires_non_membership_proofs(policy_flags) {
            let non_member_root = Self::get_asp_non_membership_root(env)?;
            if non_member_root != proof.asp_non_membership_root {
                return Err(Error::InvalidProof);
            }
        }
        if policy::requires_membership_proofs(policy_flags) {
            let member_root = Self::get_asp_membership_root(env)?;
            if member_root != proof.asp_membership_root {
                return Err(Error::InvalidProof);
            }
        }

        // 5. ZK proof verification (includes the GVK ciphertext-count and
        // canonical-range checks)
        if !Self::verify_proof(env, &proof)? {
            return Err(Error::InvalidProof);
        }

        // 6. Mark nullifiers as spent. `input_gvk_ciphertexts` is either empty
        // (view-only) or exactly as long as `input_nullifiers` (traceable) —
        // already enforced by `verify_proof`'s ciphertext-count check above —
        // so a non-empty vec means every nullifier has a matching ciphertext
        // at the same index.
        let has_input_ciphertexts = !proof.input_gvk_ciphertexts.is_empty();
        for i in 0..proof.input_nullifiers.len() {
            let n = proof
                .input_nullifiers
                .get(i)
                .expect("index within input_nullifiers bounds");
            let _ = Self::mark_spent(env, &n);
            let gvk_ciphertext = if has_input_ciphertexts {
                Some(proof.input_gvk_ciphertexts.get(i).expect(
                    "input_gvk_ciphertexts length already validated equal to input_nullifiers",
                ))
            } else {
                None
            };
            NewNullifierEvent {
                nullifier: n,
                gvk_ciphertext,
            }
            .publish(env);
        }

        // 7. Process withdrawal if ext_amount < 0
        let token = Self::get_token(env)?;
        let token_client = TokenClient::new(env, &token);
        let this = env.current_contract_address();
        let zero = I256::from_i32(env, 0);

        if ext_data.ext_amount < zero {
            let abs = zero.sub(&ext_data.ext_amount);
            let amount: i128 = Self::i256_to_i128_nonneg(env, &abs)?;
            token_client.transfer(&this, &ext_data.recipient, &amount);
        }

        // 8. Insert new commitments into Merkle tree
        let (idx_0, idx_1) = MerkleTreeWithHistory::insert_two_leaves(
            env,
            proof.output_commitment0.clone(),
            proof.output_commitment1.clone(),
        )?;

        // 9. Emit commitment events, each carrying its GVK ciphertext
        // (always present: both view-only and traceable modes encrypt every
        // output note).
        NewCommitmentEvent {
            commitment: proof.output_commitment0,
            index: idx_0,
            encrypted_output: ext_data.encrypted_output0.clone(),
            gvk_ciphertext: proof
                .output_gvk_ciphertexts
                .get(0)
                .expect("output_gvk_ciphertexts length already validated to be 2"),
        }
        .publish(env);

        NewCommitmentEvent {
            commitment: proof.output_commitment1,
            index: idx_1,
            encrypted_output: ext_data.encrypted_output1.clone(),
            gvk_ciphertext: proof
                .output_gvk_ciphertexts
                .get(1)
                .expect("output_gvk_ciphertexts length already validated to be 2"),
        }
        .publish(env);

        Ok(())
    }
}
