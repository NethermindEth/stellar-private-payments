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
    gvk::{self, BabyJubJubPoint, GvkCiphertext},
    merkle_with_history::{Error as MerkleError, MerkleTreeWithHistory},
    policy,
};
use contract_types::{Groth16Error, Groth16Proof};
use soroban_sdk::{
    Address, Bytes, BytesN, Env, I256, U256, Vec, contract, contractclient, contracterror,
    contractevent, contractimpl, contracttype, crypto::bn254::Bn254Fr, token::TokenClient,
    xdr::ToXdr,
};
use soroban_utils::constants::bn256_modulus;

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

#[contractclient(crate_path = "soroban_sdk", name = "CircomGroth16VerifierClient")]
pub trait CircomGroth16VerifierInterface {
    fn verify(
        env: Env,
        proof: Groth16Proof,
        public_inputs: Vec<Bn254Fr>,
    ) -> Result<bool, Groth16Error>;
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
    /// GVK ciphertexts for the input notes, optionally present (if GVK mode is set to traceable)
    pub input_gvk_ciphertexts: Vec<GvkCiphertext>,
}

/// External data for a transaction.
///
/// Copied from original pool ExtData
#[contracttype]
#[derive(Clone)]
pub struct ExtData {
    /// Recipient address for withdrawals
    pub recipient: Address,
    /// External amount: positive for deposits, negative for withdrawals
    pub ext_amount: I256,
    /// Encrypted data for the first output UTXO
    pub encrypted_output0: Bytes,
    /// Encrypted data for the second output UTXO
    pub encrypted_output1: Bytes,
}

/// Hash external data using Keccak256, reduced modulo the BN256 field size.
///
/// Copied from `pool::hash_ext_data`.
pub fn hash_ext_data(env: &Env, ext: &ExtData) -> BytesN<32> {
    let payload = ext.clone().to_xdr(env);
    let digest: BytesN<32> = env.crypto().keccak256(&payload).into();
    let digest_u256 = U256::from_be_bytes(env, &Bytes::from(digest));
    let reduced = digest_u256.rem_euclid(&bn256_modulus(env));
    let mut buf = [0u8; 32];
    reduced.to_be_bytes().copy_into_slice(&mut buf);
    BytesN::from_array(env, &buf)
}

/// Event emitted when a new commitment is added to the Merkle tree.
///
/// Copied from `pool::NewCommitmentEvent`.
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
}

/// Event emitted when a nullifier is spent.
///
/// Structurally copied from `pool::NewNullifierEvent`.
#[contractevent]
#[derive(Clone)]
pub struct NewNullifierEvent {
    /// The nullifier that was spent
    #[topic]
    pub nullifier: U256,
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

    /// Convert a U256 into a 32-byte big-endian field element.
    fn u256_to_bytes(env: &Env, v: &U256) -> BytesN<32> {
        let mut buf = [0u8; 32];
        v.to_be_bytes().copy_into_slice(&mut buf);
        BytesN::from_array(env, &buf)
    }

    /// Maximum absolute external amount allowed (2^248).
    fn max_ext_amount(env: &Env) -> U256 {
        U256::from_parts(env, 0x0100_0000_0000_0000, 0, 0, 0)
    }

    /// Convert a non-negative I256 to i128 with bounds checking.
    fn i256_to_i128_nonneg(env: &Env, v: &I256) -> Result<i128, Error> {
        if *v < I256::from_i32(env, 0) {
            return Err(Error::WrongExtAmount);
        }
        v.to_i128().ok_or(Error::WrongExtAmount)
    }

    /// Convert I256 to its absolute value as U256.
    fn i256_abs_to_u256(env: &Env, v: &I256) -> U256 {
        let zero = I256::from_i32(env, 0);
        let abs = if *v >= zero { v.clone() } else { zero.sub(v) };
        U256::from_be_bytes(env, &abs.to_be_bytes())
    }

    /// Calculate the public amount from external amount:
    /// `public_amount = ext_amount` in the BN256 field, wrapping negative
    /// values to `FIELD_SIZE - |ext_amount|`.
    fn calculate_public_amount(env: &Env, ext_amount: I256) -> Result<U256, Error> {
        let abs_ext = Self::i256_abs_to_u256(env, &ext_amount);
        if abs_ext >= Self::max_ext_amount(env) {
            return Err(Error::WrongExtAmount);
        }

        let zero = I256::from_i32(env, 0);

        if ext_amount >= zero {
            let pa_bytes = ext_amount.to_be_bytes();
            Ok(U256::from_be_bytes(env, &pa_bytes))
        } else {
            let neg = zero.sub(&ext_amount);
            let neg_bytes = neg.to_be_bytes();
            let neg_u256 = U256::from_be_bytes(env, &neg_bytes);

            let field = bn256_modulus(env);
            Ok(field.sub(&neg_u256))
        }
    }

    /// Mark a nullifier as spent. Presence of the key is the spent flag.
    fn mark_spent(env: &Env, n: &U256) -> Result<(), Error> {
        let key = DataKey::Nullifier(n.clone());
        env.storage().persistent().set(&key, &());
        Ok(())
    }

    /// Reject values outside the canonical BN254 scalar-field range.
    fn validate_bn256_public_input(value: &U256, modulus: &U256) -> Result<(), Error> {
        if value >= modulus {
            return Err(Error::NonCanonicalPublicInput);
        }
        Ok(())
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
            public_inputs.push_back(Bn254Fr::from_bytes(Self::u256_to_bytes(env, &ct.r.x)));
            public_inputs.push_back(Bn254Fr::from_bytes(Self::u256_to_bytes(env, &ct.r.y)));
        }
        for ct in ciphertexts.iter() {
            public_inputs.push_back(Bn254Fr::from_bytes(Self::u256_to_bytes(env, &ct.c1)));
        }
        for ct in ciphertexts.iter() {
            public_inputs.push_back(Bn254Fr::from_bytes(Self::u256_to_bytes(env, &ct.c2)));
        }
        for ct in ciphertexts.iter() {
            public_inputs.push_back(Bn254Fr::from_bytes(Self::u256_to_bytes(env, &ct.c3)));
        }

        // Declared public inputs: D, nonce, root, publicAmount, extDataHash,
        // inputNullifier[], outputCommitment[]. `nonce` reuses
        // `ext_data_hash` (already checked equal by `internal_transact`).
        public_inputs.push_back(Bn254Fr::from_bytes(Self::u256_to_bytes(
            env,
            &admin_view_key.x,
        )));
        public_inputs.push_back(Bn254Fr::from_bytes(Self::u256_to_bytes(
            env,
            &admin_view_key.y,
        )));
        public_inputs.push_back(Bn254Fr::from_bytes(proof.ext_data_hash.clone()));
        public_inputs.push_back(Bn254Fr::from_bytes(Self::u256_to_bytes(env, &proof.root)));
        public_inputs.push_back(Bn254Fr::from_bytes(Self::u256_to_bytes(
            env,
            &proof.public_amount,
        )));
        public_inputs.push_back(Bn254Fr::from_bytes(proof.ext_data_hash.clone()));
        for nullifier in proof.input_nullifiers.iter() {
            public_inputs.push_back(Bn254Fr::from_bytes(Self::u256_to_bytes(env, &nullifier)));
        }
        public_inputs.push_back(Bn254Fr::from_bytes(Self::u256_to_bytes(
            env,
            &proof.output_commitment0,
        )));
        public_inputs.push_back(Bn254Fr::from_bytes(Self::u256_to_bytes(
            env,
            &proof.output_commitment1,
        )));
        if policy::requires_membership_proofs(policy_flags) {
            for _ in 0..proof.input_nullifiers.len() {
                public_inputs.push_back(Bn254Fr::from_bytes(Self::u256_to_bytes(
                    env,
                    &proof.asp_membership_root,
                )));
            }
        }
        if policy::requires_non_membership_proofs(policy_flags) {
            for _ in 0..proof.input_nullifiers.len() {
                public_inputs.push_back(Bn254Fr::from_bytes(Self::u256_to_bytes(
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
        // making every transaction's nonce unique.
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

        // 6. Mark nullifiers as spent
        for n in proof.input_nullifiers.iter() {
            let _ = Self::mark_spent(env, &n);
            NewNullifierEvent { nullifier: n }.publish(env);
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

        // 9. Emit commitment events
        NewCommitmentEvent {
            commitment: proof.output_commitment0,
            index: idx_0,
            encrypted_output: ext_data.encrypted_output0.clone(),
        }
        .publish(env);

        NewCommitmentEvent {
            commitment: proof.output_commitment1,
            index: idx_1,
            encrypted_output: ext_data.encrypted_output1.clone(),
        }
        .publish(env);

        Ok(())
    }
}
