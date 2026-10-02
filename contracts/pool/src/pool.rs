//! Privacy Pool Contract
//!
//! This contract implements a privacy-preserving transaction pool with embedded
//! policy (membership and non-membership in an association set).
//! It enables users to deposit, transfer, and withdraw
//! tokens while maintaining transaction privacy through zero-knowledge proofs.
//!
//! # Architecture
//!
//! The contract maintains:
//! - A Merkle tree of commitments (via `MerkleTreeWithHistory`)
//! - A nullifier set to track spent UTXOs
//! - Token integration for deposits and withdrawals

#![allow(clippy::too_many_arguments)]
use contract_types::Groth16Proof;
use pool_core::{
    ASPMembershipClient, ASPNonMembershipClient, CircomGroth16VerifierClient, amounts,
    merkle_with_history::{Error as MerkleError, MerkleTreeWithHistory},
    policy, validation,
};
use soroban_sdk::{
    Address, Bytes, BytesN, Env, I256, U256, Vec, contract, contracterror, contractevent,
    contractimpl, contracttype, crypto::bn254::Bn254Fr, token::TokenClient,
};
use soroban_utils::constants::bn256_modulus;

// Re-exported rather than merely imported so `pool::ExtData` and
// `pool::hash_ext_data` keep resolving for existing consumers (`e2e-tests`,
// the SDK encoding tests) after the move into `pool-core`.
pub use pool_core::{ExtData, hash_ext_data};

/// Contract error types for the privacy pool
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
}

/// Conversion from MerkleTreeWithHistory errors to pool contract errors
/// Errors from MerkleTreeWithHistory are not `contracterror`
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

impl From<validation::Error> for Error {
    fn from(e: validation::Error) -> Self {
        match e {
            validation::Error::WrongExtAmount => Error::WrongExtAmount,
            validation::Error::InvalidProof => Error::InvalidProof,
            validation::Error::UnknownRoot => Error::UnknownRoot,
            validation::Error::AlreadySpentNullifier => Error::AlreadySpentNullifier,
            validation::Error::WrongExtHash => Error::WrongExtHash,
            validation::Error::NotInitialized => Error::NotInitialized,
            validation::Error::NonCanonicalPublicInput => Error::NonCanonicalPublicInput,
        }
    }
}

/// Zero-knowledge proof data for a transaction
///
/// Contains all the cryptographic data needed to verify a transaction,
/// including the proof itself, public inputs, and nullifiers.
#[contracttype]
pub struct Proof {
    /// The serialized zero-knowledge proof
    pub proof: Groth16Proof,
    /// Merkle root the proof was generated against
    pub root: U256,
    /// Nullifiers for spent input UTXOs (prevents double-spending)
    pub input_nullifiers: Vec<U256>,
    /// Commitment for the first output UTXO
    pub output_commitment0: U256,
    /// Commitment for the second output UTXO
    pub output_commitment1: U256,
    /// Net public amount (deposit - withdrawal, modulo field size)
    pub public_amount: U256,
    /// Hash of the external data (binds proof to transaction parameters)
    pub ext_data_hash: BytesN<32>,
    /// Merkle root the policy membership proof was generated against
    pub asp_membership_root: U256,
    /// Merkle root the policy NON-membership proof was generated against
    pub asp_non_membership_root: U256,
}

/// Storage keys for contract data
///
/// The configuration the constructor writes, [`DataKey::Token`],
/// [`DataKey::Verifier`], [`DataKey::MaximumDepositAmount`],
/// [`DataKey::ASPMembership`], [`DataKey::ASPNonMembership`], and
/// [`DataKey::PolicyFlags`], lives in the contract's instance entry.
/// [`DataKey::Admin`] and [`DataKey::Nullifier`] are persistent keys.
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
}

/// Event emitted when a new commitment is added to the Merkle tree
///
/// This event allows off-chain observers to track new UTXOs and decrypt
/// outputs intended for them.
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

/// Event emitted when a nullifier is spent
///
/// This event allows off-chain observers to track which UTXOs have been spent.
#[contractevent]
#[derive(Clone)]
pub struct NewNullifierEvent {
    /// The nullifier that was spent
    #[topic]
    pub nullifier: U256,
}

/// Privacy Pool Contract
///
/// Implements a private transaction pool.
/// Users can deposit tokens, perform private transfers, and withdraw while
/// maintaining transaction privacy through zero-knowledge proofs.
#[contract]
pub struct PoolContract;

#[contractimpl]
impl PoolContract {
    /// Constructor: initialize the privacy pool contract
    ///
    /// Sets up the contract with the specified token, verifier, and Merkle tree
    /// configuration. This function can only be called once.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `admin` - Address of the contract administrator
    /// * `token` - Address of the token contract for deposits/withdrawals
    /// * `verifier` - Address of the ZK proof verifier contract
    /// * `asp_membership` - Address of the ASP Membership contract
    /// * `asp_non_membership` - Address of the ASP Non-Membership contract
    /// * `maximum_deposit_amount` - Maximum allowed deposit per transaction
    /// * `levels` - Number of levels in the commitment Merkle tree (1-32)
    /// * `policy_flags` - ASP policy flag bitset enforced by the transact
    ///   circuit
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success, or an error if already initialized or
    /// invalid configuration
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
    ) -> Result<(), Error> {
        if !policy::is_valid(policy_flags) {
            return Err(Error::InvalidPolicyFlags);
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
        let instance = env.storage().instance();
        instance.set(&DataKey::Token, &token);
        instance.set(&DataKey::Verifier, &verifier);
        instance.set(&DataKey::ASPMembership, &asp_membership);
        instance.set(&DataKey::ASPNonMembership, &asp_non_membership);
        instance.set(&DataKey::MaximumDepositAmount, &maximum_deposit_amount);
        instance.set(&DataKey::PolicyFlags, &policy_flags);

        // Initialize the Merkle tree for commitment storage
        MerkleTreeWithHistory::init(&env, levels)?;

        Ok(())
    }

    /// Convert a non-negative I256 to i128 with bounds checking
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `v` - The I256 value to convert
    ///
    /// # Returns
    ///
    /// Returns `Ok(i128)` if the value is non-negative and fits in i128,
    /// or `Err(Error::WrongExtAmount)` otherwise
    fn i256_to_i128_nonneg(env: &Env, v: &I256) -> Result<i128, Error> {
        amounts::i256_to_i128_nonneg(env, v).ok_or(Error::WrongExtAmount)
    }

    /// Mark a nullifier as spent
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `n` - The nullifier to mark as spent
    fn mark_spent(env: &Env, n: &U256) -> Result<(), Error> {
        let key = DataKey::Nullifier(n.clone());
        // Presence of the key is the spent flag; value is unused.
        env.storage().persistent().set(&key, &());
        Ok(())
    }

    /// Validate every `U256` field that contributes to the verifier's public
    /// input vector. The transaction path checks `ext_data_hash` against
    /// `hash_ext_data` before proof verification, so this covers the remaining
    /// public-input values.
    fn validate_bn256_public_inputs(
        _env: &Env,
        proof: &Proof,
        policy_flags: u32,
        modulus: &U256,
    ) -> Result<(), Error> {
        Ok(validation::validate_base_bn256_public_inputs(
            &proof.root,
            &proof.public_amount,
            &proof.input_nullifiers,
            &proof.output_commitment0,
            &proof.output_commitment1,
            &proof.asp_membership_root,
            &proof.asp_non_membership_root,
            policy_flags,
            modulus,
        )?)
    }

    /// Verify a zero-knowledge proof
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `proof` - The proof to verify
    ///
    /// # Returns
    ///
    /// Returns `true` if the proof is valid, and `Err(Error::InvalidProof)` if
    /// the verifier refuses it. The verifier never answers `false`: every
    /// rejection is a `Groth16Error`, so that error is translated here rather
    /// than allowed to cross the contract boundary raw.
    fn verify_proof(env: &Env, proof: &Proof) -> Result<bool, Error> {
        // Check proof is not empty
        if proof.proof.is_empty() {
            return Err(Error::InvalidProof);
        }
        let policy_flags = Self::load_policy_flags(env)?;
        let verifier = Self::get_verifier(env)?;
        let client = CircomGroth16VerifierClient::new(env, &verifier);
        Self::validate_bn256_public_inputs(env, proof, policy_flags, &bn256_modulus(env))?;

        // Public inputs must match the policy circuit:
        // [root, public_amount, ext_data_hash, input_nullifiers,
        // output_commitments, membership_roots?, non_membership_roots]
        let mut public_inputs: Vec<Bn254Fr> = Vec::new(env);
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

        // `try_verify`, not `verify`. `Groth16Error` and this contract's
        // `Error` are separate `#[repr(u32)]` enums whose codes overlap:
        // `MalformedPublicInputs` is 1 and so is `NotAuthorized`,
        // `MalformedProof` is 2 and so is `MerkleTreeFull`. A plain `verify`
        // lets a verifier rejection trap out of this frame carrying the
        // verifier's own code, and the caller reads that code against the
        // pool's enum — a refused proof arrives as an authorization failure.
        // Catching the call here keeps the pool's errors the pool's own.
        match client.try_verify(&proof.proof, &public_inputs) {
            Ok(Ok(is_valid)) => Ok(is_valid),
            _ => Err(Error::InvalidProof),
        }
    }

    /// Execute a shielded transaction with deposit handling
    ///
    /// This is the main entry point for users to interact with the pool.
    /// If `ext_amount > 0`, tokens are transferred from the sender to the pool
    /// before processing the transaction.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `proof` - Zero-knowledge proof and public inputs
    /// * `ext_data` - External transaction data
    /// * `sender` - Address of the transaction sender (must authorize funding
    ///   transaction)
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success, or an error if validation fails
    pub fn transact(
        env: &Env,
        proof: Proof,
        ext_data: ExtData,
        sender: Address,
    ) -> Result<(), Error> {
        // 1. Authenticate sender
        sender.require_auth();
        // The tree entry is rewritten below; keep the configuration it
        // reads on the same lifetime.
        pool_core::extend_instance(env);

        Self::internal_transact(env, proof, ext_data, &sender)
    }

    /// Process a private transaction
    ///
    /// Validates the proof and all public inputs, processes deposits (only
    /// after validation succeeds), marks nullifiers as spent, processes
    /// withdrawals, and inserts new commitments into the Merkle tree.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `proof` - Zero-knowledge proof and public inputs
    /// * `ext_data` - External transaction data
    /// * `sender` - Address of the transaction sender
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success, or an error if any validation fails
    ///
    /// # Validation & Execution Steps
    ///
    /// 1. Perform all transaction validation and proof verification
    /// 2. Only if validation succeeds, perform deposit token transfer
    /// 3. Complete the state-changing transaction (nullifiers, withdrawal,
    ///    tree)
    fn internal_transact(
        env: &Env,
        proof: Proof,
        ext_data: ExtData,
        sender: &Address,
    ) -> Result<(), Error> {
        // 1. Validate deposit amount limits
        let max_deposit = Self::get_maximum_deposit(env)?;
        let deposit_amount =
            validation::validate_deposit_amount(env, &ext_data.ext_amount, &max_deposit)?;

        // 2. Merkle root check
        validation::validate_root(env, &proof.root)?;

        // 3. Nullifier checks (prevent double-spending)
        validation::validate_nullifiers(&proof.input_nullifiers, |n| Self::is_spent(env, n))?;

        // 4. External data hash check, bound to this pool's address and its
        // own configured token, so a hash computed for another pool or token
        // cannot match here.
        let token = Self::get_token(env)?;
        validation::validate_ext_data_hash(env, &ext_data, &token, &proof.ext_data_hash)?;

        // 5. Public amount check
        validation::validate_public_amount(env, &ext_data.ext_amount, &proof.public_amount)?;

        // 6. ASP root validation
        let policy_flags = Self::load_policy_flags(env)?;
        let asp_membership = Self::get_asp_membership(env)?;
        let asp_non_membership = Self::get_asp_non_membership(env)?;
        validation::validate_asp_roots(
            env,
            policy_flags,
            &asp_membership,
            &asp_non_membership,
            &proof.asp_membership_root,
            &proof.asp_non_membership_root,
        )?;

        // 7. ZK proof verification
        if !Self::verify_proof(env, &proof)? {
            return Err(Error::InvalidProof);
        }

        // 8. Only if validation succeeds, perform deposit token transfer
        if let Some(amount) = deposit_amount {
            let token_client = TokenClient::new(env, &token);
            let this = env.current_contract_address();
            token_client.transfer(sender, &this, &amount);
        }

        // 9. Complete the state-changing transaction
        // Mark nullifiers as spent
        for n in proof.input_nullifiers.iter() {
            let _ = Self::mark_spent(env, &n);
            NewNullifierEvent { nullifier: n }.publish(env);
        }

        // Process withdrawal if ext_amount < 0
        let token_client = TokenClient::new(env, &token);
        let this = env.current_contract_address();
        let zero = I256::from_i32(env, 0);

        if ext_data.ext_amount < zero {
            let abs = zero.sub(&ext_data.ext_amount);
            let amount: i128 = Self::i256_to_i128_nonneg(env, &abs)?;
            token_client.transfer(&this, &ext_data.recipient, &amount);
        }

        // Insert new commitments into Merkle tree
        let (idx_0, idx_1) = MerkleTreeWithHistory::insert_two_leaves(
            env,
            proof.output_commitment0.clone(),
            proof.output_commitment1.clone(),
        )?;

        // Emit commitment events
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

    // ========== Storage Getters and Setters ==========

    /// Get the token contract address
    fn get_token(env: &Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Token)
            .ok_or(Error::NotInitialized)
    }

    /// Get the maximum deposit amount
    fn get_maximum_deposit(env: &Env) -> Result<U256, Error> {
        env.storage()
            .instance()
            .get(&DataKey::MaximumDepositAmount)
            .ok_or(Error::NotInitialized)
    }

    /// Get the verifier contract address
    fn get_verifier(env: &Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Verifier)
            .ok_or(Error::NotInitialized)
    }

    /// Get the admin address
    fn get_admin(env: &Env) -> Result<Address, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)
    }

    /// Get the pool's ASP policy flags.
    pub fn get_policy_flags(env: &Env) -> Result<u32, Error> {
        Self::load_policy_flags(env)
    }

    fn load_policy_flags(env: &Env) -> Result<u32, Error> {
        env.storage()
            .instance()
            .get(&DataKey::PolicyFlags)
            .ok_or(Error::NotInitialized)
    }

    /// Get the latest root of the Merkle tree that defines the pool
    pub fn get_root(env: &Env) -> Result<U256, Error> {
        Ok(MerkleTreeWithHistory::get_last_root(env)?)
    }

    /// Check whether a pool Merkle root is still in the recent root history.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `root` - Pool Merkle root to check
    pub fn is_known_root(env: &Env, root: &U256) -> Result<bool, Error> {
        Ok(MerkleTreeWithHistory::is_known_root(env, root)?)
    }

    /// Check whether a nullifier has already been spent.
    ///
    /// Presence of the per-nullifier storage key is the spent flag.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `n` - The nullifier to check
    ///
    /// # Returns
    ///
    /// Returns `true` if the nullifier has been spent, `false` otherwise
    pub fn is_spent(env: &Env, n: &U256) -> Result<bool, Error> {
        let key = DataKey::Nullifier(n.clone());
        Ok(env.storage().persistent().has(&key))
    }

    /// Update the contract administrator
    ///
    /// Transfers administrative control to a new address. Requires
    /// authorization from the current admin.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `new_admin` - New address that will have administrative permissions
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotInitialized`] if the contract has no admin address
    /// stored.
    pub fn update_admin(env: Env, new_admin: Address) -> Result<(), Error> {
        soroban_utils::update_admin(&env, &DataKey::Admin, &new_admin)
            .map_err(|soroban_utils::AdminError::NotInitialized| Error::NotInitialized)
    }

    // ========== ASP Contract Functions ==========

    /// Get the ASP Membership contract address
    fn get_asp_membership(env: &Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::ASPMembership)
            .ok_or(Error::NotInitialized)
    }

    /// Get the ASP Non-Membership contract address
    fn get_asp_non_membership(env: &Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::ASPNonMembership)
            .ok_or(Error::NotInitialized)
    }

    /// Update the ASP Membership contract address
    ///
    /// Changes the ASP Membership contract address. Requires admin
    /// authorization.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `new_asp_membership` - New ASP Membership contract address
    pub fn update_asp_membership(env: &Env, new_asp_membership: Address) -> Result<(), Error> {
        let admin = Self::get_admin(env)?;
        admin.require_auth();
        env.storage()
            .instance()
            .set(&DataKey::ASPMembership, &new_asp_membership);
        Ok(())
    }

    /// Update the ASP Non-Membership contract address
    ///
    /// Changes the ASP Non-Membership contract address. Requires admin
    /// authorization.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `new_asp_non_membership` - New ASP Non-Membership contract address
    pub fn update_asp_non_membership(
        env: &Env,
        new_asp_non_membership: Address,
    ) -> Result<(), Error> {
        let admin = Self::get_admin(env)?;
        admin.require_auth();
        env.storage()
            .instance()
            .set(&DataKey::ASPNonMembership, &new_asp_non_membership);
        Ok(())
    }

    /// Get the current Merkle root from the ASP Membership contract
    ///
    /// Makes a cross-contract call to retrieve the current root of the
    /// membership Merkle tree.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    ///
    /// # Returns
    ///
    /// The current membership Merkle root as U256
    pub fn get_asp_membership_root(env: &Env) -> Result<U256, Error> {
        let asp_address = Self::get_asp_membership(env)?;
        let client = ASPMembershipClient::new(env, &asp_address);
        Ok(client.get_root())
    }

    /// Get the current Merkle root from the ASP Non-Membership contract
    ///
    /// Makes a cross-contract call to retrieve the current root of the
    /// non-membership Sparse Merkle tree.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    ///
    /// # Returns
    ///
    /// The current non-membership Merkle root as U256
    pub fn get_asp_non_membership_root(env: &Env) -> Result<U256, Error> {
        let asp_address = Self::get_asp_non_membership(env)?;
        let client = ASPNonMembershipClient::new(env, &asp_address);
        Ok(client.get_root())
    }
}
