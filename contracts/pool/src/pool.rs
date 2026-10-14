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
    clients::runs_wasm,
    events::{
        AspMembershipUpdated, AspNonMembershipUpdated, DepositPauseChanged, DepositPauseRepeated,
        FeesClaimed,
    },
    merkle_with_history::{Error as MerkleError, MerkleTreeWithHistory},
    policy,
    totals::{self, Error as TotalsError},
};
use soroban_sdk::{
    Address, Bytes, BytesN, Env, I256, String, U256, Vec, contract, contracterror, contractevent,
    contractimpl, contracttype, crypto::bn254::Bn254Fr, token::TokenClient,
};
use soroban_utils::{AdminError, constants::bn256_modulus};

// Re-exported rather than merely imported so `pool::ExtData` and
// `pool::hash_ext_data` keep resolving for existing consumers (`e2e-tests`,
// the SDK encoding tests) after the move into `pool-core`.
pub use pool_core::{ExtData, hash_ext_data};

/// Contract error types for the privacy pool
///
/// Codes 15 to 17 are `pool-gvk`'s own and stay unassigned here, so both pools
/// share every code from 18 on. Code 19 is unassigned.
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
    /// A deposit over the maximum or below the minimum after the fee, an
    /// amount outside the range the pool can hold, or a public amount other
    /// than `ext_amount` minus the fee
    WrongExtAmount = 6,
    /// Zero-knowledge proof verification failed
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
    /// Deposits are paused
    DepositsPaused = 18,
    /// No admin transfer is pending
    NoPendingAdmin = 20,
    /// An association set does not run the code fixed at construction
    TreeCodeMismatch = 21,
    /// A call would take the notes total below zero
    NotesTotalExceeded = 22,
    /// A claim is negative or above the fees total
    InvalidClaimAmount = 23,
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

impl From<TotalsError> for Error {
    fn from(e: TotalsError) -> Self {
        match e {
            TotalsError::NotInitialized => Error::NotInitialized,
            TotalsError::NotesTotalExceeded => Error::NotesTotalExceeded,
            TotalsError::Overflow => Error::Overflow,
            TotalsError::InvalidClaimAmount => Error::InvalidClaimAmount,
        }
    }
}

impl From<AdminError> for Error {
    fn from(e: AdminError) -> Self {
        match e {
            AdminError::NotInitialized => Error::NotInitialized,
            AdminError::NoPendingAdmin => Error::NoPendingAdmin,
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

/// Storage keys.
///
/// [`DataKey::Admin`], [`DataKey::PendingAdmin`], and [`DataKey::Nullifier`]
/// are persistent. Every other key lives in the instance.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DataKey {
    /// Administrator address with permissions to modify contract settings
    Admin,
    /// Proposed next administrator, present only during a transfer
    PendingAdmin,
    /// Address of the token contract used for deposits/withdrawals
    Token,
    /// Address of the ZK proof verifier contract
    Verifier,
    /// Maximum allowed deposit amount per transaction
    MaximumDepositAmount,
    /// Fee every transaction pays. Immutable.
    Fee,
    /// Smallest amount a deposit may add to notes after the fee. Immutable.
    MinimumDepositAmount,
    /// Spent nullifier marker keyed by nullifier (presence-only; value unused).
    Nullifier(U256),
    /// Address of the ASP Membership contract
    ASPMembership,
    /// Address of the ASP Non-Membership contract
    ASPNonMembership,
    /// Wasm hash every ASP Membership tree must run
    ASPMembershipWasmHash,
    /// Wasm hash every ASP Non-Membership tree must run
    ASPNonMembershipWasmHash,
    /// Pool ASP policy flags (bitset; see `crate::policy`).
    PolicyFlags,
    /// Privacy key derivation domain. Immutable.
    KdfDomain,
    /// Whether `transact` refuses deposits
    DepositsPaused,
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
    /// Initializes the pool.
    ///
    /// Each tree must run the Wasm its hash names, and every later re-point is
    /// checked against the same hash. `levels` is the commitment tree
    /// depth. `policy_flags` is the ASP bitset the transact circuit
    /// enforces.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPolicyFlags`] for an unsupported bit,
    /// [`Error::TreeCodeMismatch`] if a tree runs other code,
    /// [`Error::WrongExtAmount`] for a negative fee or minimum, or for a fee
    /// and minimum that together exceed the maximum, and
    /// [`Error::WrongLevels`] if `levels` is outside 1 to 32.
    pub fn __constructor(
        env: Env,
        admin: Address,
        token: Address,
        verifier: Address,
        asp_membership: Address,
        asp_non_membership: Address,
        asp_membership_wasm_hash: BytesN<32>,
        asp_non_membership_wasm_hash: BytesN<32>,
        fee: i128,
        minimum_deposit_amount: i128,
        maximum_deposit_amount: U256,
        levels: u32,
        policy_flags: u32,
        kdf_domain: String,
    ) -> Result<(), Error> {
        if !policy::is_valid(policy_flags) {
            return Err(Error::InvalidPolicyFlags);
        }
        if !runs_wasm(&asp_membership, &asp_membership_wasm_hash)
            || !runs_wasm(&asp_non_membership, &asp_non_membership_wasm_hash)
        {
            return Err(Error::TreeCodeMismatch);
        }
        if fee < 0 || minimum_deposit_amount < 0 {
            return Err(Error::WrongExtAmount);
        }
        let smallest_deposit = fee
            .checked_add(minimum_deposit_amount)
            .and_then(|sum| u128::try_from(sum).ok())
            .ok_or(Error::WrongExtAmount)?;
        if U256::from_u128(&env, smallest_deposit) > maximum_deposit_amount {
            return Err(Error::WrongExtAmount);
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
        let instance = env.storage().instance();
        instance.set(&DataKey::Token, &token);
        instance.set(&DataKey::Verifier, &verifier);
        instance.set(&DataKey::ASPMembership, &asp_membership);
        instance.set(&DataKey::ASPNonMembership, &asp_non_membership);
        instance.set(&DataKey::ASPMembershipWasmHash, &asp_membership_wasm_hash);
        instance.set(
            &DataKey::ASPNonMembershipWasmHash,
            &asp_non_membership_wasm_hash,
        );
        instance.set(&DataKey::Fee, &fee);
        instance.set(&DataKey::MinimumDepositAmount, &minimum_deposit_amount);
        instance.set(&DataKey::MaximumDepositAmount, &maximum_deposit_amount);
        instance.set(&DataKey::PolicyFlags, &policy_flags);
        instance.set(&DataKey::KdfDomain, &kdf_domain);
        instance.set(&DataKey::DepositsPaused, &false);
        totals::init(&env);

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

    /// Calculate the public amount from external amount
    ///
    /// Computes `public_amount = ext_amount` in the BN256 field.
    /// For positive results, returns the value directly.
    /// For negative results, returns `FIELD_SIZE - |public_amount|`.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `ext_amount` - External amount (positive for deposit, negative for
    ///   withdrawal)
    ///
    /// # Returns
    ///
    /// Returns the public amount as U256 in the BN256 field, or an error
    /// if the amounts exceed limits
    fn calculate_public_amount(env: &Env, ext_amount: I256) -> Result<U256, Error> {
        amounts::calculate_public_amount(env, ext_amount).ok_or(Error::WrongExtAmount)
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

    /// Reject values outside the canonical BN254 scalar-field range.
    ///
    /// `Bn254Fr::from_bytes` expects field elements, so any `U256` that will be
    /// converted into a verifier public input must be checked before
    /// conversion.
    fn validate_bn256_public_input(value: &U256, modulus: &U256) -> Result<(), Error> {
        if amounts::is_canonical_bn256_public_input(value, modulus) {
            Ok(())
        } else {
            Err(Error::NonCanonicalPublicInput)
        }
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

        Ok(())
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
        let policy_flags = Self::load_policy_flags(env)?;
        let verifier = Self::get_verifier(env)?;
        soroban_utils::extend_contract(env, &verifier);
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

    /// Hash external data using Keccak256, bound to this pool and its token
    ///
    /// Serializes the external data together with this contract's address and
    /// configured token to XDR, hashes with Keccak256, and reduces the result
    /// modulo the BN256 field size.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `ext` - The external data to hash
    /// * `token` - This pool's own configured token address
    ///
    /// # Returns
    ///
    /// Returns the 32-byte hash of the external data
    fn hash_ext_data(env: &Env, ext: &ExtData, token: &Address) -> BytesN<32> {
        hash_ext_data(env, ext, token)
    }

    /// Executes a shielded transaction.
    ///
    /// Every call pays the pool fee, from its deposit or from the notes it
    /// spends, so the proof's public amount is `ext_amount` minus the fee. A
    /// deposit (`ext_amount > 0`) first moves the tokens from `sender` to the
    /// pool. Renews the pool, its tree, and its verifier by at most a day
    /// each.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DepositsPaused`] for a deposit while paused, before the
    /// cap and minimum checks and any transfer, [`Error::WrongExtAmount`] for
    /// a deposit over the cap or below the pool minimum after the fee, or an
    /// out-of-range or mismatched amount, and [`Error::InvalidProof`] for an
    /// empty or refused proof, an ASP root the trees reject, or a failed tree
    /// call. Every other error names the failed check or marks missing or
    /// corrupt state.
    ///
    /// # Panics
    ///
    /// Panics if `sender` does not authorize the call or a token transfer
    /// fails.
    pub fn transact(
        env: &Env,
        proof: Proof,
        ext_data: ExtData,
        sender: Address,
    ) -> Result<(), Error> {
        sender.require_auth();
        soroban_utils::extend_instance(env);
        let token = Self::get_token(env)?;
        let token_client = TokenClient::new(env, &token);
        let zero = I256::from_i32(env, 0);

        // Handle deposit if ext_amount > 0
        if ext_data.ext_amount > zero {
            if Self::deposits_paused(env)? {
                return Err(Error::DepositsPaused);
            }
            let deposit_u = U256::from_be_bytes(env, &ext_data.ext_amount.to_be_bytes());
            let max = Self::get_maximum_deposit(env)?;
            if deposit_u > max {
                return Err(Error::WrongExtAmount);
            }
            let this = env.current_contract_address();
            let amount = Self::i256_to_i128_nonneg(env, &ext_data.ext_amount)?;
            let net = amount
                .checked_sub(Self::get_fee(env)?)
                .ok_or(Error::WrongExtAmount)?;
            if net < Self::get_minimum_deposit(env)? {
                return Err(Error::WrongExtAmount);
            }
            token_client.transfer(&sender, &this, &amount);
        }

        Self::internal_transact(env, proof, ext_data)
    }

    /// Process a private transaction
    ///
    /// Validates the proof and all public inputs, marks nullifiers as spent,
    /// processes withdrawals, and inserts new commitments into the Merkle tree.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `proof` - Zero-knowledge proof and public inputs
    /// * `ext_data` - External transaction data
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success, or an error if any validation fails
    ///
    /// # Validation Steps
    ///
    /// 1. Verify Merkle root is in recent history
    /// 2. Verify no nullifiers have been spent
    /// 3. Verify external data hash matches
    /// 4. Verify public amount calculation
    /// 5. Verify zero-knowledge proof
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
        // 3. External data hash check, bound to this pool's address and its
        // own configured token, so a hash computed for another pool or token
        // cannot match here.
        let token = Self::get_token(env)?;
        let ext_hash = Self::hash_ext_data(env, &ext_data, &token);
        if ext_hash != proof.ext_data_hash {
            return Err(Error::WrongExtHash);
        }

        // 4. Public amount check, net of the pool fee
        let fee = Self::get_fee(env)?;
        let net = ext_data
            .ext_amount
            .to_i128()
            .and_then(|amount| amount.checked_sub(fee))
            .ok_or(Error::WrongExtAmount)?;
        let expected_public_amount = Self::calculate_public_amount(env, I256::from_i128(env, net))?;
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
            let asp_address = Self::get_asp_membership(env)?;
            let client = ASPMembershipClient::new(env, &asp_address);
            // `try_` here and in the root getters: tree error codes overlap the
            // pool's, so a trapped tree error would read as a pool error.
            if !matches!(
                client.try_is_known_root(&proof.asp_membership_root),
                Ok(Ok(true))
            ) {
                return Err(Error::InvalidProof);
            }
        }

        // 5. ZK proof verification
        if !Self::verify_proof(env, &proof)? {
            return Err(Error::InvalidProof);
        }

        // 6. Mark nullifiers as spent
        for n in proof.input_nullifiers.iter() {
            let _ = Self::mark_spent(env, &n);
            NewNullifierEvent { nullifier: n }.publish(env);
        }

        // Only a broken circuit or verifier could take the notes total below
        // zero, since every note a call spends came from an earlier output.
        totals::record(env, net, fee)?;

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

        // 9. Insert new commitments into Merkle tree
        let (idx_0, idx_1) = MerkleTreeWithHistory::insert_two_leaves(
            env,
            proof.output_commitment0.clone(),
            proof.output_commitment1.clone(),
        )?;

        // 10. Emit commitment events
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

    /// Get the fee every transaction pays
    fn get_fee(env: &Env) -> Result<i128, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Fee)
            .ok_or(Error::NotInitialized)
    }

    /// Get the smallest amount a deposit may add to notes after the fee
    fn get_minimum_deposit(env: &Env) -> Result<i128, Error> {
        env.storage()
            .instance()
            .get(&DataKey::MinimumDepositAmount)
            .ok_or(Error::NotInitialized)
    }

    /// Get the verifier contract address
    fn get_verifier(env: &Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Verifier)
            .ok_or(Error::NotInitialized)
    }

    /// Get the pool's ASP policy flags.
    pub fn get_policy_flags(env: &Env) -> Result<u32, Error> {
        Self::load_policy_flags(env)
    }

    /// Get the deployment's privacy key derivation domain.
    pub fn get_kdf_domain(env: &Env) -> Result<String, Error> {
        env.storage()
            .instance()
            .get(&DataKey::KdfDomain)
            .ok_or(Error::NotInitialized)
    }

    fn load_policy_flags(env: &Env) -> Result<u32, Error> {
        env.storage()
            .instance()
            .get(&DataKey::PolicyFlags)
            .ok_or(Error::NotInitialized)
    }

    /// Reports whether the pool refuses deposits.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotInitialized`] if the deposit flag is not stored.
    pub fn deposits_paused(env: &Env) -> Result<bool, Error> {
        env.storage()
            .instance()
            .get(&DataKey::DepositsPaused)
            .ok_or(Error::NotInitialized)
    }

    /// Returns the fees the pool has collected and not paid out.
    pub fn get_fees_total(env: &Env) -> Result<i128, Error> {
        Ok(totals::fees_total(env)?)
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

    /// Proposes a new contract administrator.
    ///
    /// Replaces any earlier proposal. The current admin keeps every power until
    /// `new_admin` calls `accept_admin`.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `new_admin` - Address proposed as the next administrator
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotInitialized`] if the contract has no admin address
    /// stored.
    ///
    /// # Panics
    ///
    /// Panics if the admin does not authorize the call.
    pub fn update_admin(env: Env, new_admin: Address) -> Result<(), Error> {
        soroban_utils::update_admin(&env, &DataKey::Admin, &DataKey::PendingAdmin, &new_admin)
            .map_err(Error::from)
    }

    /// Withdraws the pending admin transfer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoPendingAdmin`] if no transfer is pending, and
    /// [`Error::NotInitialized`] if no admin is stored.
    ///
    /// # Panics
    ///
    /// Panics if the admin does not authorize the call.
    pub fn cancel_admin_transfer(env: &Env) -> Result<(), Error> {
        soroban_utils::cancel_admin_transfer(env, &DataKey::Admin, &DataKey::PendingAdmin)
            .map_err(Error::from)
    }

    /// Installs the pending admin as the contract administrator.
    ///
    /// The previous admin loses every power over the contract.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoPendingAdmin`] if no transfer is pending, and
    /// [`Error::NotInitialized`] if no admin is stored.
    ///
    /// # Panics
    ///
    /// Panics if the pending admin does not authorize the call.
    pub fn accept_admin(env: &Env) -> Result<(), Error> {
        soroban_utils::accept_admin(env, &DataKey::Admin, &DataKey::PendingAdmin)
            .map_err(Error::from)
    }

    /// Returns the contract administrator.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotInitialized`] if the contract has no admin address
    /// stored.
    pub fn get_admin(env: &Env) -> Result<Address, Error> {
        soroban_utils::get_admin(env, &DataKey::Admin).map_err(Error::from)
    }

    /// Returns the address proposed as the next administrator, or `None` when
    /// no transfer is pending.
    pub fn get_pending_admin(env: &Env) -> Option<Address> {
        soroban_utils::get_pending_admin(env, &DataKey::PendingAdmin)
    }

    /// Pauses deposits.
    ///
    /// While paused, `transact` refuses `ext_amount > 0` before any token
    /// moves. Transfers and withdrawals still go through. Publishes
    /// [`DepositPauseChanged`], or [`DepositPauseRepeated`] on a paused pool.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotInitialized`] if the admin or the deposit flag is
    /// not stored.
    ///
    /// # Panics
    ///
    /// Panics if the admin does not authorize the call.
    pub fn pause_deposits(env: &Env) -> Result<(), Error> {
        Self::set_deposits_paused(env, true)
    }

    /// Resumes deposits. Publishes [`DepositPauseChanged`], or
    /// [`DepositPauseRepeated`] on an open pool.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotInitialized`] if the admin or the deposit flag is
    /// not stored.
    ///
    /// # Panics
    ///
    /// Panics if the admin does not authorize the call.
    pub fn unpause_deposits(env: &Env) -> Result<(), Error> {
        Self::set_deposits_paused(env, false)
    }

    fn set_deposits_paused(env: &Env, paused: bool) -> Result<(), Error> {
        soroban_utils::get_admin(env, &DataKey::Admin)?.require_auth();
        // A failed call publishes the signed authorization unspent, for anyone
        // to replay. So a no-op succeeds, and still writes: simulated as a
        // no-op, the call keeps write access if the opposite call lands first.
        let changed = Self::deposits_paused(env)? != paused;
        env.storage()
            .instance()
            .set(&DataKey::DepositsPaused, &paused);
        if changed {
            DepositPauseChanged { paused }.publish(env);
        } else {
            DepositPauseRepeated { paused }.publish(env);
        }
        Ok(())
    }

    /// Pays `amount` of the collected fees to `to` and publishes
    /// [`FeesClaimed`].
    ///
    /// Pays out fees only, never note value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidClaimAmount`] for a negative amount or one above
    /// the fees total.
    ///
    /// # Panics
    ///
    /// Panics if the admin does not authorize the call or the token transfer
    /// fails.
    pub fn claim_fees(env: &Env, to: Address, amount: i128) -> Result<(), Error> {
        soroban_utils::get_admin(env, &DataKey::Admin)?.require_auth();
        totals::claim(env, amount)?;
        let token_client = TokenClient::new(env, &Self::get_token(env)?);
        token_client.transfer(&env.current_contract_address(), &to, &amount);
        FeesClaimed { to, amount }.publish(env);
        Ok(())
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

    /// Points the pool at another ASP Membership tree and publishes
    /// [`AspMembershipUpdated`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::TreeCodeMismatch`] if the tree does not run the Wasm
    /// fixed at construction, and [`Error::NotInitialized`] if the admin,
    /// the hash, or the current tree is not stored.
    ///
    /// # Panics
    ///
    /// Panics if the admin does not authorize the call.
    pub fn update_asp_membership(env: &Env, new_asp_membership: Address) -> Result<(), Error> {
        soroban_utils::get_admin(env, &DataKey::Admin)?.require_auth();
        let (wasm_hash, _) = Self::get_asp_wasm_hashes(env)?;
        if !runs_wasm(&new_asp_membership, &wasm_hash) {
            return Err(Error::TreeCodeMismatch);
        }
        let old_tree = Self::get_asp_membership(env)?;
        env.storage()
            .instance()
            .set(&DataKey::ASPMembership, &new_asp_membership);
        AspMembershipUpdated {
            old_tree,
            new_tree: new_asp_membership,
        }
        .publish(env);
        Ok(())
    }

    /// Points the pool at another ASP Non-Membership tree and publishes
    /// [`AspNonMembershipUpdated`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::TreeCodeMismatch`] if the tree does not run the Wasm
    /// fixed at construction, and [`Error::NotInitialized`] if the admin,
    /// the hash, or the current tree is not stored.
    ///
    /// # Panics
    ///
    /// Panics if the admin does not authorize the call.
    pub fn update_asp_non_membership(
        env: &Env,
        new_asp_non_membership: Address,
    ) -> Result<(), Error> {
        soroban_utils::get_admin(env, &DataKey::Admin)?.require_auth();
        let (_, wasm_hash) = Self::get_asp_wasm_hashes(env)?;
        if !runs_wasm(&new_asp_non_membership, &wasm_hash) {
            return Err(Error::TreeCodeMismatch);
        }
        let old_tree = Self::get_asp_non_membership(env)?;
        env.storage()
            .instance()
            .set(&DataKey::ASPNonMembership, &new_asp_non_membership);
        AspNonMembershipUpdated {
            old_tree,
            new_tree: new_asp_non_membership,
        }
        .publish(env);
        Ok(())
    }

    /// Returns the Wasm hashes the ASP Membership and ASP Non-Membership trees
    /// must run, in that order.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotInitialized`] if either hash is missing.
    pub fn get_asp_wasm_hashes(env: &Env) -> Result<(BytesN<32>, BytesN<32>), Error> {
        let instance = env.storage().instance();
        let membership = instance
            .get(&DataKey::ASPMembershipWasmHash)
            .ok_or(Error::NotInitialized)?;
        let non_membership = instance
            .get(&DataKey::ASPNonMembershipWasmHash)
            .ok_or(Error::NotInitialized)?;
        Ok((membership, non_membership))
    }

    /// Returns the ASP Membership tree's current root.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidProof`] if the tree call fails, and
    /// [`Error::NotInitialized`] if no tree is stored.
    pub fn get_asp_membership_root(env: &Env) -> Result<U256, Error> {
        let asp_address = Self::get_asp_membership(env)?;
        let client = ASPMembershipClient::new(env, &asp_address);
        match client.try_get_root() {
            Ok(Ok(root)) => Ok(root),
            _ => Err(Error::InvalidProof),
        }
    }

    /// Returns the ASP Non-Membership tree's current root.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidProof`] if the tree call fails, and
    /// [`Error::NotInitialized`] if no tree is stored.
    pub fn get_asp_non_membership_root(env: &Env) -> Result<U256, Error> {
        let asp_address = Self::get_asp_non_membership(env)?;
        let client = ASPNonMembershipClient::new(env, &asp_address);
        match client.try_get_root() {
            Ok(Ok(root)) => Ok(root),
            _ => Err(Error::InvalidProof),
        }
    }
}
