//! Privacy Pool Contract
//!
//! This contract implements a privacy-preserving transaction pool with embedded compliance.
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
use crate::merkle_with_history::{Error as MerkleError, MerkleTreeWithHistory};
use circom_groth16_verifier::CircomGroth16VerifierClient;
use soroban_sdk::token::TokenClient;
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{
    Address, Bytes, BytesN, Env, I256, Map, U256, Vec, contract, contracterror, contractevent,
    contractimpl, contracttype, crypto::bn254::Fr,
};
use soroban_utils::constants::bn256_modulus;

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
    /// Fee exceeds the maximum allowed value (2^248)
    WrongFee = 7,
    /// Zero-knowledge proof verification failed or proof is empty
    InvalidProof = 8,
    /// Provided Merkle root is not in the recent history
    UnknownRoot = 9,
    /// Nullifier has already been spent (double-spend attempt)
    AlreadySpentNullifier = 10,
    /// External data hash does not match the provided data
    WrongExtHash = 11,
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
        }
    }
}

/// External data for a transaction
///
/// Contains public information about the transaction that is hashed and
/// included in the zero-knowledge proof to bind the proof to specific
/// transaction parameters (e.g. recipient address).
#[contracttype]
#[derive(Clone)]
pub struct ExtData {
    /// Recipient address for withdrawals
    pub recipient: Address,
    /// External amount: positive for deposits, negative for withdrawals
    pub ext_amount: I256,
    /// Relayer fee (paid from the withdrawal amount)
    pub fee: U256,
    /// Encrypted data for the first output UTXO
    pub encrypted_output0: Bytes,
    /// Encrypted data for the second output UTXO
    pub encrypted_output1: Bytes,
}

/// Zero-knowledge proof data for a transaction
///
/// Contains all the cryptographic data needed to verify a transaction,
/// including the proof itself, public inputs, and nullifiers.
#[contracttype]
pub struct Proof {
    /// The serialized zero-knowledge proof
    pub proof: Bytes,
    /// Merkle root the proof was generated against
    pub root: U256,
    /// Nullifiers for spent input UTXOs (prevents double-spending)
    pub input_nullifiers: Vec<U256>,
    /// Commitment for the first output UTXO
    pub output_commitment0: U256,
    /// Commitment for the second output UTXO
    pub output_commitment1: U256,
    /// Net public amount (deposit - withdrawal - fee, modulo field size)
    pub public_amount: U256,
    /// Hash of the external data (binds proof to transaction parameters)
    pub ext_data_hash: BytesN<32>,
}

/// User account registration data
///
/// Used for registering a user's public key to enable encrypted communication
/// for receiving transfers.
/// Not required to interact with the pool. But facilitates in-pool transfers via events.
/// As parties can learn about each other public key.
#[contracttype]
pub struct Account {
    /// Owner address of the account
    pub owner: Address,
    /// Public encryption key for receiving encrypted outputs
    pub public_key: Bytes,
}

/// Storage keys for contract persistent data
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    /// Address of the token contract used for deposits/withdrawals
    Token,
    /// Address of the ZK proof verifier contract
    Verifier,
    /// Maximum allowed deposit amount per transaction
    MaximumDepositAmount,
    /// Map of spent nullifiers (nullifier -> bool)
    Nullifiers,
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

/// Event emitted when a user registers their public key
///
/// This event allows other users to discover encryption keys for sending
/// private transfers.
#[contractevent]
#[derive(Clone)]
pub struct PublicKeyEvent {
    /// Address of the account owner
    #[topic]
    pub owner: Address,
    /// Public encryption key
    pub key: Bytes,
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
    /// Initialize the privacy pool contract
    ///
    /// Sets up the contract with the specified token, verifier, and Merkle tree
    /// configuration. This function can only be called once.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `token` - Address of the token contract for deposits/withdrawals
    /// * `verifier` - Address of the ZK proof verifier contract
    /// * `maximum_deposit_amount` - Maximum allowed deposit per transaction
    /// * `levels` - Number of levels in the commitment Merkle tree (1-32)
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success, or an error if already initialized or
    /// invalid configuration
    pub fn init(
        env: Env,
        token: Address,
        verifier: Address,
        maximum_deposit_amount: U256,
        levels: u32,
    ) -> Result<(), Error> {
        if env.storage().persistent().has(&DataKey::Token) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().persistent().set(&DataKey::Token, &token);
        env.storage()
            .persistent()
            .set(&DataKey::Verifier, &verifier);
        env.storage()
            .persistent()
            .set(&DataKey::MaximumDepositAmount, &maximum_deposit_amount);
        env.storage()
            .persistent()
            .set(&DataKey::Nullifiers, &Map::<U256, bool>::new(&env));

        // Initialize the Merkle tree for commitment storage
        MerkleTreeWithHistory::init(&env, levels)?;

        Ok(())
    }

    /// Maximum absolute external amount allowed (2^248)
    ///
    /// This limit ensures amounts fit within field arithmetic constraints.
    fn max_ext_amount(env: &Env) -> U256 {
        U256::from_parts(env, 0x0100_0000_0000_0000, 0, 0, 0)
    }

    /// Maximum fee allowed (2^248)
    ///
    /// This limit ensures fees fit within field arithmetic constraints.
    fn max_fee(env: &Env) -> U256 {
        U256::from_parts(env, 0x0100_0000_0000_0000, 0, 0, 0)
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
        if *v < I256::from_i32(env, 0) {
            return Err(Error::WrongExtAmount);
        }
        v.to_i128().ok_or(Error::WrongExtAmount)
    }

    /// Calculate the public amount from external amount and fee
    ///
    /// Computes `public_amount = ext_amount - fee` in the BN256 field.
    /// For positive results, returns the value directly.
    /// For negative results, returns `FIELD_SIZE - |public_amount|`.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `ext_amount` - External amount (positive for deposit, negative for withdrawal)
    /// * `fee` - Relayer fee
    ///
    /// # Returns
    ///
    /// Returns the public amount as U256 in the BN256 field, or an error
    /// if the amounts exceed limits
    fn calculate_public_amount(env: &Env, ext_amount: I256, fee: U256) -> Result<U256, Error> {
        if fee >= Self::max_fee(env) {
            return Err(Error::WrongFee);
        }

        let abs_ext = Self::i256_abs_to_u256(env, &ext_amount);
        if abs_ext >= Self::max_ext_amount(env) {
            return Err(Error::WrongExtAmount);
        }

        let fee_bytes = fee.to_be_bytes();
        let fee_i256 = I256::from_be_bytes(env, &fee_bytes);
        let public_amount = ext_amount.sub(&fee_i256);
        let zero = I256::from_i32(env, 0);

        if public_amount >= zero {
            let pa_bytes = public_amount.to_be_bytes();
            Ok(U256::from_be_bytes(env, &pa_bytes))
        } else {
            // Negative: compute FIELD_SIZE - |public_amount|
            let neg = zero.sub(&public_amount);
            let neg_bytes = neg.to_be_bytes();
            let neg_u256 = U256::from_be_bytes(env, &neg_bytes);

            let field = bn256_modulus(env);
            Ok(field.sub(&neg_u256))
        }
    }

    /// Check if a nullifier has already been spent
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `n` - The nullifier to check
    ///
    /// # Returns
    ///
    /// Returns `true` if the nullifier has been spent, `false` otherwise
    fn is_spent(env: &Env, n: &U256) -> bool {
        let nulls = Self::get_nullifiers(env);
        nulls.get(n.clone()).unwrap_or(false)
    }

    /// Mark a nullifier as spent
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `n` - The nullifier to mark as spent
    fn mark_spent(env: &Env, n: &U256) {
        let mut nulls = Self::get_nullifiers(env);
        nulls.set(n.clone(), true);
        Self::set_nullifiers(env, &nulls);
    }

    /// Verify a zero-knowledge proof
    ///
    /// # Arguments
    ///
    /// * `_env` - The Soroban environment
    /// * `_proof` - The proof to verify
    ///
    /// # Returns
    ///
    /// Returns `true` if the proof is valid, `false` otherwise
    ///
    /// # Note
    ///
    fn verify_proof(env: &Env, proof: &Proof) -> bool {
        let verifier = Self::get_verifier(env);
        let client = CircomGroth16VerifierClient::new(env, &verifier);

        // Public inputs expected by the Circom Transaction circuit:
        // [root, publicAmount, extDataHash, inputNullifier..., outputCommitment0, outputCommitment1]
        let mut public_inputs: Vec<Fr> = Vec::new(env);
        public_inputs.push_back(Fr::from_bytes(Self::u256_to_bytes(env, &proof.root)));
        public_inputs.push_back(Fr::from_bytes(Self::u256_to_bytes(
            env,
            &proof.public_amount,
        )));
        public_inputs.push_back(Fr::from_bytes(proof.ext_data_hash.clone()));
        for nullifier in proof.input_nullifiers.iter() {
            public_inputs.push_back(Fr::from_bytes(Self::u256_to_bytes(env, &nullifier)));
        }
        public_inputs.push_back(Fr::from_bytes(Self::u256_to_bytes(
            env,
            &proof.output_commitment0,
        )));
        public_inputs.push_back(Fr::from_bytes(Self::u256_to_bytes(
            env,
            &proof.output_commitment1,
        )));

        client.try_verify(&proof.proof, &public_inputs).is_ok()
    }

    /// Hash external data using Keccak256
    ///
    /// Serializes the external data to XDR, hashes it with Keccak256,
    /// and reduces the result modulo the BN256 field size.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `ext` - The external data to hash
    ///
    /// # Returns
    ///
    /// Returns the 32-byte hash of the external data
    fn hash_ext_data(env: &Env, ext: &ExtData) -> BytesN<32> {
        let payload = ext.clone().to_xdr(env);
        let digest: BytesN<32> = env.crypto().keccak256(&payload).into();
        let digest_u256 = U256::from_be_bytes(env, &Bytes::from(digest));
        let reduced = digest_u256.rem_euclid(&bn256_modulus(env));
        let mut buf = [0u8; 32];
        reduced.to_be_bytes().copy_into_slice(&mut buf);
        BytesN::from_array(env, &buf)
    }

    /// Convert I256 to its absolute value as U256
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `v` - The I256 value
    ///
    /// # Returns
    ///
    /// Returns the absolute value of `v` as U256
    fn i256_abs_to_u256(env: &Env, v: &I256) -> U256 {
        let zero = I256::from_i32(env, 0);
        let abs = if *v >= zero { v.clone() } else { zero.sub(v) };
        U256::from_be_bytes(env, &abs.to_be_bytes())
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
    /// * `sender` - Address of the transaction sender (must authorize funding transaction)
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
        sender.require_auth();
        let token = Self::get_token(env);
        let token_client = TokenClient::new(env, &token);
        let zero = I256::from_i32(env, 0);

        // Handle deposit if ext_amount > 0
        if ext_data.ext_amount > zero {
            let deposit_u = U256::from_be_bytes(env, &ext_data.ext_amount.to_be_bytes());
            let max = Self::get_maximum_deposit(env);
            if deposit_u > max {
                return Err(Error::WrongExtAmount);
            }
            let this = env.current_contract_address();
            let amount = Self::i256_to_i128_nonneg(env, &ext_data.ext_amount)?;
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
    /// 1. Verify proof is not empty
    /// 2. Verify Merkle root is in recent history
    /// 3. Verify no nullifiers have been spent
    /// 4. Verify external data hash matches
    /// 5. Verify public amount calculation
    /// 6. Verify zero-knowledge proof
    fn internal_transact(env: &Env, proof: Proof, ext_data: ExtData) -> Result<(), Error> {
        // 1. Check proof is not empty
        if proof.proof.is_empty() {
            return Err(Error::InvalidProof);
        }

        // 2. Merkle root check
        if !MerkleTreeWithHistory::is_known_root(env, &proof.root) {
            return Err(Error::UnknownRoot);
        }

        // 3. Nullifier checks (prevent double-spending)
        for n in proof.input_nullifiers.iter() {
            if Self::is_spent(env, &n) {
                return Err(Error::AlreadySpentNullifier);
            }
        }

        // 4. External data hash check
        let ext_hash = Self::hash_ext_data(env, &ext_data);
        if ext_hash != proof.ext_data_hash {
            return Err(Error::WrongExtHash);
        }

        // 5. Public amount check
        let expected_public_amount =
            Self::calculate_public_amount(env, ext_data.ext_amount.clone(), ext_data.fee.clone())?;
        if proof.public_amount != expected_public_amount {
            return Err(Error::WrongExtAmount);
        }

        // 6. ZK proof verification
        if !Self::verify_proof(env, &proof) {
            return Err(Error::InvalidProof);
        }

        // 7. Mark nullifiers as spent
        for n in proof.input_nullifiers.iter() {
            Self::mark_spent(env, &n);
            NewNullifierEvent { nullifier: n }.publish(env);
        }

        // 8. Process withdrawal if ext_amount < 0
        let token = Self::get_token(env);
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

    /// Register a user's public encryption key
    ///
    /// Allows users to publish their public key so others can send them
    /// encrypted outputs for private transfers.
    /// The account owner must authorize this call
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `account` - Account data containing owner address and public key
    pub fn register(env: Env, account: Account) {
        account.owner.require_auth();
        PublicKeyEvent {
            owner: account.owner,
            key: account.public_key,
        }
        .publish(&env);
    }

    // ========== Storage Getters and Setters ==========

    /// Get the nullifiers map from storage
    fn get_nullifiers(env: &Env) -> Map<U256, bool> {
        env.storage()
            .persistent()
            .get(&DataKey::Nullifiers)
            .unwrap_or(Map::new(env))
    }

    /// Save the nullifiers map to storage
    fn set_nullifiers(env: &Env, m: &Map<U256, bool>) {
        env.storage().persistent().set(&DataKey::Nullifiers, m);
    }

    /// Get the token contract address
    fn get_token(env: &Env) -> Address {
        env.storage().persistent().get(&DataKey::Token).unwrap()
    }

    /// Get the maximum deposit amount
    fn get_maximum_deposit(env: &Env) -> U256 {
        env.storage()
            .persistent()
            .get(&DataKey::MaximumDepositAmount)
            .expect("Pool contract not initialized")
    }

    /// Get the verifier contract address
    fn get_verifier(env: &Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::Verifier)
            .expect("Verifier not configured")
    }

    /// Convert a U256 into a 32-byte big-endian field element
    fn u256_to_bytes(env: &Env, v: &U256) -> BytesN<32> {
        let mut buf = [0u8; 32];
        v.to_be_bytes().copy_into_slice(&mut buf);
        BytesN::from_array(env, &buf)
    }
}
