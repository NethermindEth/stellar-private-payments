//! External transaction data and its hash.
//!
//! `ExtData` carries the public parameters a proof is bound to. It is hashed
//! and checked against the proof's `ext_data_hash` rather than verified by the
//! SNARK directly, so it is identical for every pool variant.

use soroban_sdk::{Address, Bytes, BytesN, Env, I256, U256, contracttype, xdr::ToXdr};
use soroban_utils::constants::bn256_modulus;

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
    /// Encrypted data for the first output UTXO
    pub encrypted_output0: Bytes,
    /// Encrypted data for the second output UTXO
    pub encrypted_output1: Bytes,
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
pub fn hash_ext_data(env: &Env, ext: &ExtData) -> BytesN<32> {
    let payload = ext.clone().to_xdr(env);
    let digest: BytesN<32> = env.crypto().keccak256(&payload).into();
    let digest_u256 = U256::from_be_bytes(env, &Bytes::from(digest));
    let reduced = digest_u256.rem_euclid(&bn256_modulus(env));
    let mut buf = [0u8; 32];
    reduced.to_be_bytes().copy_into_slice(&mut buf);
    BytesN::from_array(env, &buf)
}
