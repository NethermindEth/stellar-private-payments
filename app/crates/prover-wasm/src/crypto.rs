//! Cryptographic utilities for input preparation
//!
//! Provides Poseidon2 hashing and key derivation functions matching
//! the Circom circuit implementations.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use wasm_bindgen::prelude::*;
use zkhash::fields::bn256::FpBN256 as Scalar;
use zkhash::poseidon2::{
    poseidon2::Poseidon2,
    poseidon2_instance_bn256::{POSEIDON2_BN256_PARAMS_2, POSEIDON2_BN256_PARAMS_3},
};
use zkhash::poseidon2::poseidon2_instance_bn256::POSEIDON2_BN256_PARAMS_4;
use crate::serialization::{bytes_to_scalar, scalar_to_bytes, scalar_to_hex};

/// Poseidon2 hash with 2 inputs and optional domain separation (t=3, r=2, c=1)
///
/// This is the core hash function used throughout the crate for merkle trees
/// and other cryptographic operations.
pub(crate) fn poseidon2_hash2_internal(a: Scalar, b: Scalar, domain: Option<Scalar>) -> Scalar {
    let poseidon2 = Poseidon2::new(&POSEIDON2_BN256_PARAMS_3);
    let input = match domain {
        Some(d) => vec![a, b, d],
        None => vec![a, b, Scalar::from(0u64)],
    };
    let perm = poseidon2.permutation(&input);
    perm[0]
}

/// Poseidon2 hash with 3 inputs and optional domain separation
///
/// Used for leaf hashing in sparse merkle trees and commitment generation.
pub(crate) fn poseidon2_hash3_internal(a: Scalar, b: Scalar, c: Scalar, domain: Option<Scalar>) -> Scalar {
    let poseidon2 = Poseidon2::new(&POSEIDON2_BN256_PARAMS_4);
    let input = match domain {
        Some(d) => vec![a, b, c ,d],
        None => vec![a, b, c, Scalar::from(0u64)],
    };
    let perm = poseidon2.permutation(&input);
    perm[0]
}

/// Poseidon2 compression (2 inputs, no domain separation)
///
/// Used for internal nodes in merkle trees.
pub(crate) fn poseidon2_compression(left: Scalar, right: Scalar) -> Scalar {
    let poseidon2 = Poseidon2::new(&POSEIDON2_BN256_PARAMS_2);
    let input = [left, right];
    let perm = poseidon2.permutation(&input);
    // Feed-forward: add inputs back to permutation output
    perm[0] + input[0]
}

/// Poseidon2 hash with 2 inputs and domain separation
///
/// Matches the Circom Poseidon2(2) template
#[wasm_bindgen]
pub fn poseidon2_hash2(
    input0: &[u8],
    input1: &[u8],
    domain_separation: u8,
) -> Result<Vec<u8>, JsValue> {
    let a = bytes_to_scalar(input0)?;
    let b = bytes_to_scalar(input1)?;
    let domain = Scalar::from(domain_separation as u64);

    let result = poseidon2_hash2_internal(a, b, Some(domain));
    Ok(scalar_to_bytes(&result))
}

/// Poseidon2 hash with 3 inputs and domain separation
///
/// Matches the Circom Poseidon2(3) template
#[wasm_bindgen]
pub fn poseidon2_hash3(
    input0: &[u8],
    input1: &[u8],
    input2: &[u8],
    domain_separation: u8,
) -> Result<Vec<u8>, JsValue> {
    let a = bytes_to_scalar(input0)?;
    let b = bytes_to_scalar(input1)?;
    let c = bytes_to_scalar(input2)?;
    let domain = Scalar::from(domain_separation as u64);

    let result = poseidon2_hash3_internal(a, b, c, Some(domain));
    Ok(scalar_to_bytes(&result))
}

/// Derive public key from private key
///
/// publicKey = Poseidon2(privateKey, 0, domain=0)
#[wasm_bindgen]
pub fn derive_public_key(private_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let sk = bytes_to_scalar(private_key)?;
    let pk = derive_public_key_internal(sk);
    Ok(scalar_to_bytes(&pk))
}

/// Derive public key and return as hex string (for JS BigInt)
#[wasm_bindgen]
pub fn derive_public_key_hex(private_key: &[u8]) -> Result<String, JsValue> {
    let sk = bytes_to_scalar(private_key)?;
    let pk = derive_public_key_internal(sk);
    Ok(scalar_to_hex(&pk))
}

/// Compute commitment: hash(amount, publicKey, blinding)
///
/// Uses domain separation 0x01 for leaf commitments
#[wasm_bindgen]
pub fn compute_commitment(
    amount: &[u8],
    public_key: &[u8],
    blinding: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let amt = bytes_to_scalar(amount)?;
    let pk = bytes_to_scalar(public_key)?;
    let blind = bytes_to_scalar(blinding)?;

    // Domain separation 0x01 for leaf commitment
    let commitment = poseidon2_hash3_internal(amt, pk, blind, Some(Scalar::from(1u64)));
    Ok(scalar_to_bytes(&commitment))
}

/// Compute signature: hash(privateKey, commitment, merklePath)
#[wasm_bindgen]
pub fn compute_signature(
    private_key: &[u8],
    commitment: &[u8],
    merkle_path: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let sk = bytes_to_scalar(private_key)?;
    let comm = bytes_to_scalar(commitment)?;
    let path = bytes_to_scalar(merkle_path)?;

    let sig = poseidon2_hash3_internal(sk, comm, path, Some(Scalar::from(4u64)));
    Ok(scalar_to_bytes(&sig))
}

/// Compute nullifier: hash(commitment, pathIndices, signature)
///
/// Uses domain separation 0x02 for nullifiers
#[wasm_bindgen]
pub fn compute_nullifier(
    commitment: &[u8],
    path_indices: &[u8],
    signature: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let comm = bytes_to_scalar(commitment)?;
    let indices = bytes_to_scalar(path_indices)?;
    let sig = bytes_to_scalar(signature)?;

    // Domain separation 0x02 for nullifier
    let nullifier = poseidon2_hash3_internal(comm, indices, sig, Some(Scalar::from(2u64)));
    Ok(scalar_to_bytes(&nullifier))
}

/// Internal public key derivation
/// Uses domain separation 0x03 (matching Keypair template in circom)
pub(crate) fn derive_public_key_internal(private_key: Scalar) -> Scalar {
    poseidon2_hash2_internal(private_key, Scalar::from(0u64), Some(Scalar::from(3u64)))
}