//! Serialization utilities for witness and proof data
//!
//! Handles conversion between JavaScript types and Arkworks field elements.
//! All byte arrays use Little-Endian format (as expected by Arkworks).

use alloc::{format, string::String, vec::Vec};
use ark_bn254::Fr;
use ark_ff::{Field, PrimeField};
use core::ops::{Add, Mul};
use wasm_bindgen::prelude::*;
use zkhash::fields::bn256::FpBN256 as Scalar;

use crate::types::FIELD_SIZE;

/// Convert Little-Endian bytes to Arkworks Fr field element
pub fn bytes_to_fr(bytes: &[u8]) -> Result<Fr, JsValue> {
    if bytes.len() != FIELD_SIZE {
        return Err(JsValue::from_str(&format!(
            "Expected {} bytes, got {}",
            FIELD_SIZE,
            bytes.len()
        )));
    }
    Ok(Fr::from_le_bytes_mod_order(bytes))
}

/// Convert Arkworks Fr field element to Little-Endian bytes
pub fn fr_to_bytes(fr: &Fr) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(FIELD_SIZE);
    // Arkworks BigInt is stored as limbs, we need to convert to LE bytes
    let bigint = fr.into_bigint();
    for limb in bigint.0.iter() {
        bytes.extend_from_slice(&limb.to_le_bytes());
    }
    bytes.truncate(FIELD_SIZE);
    bytes
}

/// Convert Little-Endian bytes to zkhash Scalar
pub fn bytes_to_scalar(bytes: &[u8]) -> Result<Scalar, JsValue> {
    if bytes.len() != FIELD_SIZE {
        return Err(JsValue::from_str(&format!(
            "Expected {} bytes, got {}",
            FIELD_SIZE,
            bytes.len()
        )));
    }
    Ok(Scalar::from_le_bytes_mod_order(bytes))
}

/// Convert zkhash Scalar to Little-Endian bytes
pub fn scalar_to_bytes(scalar: &Scalar) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(FIELD_SIZE);
    let bigint = scalar.into_bigint();
    for limb in bigint.0.iter() {
        bytes.extend_from_slice(&limb.to_le_bytes());
    }
    bytes.truncate(FIELD_SIZE);
    bytes
}

/// Convert zkhash Scalar to hex string (for JS BigInt)
pub fn scalar_to_hex(scalar: &Scalar) -> String {
    let bytes = scalar_to_bytes(scalar);
    // Convert to big-endian hex for human readability
    let mut hex = String::from("0x");
    for byte in bytes.iter().rev() {
        hex.push_str(&format!("{:02x}", byte));
    }
    hex
}

/// Convert hex string to zkhash Scalar
pub fn hex_to_scalar(hex: &str) -> Result<Scalar, JsValue> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);

    if hex.len() > 64 {
        return Err(JsValue::from_str("Hex string too long"));
    }

    // Pad to 64 characters
    let padded = format!("{:0>64}", hex);

    // Parse hex to bytes (big-endian)
    let mut bytes = [0u8; FIELD_SIZE];
    for (i, chunk) in padded.as_bytes().chunks(2).enumerate() {
        let byte_str =
            core::str::from_utf8(chunk).map_err(|_| JsValue::from_str("Invalid hex character"))?;
        let idx = FIELD_SIZE
            .checked_sub(1)
            .and_then(|v| v.checked_sub(i))
            .ok_or_else(|| JsValue::from_str("Index overflow"))?;
        bytes[idx] = u8::from_str_radix(byte_str, 16)
            .map_err(|_| JsValue::from_str("Invalid hex character"))?;
    }

    Ok(Scalar::from_le_bytes_mod_order(&bytes))
}

/// Parse witness bytes into vector of Fr elements
///
/// Witness bytes are Little-Endian, 32 bytes per element
#[wasm_bindgen]
pub fn parse_witness(witness_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    if !witness_bytes.len().is_multiple_of(FIELD_SIZE) {
        return Err(JsValue::from_str(&format!(
            "Witness bytes length {} is not a multiple of {}",
            witness_bytes.len(),
            FIELD_SIZE
        )));
    }

    // For now, just validate and return as-is
    // The actual parsing happens in the prover
    Ok(witness_bytes.to_vec())
}

/// Get the number of witness elements
#[wasm_bindgen]
pub fn witness_element_count(witness_bytes: &[u8]) -> Result<u32, JsValue> {
    if !witness_bytes.len().is_multiple_of(FIELD_SIZE) {
        return Err(JsValue::from_str("Invalid witness bytes length"));
    }
    let count = witness_bytes.len() / FIELD_SIZE;
    u32::try_from(count).map_err(|_| JsValue::from_str("Witness count exceeds u32"))
}

/// Convert a u64 to Little-Endian field element bytes
#[wasm_bindgen]
pub fn u64_to_field_bytes(value: u64) -> Vec<u8> {
    let scalar = Scalar::from(value);
    scalar_to_bytes(&scalar)
}

/// Convert a decimal string to Little-Endian field element bytes
#[wasm_bindgen]
pub fn decimal_to_field_bytes(decimal: &str) -> Result<Vec<u8>, JsValue> {
    // Parse decimal string to BigInt-like representation
    // For simplicity, handle up to u128 range
    let value: u128 = decimal
        .parse()
        .map_err(|_| JsValue::from_str("Invalid decimal string"))?;

    // Convert to field element using safe field arithmetic
    let low = (value & 0xFFFFFFFFFFFFFFFF) as u64;
    let high = (value >> 64) as u64;

    let scalar = Scalar::from(low).add(Scalar::from(high).mul(Scalar::from(1u64 << 32).square()));
    Ok(scalar_to_bytes(&scalar))
}

/// Convert Little-Endian field bytes to hex string
#[wasm_bindgen]
pub fn field_bytes_to_hex(bytes: &[u8]) -> Result<String, JsValue> {
    let scalar = bytes_to_scalar(bytes)?;
    Ok(scalar_to_hex(&scalar))
}

/// Convert hex string to Little-Endian field bytes
#[wasm_bindgen]
pub fn hex_to_field_bytes(hex: &str) -> Result<Vec<u8>, JsValue> {
    let scalar = hex_to_scalar(hex)?;
    Ok(scalar_to_bytes(&scalar))
}
