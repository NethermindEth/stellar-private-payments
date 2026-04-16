//! Serialization utilities for witness and proof data
//!
//! Handles conversion between JavaScript types and Arkworks field elements.
//! All byte arrays use Little-Endian format (as expected by Arkworks).
use alloc::{format, string::String, vec, vec::Vec};
use anyhow::{Result, anyhow};
use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, PrimeField};
use core::ops::{Add, Mul};
use zkhash::fields::bn256::FpBN256 as Scalar;

use crate::types::FIELD_SIZE;

fn bytes_to_prime_field<F: PrimeField>(bytes: &[u8]) -> Result<F> {
    if bytes.len() != FIELD_SIZE {
        return Err(anyhow!(
            "Expected {} bytes, got {}",
            FIELD_SIZE,
            bytes.len()
        ));
    }
    Ok(F::from_le_bytes_mod_order(bytes))
}

fn prime_field_to_bytes<F: PrimeField>(f: &F) -> Vec<u8> {
    let src = f.into_bigint().to_bytes_le();
    if src.len() > FIELD_SIZE {
        panic!(
            "PrimeField element serialized to {} bytes, expected <= {}",
            src.len(),
            FIELD_SIZE
        );
    }

    let mut out = vec![0u8; FIELD_SIZE];
    out[..src.len()].copy_from_slice(&src);
    out
}

/// Convert Little-Endian bytes to Arkworks Fr field element
pub fn bytes_to_fr(bytes: &[u8]) -> Result<Fr> {
    bytes_to_prime_field(bytes)
}

/// Convert Arkworks Fr field element to Little-Endian bytes
pub fn fr_to_bytes(fr: &Fr) -> Vec<u8> {
    prime_field_to_bytes(fr)
}

/// Convert Little-Endian bytes to zkhash Scalar
pub fn bytes_to_scalar(bytes: &[u8]) -> Result<Scalar> {
    bytes_to_prime_field(bytes)
}

/// Convert zkhash Scalar to Little-Endian bytes
pub fn scalar_to_bytes(scalar: &Scalar) -> Vec<u8> {
    prime_field_to_bytes(scalar)
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
pub fn hex_to_scalar(hex: &str) -> Result<Scalar> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);

    if hex.len() > 64 {
        return Err(anyhow!("Hex string too long"));
    }

    // Pad to 64 characters
    let padded = format!("{:0>64}", hex);

    // Parse hex to bytes (big-endian)
    let mut bytes = [0u8; FIELD_SIZE];
    for (i, chunk) in padded.as_bytes().chunks(2).enumerate() {
        let byte_str = core::str::from_utf8(chunk).map_err(|_| anyhow!("Invalid hex character"))?;
        let idx = FIELD_SIZE
            .checked_sub(1)
            .and_then(|v| v.checked_sub(i))
            .ok_or_else(|| anyhow!("Index overflow"))?;
        bytes[idx] =
            u8::from_str_radix(byte_str, 16).map_err(|_| anyhow!("Invalid hex character"))?;
    }

    Ok(Scalar::from_le_bytes_mod_order(&bytes))
}

/// Parse witness bytes into vector of Fr elements
///
/// Witness bytes are Little-Endian, 32 bytes per element
pub fn parse_witness(witness_bytes: &[u8]) -> Result<Vec<u8>> {
    if !witness_bytes.len().is_multiple_of(FIELD_SIZE) {
        return Err(anyhow!(
            "Witness bytes length {} is not a multiple of {}",
            witness_bytes.len(),
            FIELD_SIZE
        ));
    }

    // For now, just validate and return as-is
    // The actual parsing happens in the prover
    Ok(witness_bytes.to_vec())
}

/// Get the number of witness elements
pub fn witness_element_count(witness_bytes: &[u8]) -> Result<u32> {
    if !witness_bytes.len().is_multiple_of(FIELD_SIZE) {
        return Err(anyhow!("Invalid witness bytes length"));
    }
    let count = witness_bytes.len() / FIELD_SIZE;
    u32::try_from(count).map_err(|_| anyhow!("Witness count exceeds u32"))
}

/// Convert a u64 to Little-Endian field element bytes
pub fn u64_to_field_bytes(value: u64) -> Vec<u8> {
    let scalar = Scalar::from(value);
    scalar_to_bytes(&scalar)
}

/// Convert a decimal string to Little-Endian field element bytes
pub fn decimal_to_field_bytes(decimal: &str) -> Result<Vec<u8>> {
    // Parse decimal string to BigInt-like representation
    // For simplicity, handle up to u128 range
    let value: u128 = decimal
        .parse()
        .map_err(|_| anyhow!("Invalid decimal string"))?;

    // Convert to field element using safe field arithmetic
    let low = (value & 0xFFFFFFFFFFFFFFFF) as u64;
    let high = (value >> 64) as u64;

    let scalar = Scalar::from(low).add(Scalar::from(high).mul(Scalar::from(1u64 << 32).square()));
    Ok(scalar_to_bytes(&scalar))
}

/// Convert Little-Endian field bytes to hex string
pub fn field_bytes_to_hex(bytes: &[u8]) -> Result<String> {
    let scalar = bytes_to_scalar(bytes)?;
    Ok(scalar_to_hex(&scalar))
}

/// Convert hex string to Little-Endian field bytes
pub fn hex_to_field_bytes(hex: &str) -> Result<Vec<u8>> {
    let scalar = hex_to_scalar(hex)?;
    Ok(scalar_to_bytes(&scalar))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{string::String, vec};

    #[test]
    fn fr_roundtrip_bytes() {
        let original = Fr::from(123u64);
        let bytes = fr_to_bytes(&original);
        let parsed = bytes_to_fr(&bytes).expect("bytes_to_fr failed");
        assert_eq!(parsed, original);
    }

    #[test]
    fn scalar_roundtrip_bytes() {
        let original = Scalar::from(123u64);
        let bytes = scalar_to_bytes(&original);
        let parsed = bytes_to_scalar(&bytes).expect("bytes_to_scalar failed");
        assert_eq!(scalar_to_bytes(&parsed), bytes);
    }

    #[test]
    fn scalar_roundtrip_hex() {
        let original = Scalar::from(123u64);
        let hex = scalar_to_hex(&original);
        let parsed = hex_to_scalar(&hex).expect("hex_to_scalar failed");
        assert_eq!(scalar_to_bytes(&parsed), scalar_to_bytes(&original));
    }

    #[test]
    fn bytes_to_fr_rejects_wrong_len() {
        assert!(bytes_to_fr(&vec![0u8; 31]).is_err());
        assert!(bytes_to_fr(&vec![0u8; 33]).is_err());
    }

    #[test]
    fn bytes_to_scalar_rejects_wrong_len() {
        assert!(bytes_to_scalar(&vec![0u8; 31]).is_err());
        assert!(bytes_to_scalar(&vec![0u8; 33]).is_err());
    }

    #[test]
    fn hex_to_scalar_rejects_too_long() {
        let mut too_long = String::from("0x");
        too_long.push_str(&"aa".repeat(33));
        assert!(hex_to_scalar(&too_long).is_err());
    }
}
