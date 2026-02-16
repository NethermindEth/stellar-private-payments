//! Stellar identity access, BN254/X25519 derivation.
//!
//! Key derivation must match the browser exactly:
//! - Ed25519 secret key → sign deterministic message → SHA-256 → BN254/X25519

use anyhow::{Context, Result};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zkhash::fields::bn256::FpBN256 as Scalar;

use crate::stellar;

/// Message signed for BN254 note private key derivation.
const SPENDING_KEY_MESSAGE: &[u8] = b"Privacy Pool Spending Key [v1]";

/// Message signed for X25519 encryption key derivation.
const ENCRYPTION_KEY_MESSAGE: &[u8] = b"Sign to access Privacy Pool [v1]";

/// Decode a Stellar S... secret key to a 32-byte Ed25519 seed.
fn decode_secret_key(s_key: &str) -> Result<[u8; 32]> {
    let decoded = stellar_strkey::ed25519::PrivateKey::from_string(s_key)
        .context("Invalid S... secret key")?;
    Ok(decoded.0)
}

/// Sign a message deterministically with an Ed25519 key.
fn ed25519_sign(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let signing_key = SigningKey::from_bytes(seed);
    let sig = signing_key.sign(message);
    sig.to_bytes()
}

/// Derive the BN254 note private key for a stellar identity.
///
/// Process: secret key → Ed25519 sign(SPENDING_KEY_MESSAGE) → SHA-256 → Fr::from_le_bytes_mod_order
pub fn derive_note_private_key(identity: &str, network: &str) -> Result<Scalar> {
    let s_key = stellar::keys_secret(identity, network)?;
    let seed = decode_secret_key(&s_key)?;
    let sig = ed25519_sign(&seed, SPENDING_KEY_MESSAGE);

    let mut hasher = Sha256::new();
    hasher.update(sig);
    let hash = hasher.finalize();

    // Fr and Scalar are both BN254 field elements; reduce modulo field order
    let fr = Fr::from_le_bytes_mod_order(&hash);
    // Convert Fr to Scalar via BigInt
    let bigint = fr.into_bigint();
    let bytes_le = bigint.to_bytes_le();
    Ok(Scalar::from_le_bytes_mod_order(&bytes_le))
}

/// Derive the X25519 encryption keypair for a stellar identity.
///
/// Process: secret key → Ed25519 sign(ENCRYPTION_KEY_MESSAGE) → SHA-256 → X25519 keypair
///
/// Returns `(public_key_bytes, private_key_bytes)`.
pub fn derive_encryption_keypair(identity: &str, network: &str) -> Result<([u8; 32], [u8; 32])> {
    let s_key = stellar::keys_secret(identity, network)?;
    let seed = decode_secret_key(&s_key)?;
    let sig = ed25519_sign(&seed, ENCRYPTION_KEY_MESSAGE);

    let mut hasher = Sha256::new();
    hasher.update(sig);
    let hash = hasher.finalize();

    let mut secret_bytes = [0u8; 32];
    secret_bytes.copy_from_slice(&hash);

    let secret = StaticSecret::from(secret_bytes);
    let public = X25519PublicKey::from(&secret);

    Ok((*public.as_bytes(), secret.to_bytes()))
}

/// Get the G... public address for a stellar identity.
pub fn resolve_address(identity: &str, network: &str) -> Result<String> {
    stellar::keys_address(identity, network)
}
