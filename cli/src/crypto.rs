//! Poseidon2 ops, key derivation, encryption.
//!
//! Mirrors the browser's `prover/src/crypto.rs` and `prover/src/encryption.rs`
//! without wasm-bindgen.

use anyhow::{Result, bail};
use ark_ff::{BigInteger, PrimeField};
use crypto_secretbox::{KeyInit, Nonce, XSalsa20Poly1305, aead::Aead};
use x25519_dalek::{PublicKey, StaticSecret};
use zkhash::{
    fields::bn256::FpBN256 as Scalar,
    poseidon2::{
        poseidon2::Poseidon2,
        poseidon2_instance_bn256::{
            POSEIDON2_BN256_PARAMS_2, POSEIDON2_BN256_PARAMS_3, POSEIDON2_BN256_PARAMS_4,
        },
    },
};

// ==================== Poseidon2 hashing ====================

/// Poseidon2 compression (2 inputs, feed-forward). Used for Merkle tree nodes.
pub fn poseidon2_compression(left: Scalar, right: Scalar) -> Scalar {
    let h = Poseidon2::new(&POSEIDON2_BN256_PARAMS_2);
    let input = [left, right];
    let perm = h.permutation(&input);
    use core::ops::Add;
    perm[0].add(input[0])
}

/// Poseidon2 hash of 2 inputs with domain separation (t=3).
pub fn poseidon2_hash2(a: Scalar, b: Scalar, domain: Option<Scalar>) -> Scalar {
    let h = Poseidon2::new(&POSEIDON2_BN256_PARAMS_3);
    let d = domain.unwrap_or(Scalar::from(0u64));
    let perm = h.permutation(&[a, b, d]);
    perm[0]
}

/// Poseidon2 hash of 3 inputs with domain separation (t=4).
pub fn poseidon2_hash3(a: Scalar, b: Scalar, c: Scalar, domain: Option<Scalar>) -> Scalar {
    let h = Poseidon2::new(&POSEIDON2_BN256_PARAMS_4);
    let d = domain.unwrap_or(Scalar::from(0u64));
    let perm = h.permutation(&[a, b, c, d]);
    perm[0]
}

// ==================== Key derivation ====================

/// Derive note public key from note private key.
/// `publicKey = Poseidon2(privateKey, 0, domain=3)`
pub fn derive_public_key(private_key: &Scalar) -> Scalar {
    poseidon2_hash2(*private_key, Scalar::from(0u64), Some(Scalar::from(3u64)))
}

/// Compute commitment: `Poseidon2(amount, pubkey, blinding, domain=1)`
pub fn commitment(amount: Scalar, pubkey: Scalar, blinding: Scalar) -> Scalar {
    poseidon2_hash3(amount, pubkey, blinding, Some(Scalar::from(1u64)))
}

/// Compute signature: `Poseidon2(privateKey, commitment, merklePath, domain=4)`
pub fn sign(private_key: Scalar, commitment_val: Scalar, merkle_path: Scalar) -> Scalar {
    poseidon2_hash3(
        private_key,
        commitment_val,
        merkle_path,
        Some(Scalar::from(4u64)),
    )
}

/// Compute nullifier: `Poseidon2(commitment, pathIndices, signature, domain=2)`
pub fn nullifier(commitment_val: Scalar, path_indices: Scalar, signature: Scalar) -> Scalar {
    poseidon2_hash3(
        commitment_val,
        path_indices,
        signature,
        Some(Scalar::from(2u64)),
    )
}

/// Compute membership leaf: `Poseidon2(note_pubkey, 0, domain=1)`
pub fn membership_leaf(note_pubkey: Scalar, blinding: Scalar) -> Scalar {
    poseidon2_hash2(note_pubkey, blinding, Some(Scalar::from(1u64)))
}

// ==================== Scalar conversions ====================

/// Convert a scalar to big-endian hex string.
pub fn scalar_to_hex_be(s: &Scalar) -> String {
    let bytes = s.into_bigint().to_bytes_be();
    hex::encode(bytes)
}

/// Convert big-endian hex string to scalar.
pub fn hex_be_to_scalar(h: &str) -> Result<Scalar> {
    let h = h.strip_prefix("0x").unwrap_or(h);
    let padded = format!("{:0>64}", h);
    let bytes = hex::decode(&padded)?;
    let bu = num_bigint::BigUint::from_bytes_be(&bytes);
    Ok(Scalar::from(bu))
}

/// Convert scalar to little-endian bytes (32 bytes).
pub fn scalar_to_le_bytes(s: &Scalar) -> [u8; 32] {
    let mut buf = [0u8; 32];
    let le = s.into_bigint().to_bytes_le();
    let len = le.len().min(32);
    buf[..len].copy_from_slice(&le[..len]);
    buf
}

/// Convert little-endian bytes to scalar.
pub fn le_bytes_to_scalar(bytes: &[u8]) -> Scalar {
    Scalar::from_le_bytes_mod_order(bytes)
}

/// Convert scalar to big-endian bytes (32 bytes).
pub fn scalar_to_be_bytes(s: &Scalar) -> [u8; 32] {
    let mut buf = [0u8; 32];
    let be = s.into_bigint().to_bytes_be();
    let len = be.len().min(32);
    buf[..len].copy_from_slice(&be[..len]);
    buf
}

/// Generate a random blinding factor.
pub fn random_blinding() -> Result<Scalar> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|e| anyhow::anyhow!("RNG failed: {e}"))?;
    Ok(Scalar::from_le_bytes_mod_order(&bytes))
}

// ==================== Encryption ====================

/// Encrypt note data (amount + blinding) for a recipient.
///
/// Output format: `[ephemeral_pubkey (32)] [nonce (24)] [ciphertext+tag (56)]` = 112 bytes
pub fn encrypt_note(recipient_pubkey: &[u8; 32], amount: u64, blinding: &Scalar) -> Result<Vec<u8>> {
    // Build plaintext: [amount (8 bytes LE)] [blinding (32 bytes LE)]
    let mut plaintext = Vec::with_capacity(40);
    plaintext.extend_from_slice(&amount.to_le_bytes());
    plaintext.extend_from_slice(&scalar_to_le_bytes(blinding));

    // Generate ephemeral key
    let mut eph_bytes = [0u8; 32];
    getrandom::getrandom(&mut eph_bytes).map_err(|e| anyhow::anyhow!("RNG failed: {e}"))?;
    let eph_secret = StaticSecret::from(eph_bytes);
    let eph_public = PublicKey::from(&eph_secret);

    // ECDH
    let recipient_pk = PublicKey::from(*recipient_pubkey);
    let shared = eph_secret.diffie_hellman(&recipient_pk);

    // XSalsa20Poly1305
    let cipher = XSalsa20Poly1305::new(shared.as_bytes().into());
    let mut nonce_bytes = [0u8; 24];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| anyhow::anyhow!("RNG failed: {e}"))?;
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .map_err(|e| anyhow::anyhow!("Encryption failed: {e:?}"))?;

    // Pack output
    let mut result = Vec::with_capacity(112);
    result.extend_from_slice(eph_public.as_bytes());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt note data. Returns `Ok(Some((amount, blinding)))` on success,
/// `Ok(None)` if the note is not for us.
pub fn decrypt_note(private_key: &[u8; 32], encrypted: &[u8]) -> Result<Option<(u64, Scalar)>> {
    if encrypted.len() < 112 {
        bail!("Encrypted data too short");
    }

    let eph_pub_bytes: [u8; 32] = encrypted[0..32]
        .try_into()
        .expect("slice is 32 bytes");
    let nonce_bytes: [u8; 24] = encrypted[32..56]
        .try_into()
        .expect("slice is 24 bytes");
    let ciphertext = &encrypted[56..];

    let our_secret = StaticSecret::from(*private_key);
    let eph_public = PublicKey::from(eph_pub_bytes);
    let shared = our_secret.diffie_hellman(&eph_public);

    let cipher = XSalsa20Poly1305::new(shared.as_bytes().into());
    let nonce = Nonce::from(nonce_bytes);

    match cipher.decrypt(&nonce, ciphertext) {
        Ok(plaintext) => {
            if plaintext.len() != 40 {
                bail!("Decrypted data has wrong length: {}", plaintext.len());
            }
            let amount = u64::from_le_bytes(
                plaintext[0..8]
                    .try_into()
                    .expect("slice is 8 bytes"),
            );
            let blinding = le_bytes_to_scalar(&plaintext[8..40]);
            Ok(Some((amount, blinding)))
        }
        Err(_) => Ok(None), // Not for us
    }
}
