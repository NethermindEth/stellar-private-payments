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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // Reference implementations from circuits crate
    use circuits::test::utils::general as ref_general;
    use circuits::test::utils::keypair as ref_keypair;
    use circuits::test::utils::transaction as ref_tx;

    // ========== Poseidon2 cross-validation ==========

    #[test]
    fn test_poseidon2_hash2_matches_reference() {
        let a = Scalar::from(42u64);
        let b = Scalar::from(99u64);
        let dom = Some(Scalar::from(3u64));

        let ours = poseidon2_hash2(a, b, dom);
        let reference = ref_general::poseidon2_hash2(a, b, dom);
        assert_eq!(ours, reference, "poseidon2_hash2 mismatch with reference");
    }

    #[test]
    fn test_poseidon2_hash3_matches_reference() {
        let a = Scalar::from(10u64);
        let b = Scalar::from(20u64);
        let c = Scalar::from(30u64);
        let dom = Some(Scalar::from(1u64));

        let ours = poseidon2_hash3(a, b, c, dom);
        let reference = ref_general::poseidon2_hash3(a, b, c, dom);
        assert_eq!(ours, reference, "poseidon2_hash3 mismatch with reference");
    }

    #[test]
    fn test_poseidon2_compression_matches_reference() {
        let left = Scalar::from(111u64);
        let right = Scalar::from(222u64);

        let ours = poseidon2_compression(left, right);
        let reference = ref_general::poseidon2_compression(left, right);
        assert_eq!(
            ours, reference,
            "poseidon2_compression mismatch with reference"
        );
    }

    #[test]
    fn test_poseidon2_hash2_no_domain() {
        let a = Scalar::from(1u64);
        let b = Scalar::from(2u64);

        let with_none = poseidon2_hash2(a, b, None);
        let with_zero = poseidon2_hash2(a, b, Some(Scalar::from(0u64)));
        assert_eq!(with_none, with_zero, "None domain should equal 0 domain");
    }

    // ========== Key derivation cross-validation ==========

    #[test]
    fn test_derive_public_key_matches_reference() {
        let privkey = Scalar::from(12345u64);

        let ours = derive_public_key(&privkey);
        let reference = ref_keypair::derive_public_key(privkey);
        assert_eq!(
            ours, reference,
            "derive_public_key mismatch with reference"
        );
    }

    #[test]
    fn test_derive_public_key_deterministic() {
        let privkey = Scalar::from(777u64);
        let pk1 = derive_public_key(&privkey);
        let pk2 = derive_public_key(&privkey);
        assert_eq!(pk1, pk2, "public key derivation should be deterministic");
    }

    #[test]
    fn test_derive_public_key_different_inputs() {
        let pk1 = derive_public_key(&Scalar::from(1u64));
        let pk2 = derive_public_key(&Scalar::from(2u64));
        assert_ne!(pk1, pk2, "different private keys should produce different public keys");
    }

    // ========== Commitment cross-validation ==========

    #[test]
    fn test_commitment_matches_reference() {
        let amount = Scalar::from(1000u64);
        let pubkey = Scalar::from(42u64);
        let blinding = Scalar::from(99u64);

        let ours = commitment(amount, pubkey, blinding);
        let reference = ref_tx::commitment(amount, pubkey, blinding);
        assert_eq!(ours, reference, "commitment mismatch with reference");
    }

    // ========== Sign cross-validation ==========

    #[test]
    fn test_sign_matches_reference() {
        let privkey = Scalar::from(100u64);
        let cm = Scalar::from(200u64);
        let path = Scalar::from(5u64);

        let ours = sign(privkey, cm, path);
        let reference = ref_keypair::sign(privkey, cm, path);
        assert_eq!(ours, reference, "sign mismatch with reference");
    }

    // ========== Nullifier ==========

    #[test]
    fn test_nullifier_uses_domain_2() {
        // nullifier(cm, path, sig) should equal poseidon2_hash3(cm, path, sig, domain=2)
        let cm = Scalar::from(300u64);
        let path = Scalar::from(7u64);
        let sig = Scalar::from(400u64);

        let nul = nullifier(cm, path, sig);
        let expected = poseidon2_hash3(cm, path, sig, Some(Scalar::from(2u64)));
        assert_eq!(nul, expected, "nullifier should use domain=2");
    }

    // ========== Full nullifier pipeline ==========

    #[test]
    fn test_full_nullifier_pipeline() {
        let privkey = Scalar::from(55555u64);
        let pubkey = derive_public_key(&privkey);
        let amount = Scalar::from(1000u64);
        let blinding = Scalar::from(12345u64);
        let leaf_index = Scalar::from(3u64);

        let cm = commitment(amount, pubkey, blinding);
        let sig = sign(privkey, cm, leaf_index);
        let nul = nullifier(cm, leaf_index, sig);

        // Reference pipeline (pubkey, commitment, sign use public functions)
        let ref_pubkey = ref_keypair::derive_public_key(privkey);
        let ref_cm = ref_tx::commitment(amount, ref_pubkey, blinding);
        let ref_sig = ref_keypair::sign(privkey, ref_cm, leaf_index);
        // nullifier is pub(crate) in circuits, so validate via raw hash
        let ref_nul = ref_general::poseidon2_hash3(ref_cm, leaf_index, ref_sig, Some(Scalar::from(2u64)));

        assert_eq!(pubkey, ref_pubkey);
        assert_eq!(cm, ref_cm);
        assert_eq!(sig, ref_sig);
        assert_eq!(nul, ref_nul, "full nullifier pipeline mismatch");
    }

    // ========== Membership leaf ==========

    #[test]
    fn test_membership_leaf_uses_domain_1() {
        let pubkey = Scalar::from(42u64);
        let blinding = Scalar::from(0u64);

        let leaf = membership_leaf(pubkey, blinding);
        let expected = poseidon2_hash2(pubkey, blinding, Some(Scalar::from(1u64)));
        assert_eq!(leaf, expected);
    }

    // ========== Scalar conversions ==========

    #[test]
    fn test_scalar_hex_be_roundtrip() {
        let original = Scalar::from(123456789u64);
        let hex_str = scalar_to_hex_be(&original);
        let recovered = hex_be_to_scalar(&hex_str).unwrap();
        assert_eq!(original, recovered, "hex BE roundtrip failed");
    }

    #[test]
    fn test_scalar_hex_be_zero() {
        let zero = Scalar::from(0u64);
        let hex_str = scalar_to_hex_be(&zero);
        let recovered = hex_be_to_scalar(&hex_str).unwrap();
        assert_eq!(zero, recovered);
    }

    #[test]
    fn test_scalar_hex_be_with_prefix() {
        let val = Scalar::from(255u64);
        let hex_str = scalar_to_hex_be(&val);
        // Should also work with 0x prefix
        let with_prefix = format!("0x{hex_str}");
        let recovered = hex_be_to_scalar(&with_prefix).unwrap();
        assert_eq!(val, recovered, "hex with 0x prefix roundtrip failed");
    }

    #[test]
    fn test_scalar_le_bytes_roundtrip() {
        let original = Scalar::from(987654321u64);
        let bytes = scalar_to_le_bytes(&original);
        let recovered = le_bytes_to_scalar(&bytes);
        assert_eq!(original, recovered, "LE bytes roundtrip failed");
    }

    #[test]
    fn test_scalar_be_bytes_length() {
        let val = Scalar::from(1u64);
        let bytes = scalar_to_be_bytes(&val);
        assert_eq!(bytes.len(), 32);
    }

    // ========== Encryption round-trip ==========

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // Generate a keypair
        let mut secret_bytes = [0u8; 32];
        getrandom::getrandom(&mut secret_bytes).unwrap();
        let secret = x25519_dalek::StaticSecret::from(secret_bytes);
        let public = x25519_dalek::PublicKey::from(&secret);

        let amount = 42000u64;
        let blinding = Scalar::from(99999u64);

        let encrypted = encrypt_note(public.as_bytes(), amount, &blinding).unwrap();
        assert_eq!(encrypted.len(), 112, "encrypted output should be 112 bytes");

        let decrypted = decrypt_note(&secret.to_bytes(), &encrypted)
            .unwrap()
            .expect("decryption should succeed");

        assert_eq!(decrypted.0, amount, "decrypted amount mismatch");
        assert_eq!(decrypted.1, blinding, "decrypted blinding mismatch");
    }

    #[test]
    fn test_decrypt_with_wrong_key_returns_none() {
        let mut secret_bytes = [0u8; 32];
        getrandom::getrandom(&mut secret_bytes).unwrap();
        let secret = x25519_dalek::StaticSecret::from(secret_bytes);
        let public = x25519_dalek::PublicKey::from(&secret);

        let amount = 1000u64;
        let blinding = Scalar::from(42u64);
        let encrypted = encrypt_note(public.as_bytes(), amount, &blinding).unwrap();

        // Try to decrypt with a different key
        let mut wrong_bytes = [0u8; 32];
        getrandom::getrandom(&mut wrong_bytes).unwrap();
        let result = decrypt_note(&wrong_bytes, &encrypted).unwrap();
        assert!(result.is_none(), "decryption with wrong key should return None");
    }

    #[test]
    fn test_decrypt_too_short() {
        let short_data = vec![0u8; 50];
        let key = [0u8; 32];
        let result = decrypt_note(&key, &short_data);
        assert!(result.is_err(), "should error on too-short data");
    }

    // ========== Random blinding ==========

    #[test]
    fn test_random_blinding_is_nonzero() {
        let b1 = random_blinding().unwrap();
        let b2 = random_blinding().unwrap();
        // Extremely unlikely to be zero or equal
        assert_ne!(b1, Scalar::from(0u64));
        assert_ne!(b1, b2, "random blindings should differ");
    }
}
