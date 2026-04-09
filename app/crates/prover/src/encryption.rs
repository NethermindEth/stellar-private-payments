//! Cryptographic key derivation and note encryption.
//!
//! This module implements two key derivation schemes:
//!
//! 1. **Encryption Keys (X25519)**: For encrypting/decrypting note data
//!    off-chain. Derived from Freighter signature using SHA-256.
//!
//! 2. **Note Identity Keys (BN254)**: For proving ownership in ZK circuits.
//!    Also derived from Freighter signature using SHA-256 with domain
//!    separation.
//!
//! Both key types are deterministically derived from wallet signatures,
//! ensuring users can recover all keys using only their wallet seed phrase.
//!
//! We use SHA-256 as the hash function for both key derivation and encryption.
//! We use sha instead of Poseidon2 because:
//! - It won't be used in the circuit context
//! - SHA is well-established and its security has been more researched than
//!   Poseidon2
//!
//! # Key Architecture
//!
//! ```text
//! Freighter Wallet (Ed25519)
//!        │
//!        ├── signMessage("Sign to access Privacy Pool [v1]")
//!        │          │
//!        │          └── SHA-256 → X25519 Encryption Keypair
//!        │
//!        └── signMessage("Privacy Pool Spending Key [v1]")
//!                   │
//!                   └── SHA-256 → BN254 Note Private Key
//!                                      │
//!                                      └── Poseidon2 → Note Public Key
//! ```
use crate::crypto::derive_public_key;
use alloc::{format, string::String, vec::Vec};
use anyhow::{Result, anyhow};
use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use crypto_secretbox::{KeyInit, Nonce, XSalsa20Poly1305, aead::Aead};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use types::{
    EncryptionKeyPair, EncryptionPrivateKey, EncryptionPublicKey, EncryptionSignature, NoteAmount,
    NoteKeyPair, NotePrivateKey, NotePublicKey, SpendingSignature,
};

// Key derivation constants.
// These MUST remain constant for backwards compatibility.

/// Message signed to derive the X25519 encryption keypair
pub const ENCRYPTION_MESSAGE: &str = "Sign to access Privacy Pool [v1]";

/// Message signed to derive the BN254 note identity keypair
pub const SPENDING_KEY_MESSAGE: &str = "Privacy Pool Spending Key [v1]";

/// Keypairs derivation
pub fn derive_encryption_and_note_keypairs(
    spending_signature: SpendingSignature,
    encryption_signature: EncryptionSignature,
) -> Result<(NoteKeyPair, EncryptionKeyPair)> {
    let note_private_key = derive_note_private_key(spending_signature)?;
    let pubkey = derive_public_key(&note_private_key.0)?;
    let note_public_key = NotePublicKey(pubkey.try_into().map_err(|e: Vec<u8>| anyhow::anyhow!("Expected 32 bytes, but got {}", e.len()))?);
    let note_keypair = NoteKeyPair {
        private: note_private_key,
        public: note_public_key,
    };
    let encryption_keypair = derive_keypair_from_signature(encryption_signature)?;
    Ok((note_keypair, encryption_keypair))
}

/// Encryption key derivation (X25519). Used for off-chain note
/// encryption/decryption Derive X25519 encryption keypair deterministically
/// from a Freighter signature.
///
/// This keypair is used for encrypting note data (amount, blinding) so that
/// only the recipient can decrypt it. The encryption scheme is
/// X25519-XSalsa20-Poly1305.
///
/// # Derivation
/// ```text
/// signature (64 bytes) → SHA-256 → 32-byte seed → X25519 keypair
/// ```
///
/// # Arguments
/// * `signature` - Stellar Ed25519 signature from signing "Sign to access
///   Privacy Pool [v1]"
///
/// # Returns
/// 64 bytes: `[public_key (32), private_key (32)]`
fn derive_keypair_from_signature(signature: EncryptionSignature) -> Result<EncryptionKeyPair> {
    let EncryptionSignature(signature) = signature;
    if signature.len() != 64 {
        return Err(anyhow!("Signature must be 64 bytes (Ed25519)"));
    }

    // Hash signature to get a 32-byte seed
    let mut hasher = Sha256::new();
    hasher.update(signature);
    let seed = hasher.finalize();

    // Generate X25519 keypair from seed
    let mut secret_bytes = [0u8; 32];
    secret_bytes.copy_from_slice(&seed);

    let secret = StaticSecret::from(secret_bytes);
    let public = PublicKey::from(&secret);

    let keypair = EncryptionKeyPair {
        private: EncryptionPrivateKey(secret.to_bytes().try_into()?),
        public: EncryptionPublicKey(public.to_bytes().try_into()?),
    };

    Ok(keypair)
}

/// Derive private key (BN254 scalar) deterministically from a Freighter
/// signature for note identity. Used for ZK circuit ownership proofs
///
/// This private key is used inside ZK circuits to prove ownership of notes.
/// The corresponding public key is derived via Poseidon2 hash
///
/// # Derivation
/// ```text
/// signature (64 bytes) → SHA-256 → 32-byte BN254 scalar (note private key)
/// ```
///
/// # Arguments
/// * `signature` - Stellar Ed25519 signature from signing "Privacy Pool
///   Spending Key [v1]"
///
/// # Returns
/// 32 bytes: Note private key (BN254 scalar, little-endian)
fn derive_note_private_key(signature: SpendingSignature) -> Result<NotePrivateKey> {
    let SpendingSignature(signature) = signature;
    if signature.len() != 64 {
        return Err(anyhow!("Signature must be 64 bytes (Ed25519)"));
    }

    // Hash signature to get 32-byte key
    // As SHA-256 might be larger than BN254 field, we apply module reduction.
    let mut hasher = Sha256::new();
    hasher.update(signature);
    let key = hasher.finalize();

    // Reduce to BN254 module
    let field = Fr::from_le_bytes_mod_order(&key);

    // Serialize into bytes
    let mut result = [0u8; 32];
    field
        .serialize_compressed(&mut result[..])
        .expect("Serialization failed");

    Ok(NotePrivateKey(result))
}

/// Generate a cryptographically random blinding factor for a note.
///
/// Each note requires a unique blinding factor to ensure commitments are unique
/// even when amount and recipient are the same.
///
/// # Returns
/// 32 bytes: Random BN254 scalar (little-endian), reduced to field modulus
///
/// # Note
/// Unlike the private keys above, blinding factors are NOT derived
/// deterministically. They are random per-note and must be stored for later
/// use.
pub fn generate_random_blinding() -> Result<Vec<u8>> {
    let mut random_bytes = [0u8; 32];
    getrandom::getrandom(&mut random_bytes)
        .map_err(|e| anyhow!("Random generation failed: {}", e))?;

    // Reduce to BN254 field
    let scalar = Fr::from_le_bytes_mod_order(&random_bytes);

    // Serialize back to little-endian bytes
    let mut result = Vec::with_capacity(32);
    scalar
        .serialize_compressed(&mut result)
        .map_err(|e| anyhow!("Serialization failed: {}", e))?;
    Ok(result)
}

/// Encrypt output note data for on-chain storage.
///
/// Plaintext format: `amount (8 bytes LE) || blinding (32 bytes)`.
pub fn encrypt_output_note(
    recipient_pubkey: &EncryptionPublicKey,
    amount_stroops: NoteAmount,
    blinding: &[u8; 32],
) -> Result<Vec<u8>> {
    let mut plaintext = [0u8; 40];
    plaintext[..8].copy_from_slice(&amount_stroops.to_le_bytes());
    plaintext[8..].copy_from_slice(blinding);
    encrypt_note_data(recipient_pubkey.as_ref(), &plaintext)
}

/// Encrypt note data using X25519-XSalsa20-Poly1305 (NaCl crypto_box).
///
/// When sending a note to someone, we encrypt the sensitive data (amount and
/// blinding) with their X25519 public key. Only they can decrypt it.
///
/// # Output Format
/// ```text
/// [ephemeral_pubkey (32)] [nonce (24)] [ciphertext (40) + tag (16)]
/// Total: 112 bytes minimum
/// ```
///
/// # Arguments
/// * `recipient_pubkey_bytes` - Recipient's X25519 encryption public key (32
///   bytes)
/// * `plaintext` - Note data: `[amount (8 bytes LE)] [blinding (32 bytes)]` =
///   40 bytes
///
/// # Returns
/// Encrypted data (112 bytes)
fn encrypt_note_data(recipient_pubkey_bytes: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if recipient_pubkey_bytes.len() != 32 {
        return Err(anyhow!("Recipient public key must be 32 bytes"));
    }
    if plaintext.len() != 40 {
        return Err(anyhow!(
            "Plaintext must be 40 bytes (8 amount + 32 blinding)"
        ));
    }

    // Generate ephemeral secret key using getrandom directly
    let mut ephemeral_bytes = [0u8; 32];
    getrandom::getrandom(&mut ephemeral_bytes)
        .map_err(|e| anyhow!("Failed to generate ephemeral key: {}", e))?;

    let ephemeral_secret = StaticSecret::from(ephemeral_bytes);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    // ECDH: derive shared secret
    let recipient_public = PublicKey::from(
        *<&[u8; 32]>::try_from(recipient_pubkey_bytes)
            .map_err(|_| anyhow!("Invalid recipient public key"))?,
    );
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_public);

    // Setup XSalsa20Poly1305 cipher with shared secret
    let cipher = XSalsa20Poly1305::new(shared_secret.as_bytes().into());

    // Generate random nonce (24 bytes for XSalsa20) using getrandom
    let mut nonce_bytes = [0u8; 24];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| anyhow!("Failed to generate nonce: {}", e))?;
    let nonce = Nonce::from(nonce_bytes);

    // Encrypt plaintext
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow!("Encryption failed: {:?}", e))?;

    // Pack: [ephemeral_pubkey (32)] [nonce (24)] [ciphertext + tag]
    // 32 (pubkey) + 24 (nonce) = 56 bytes overhead
    let capacity = ciphertext
        .len()
        .checked_add(56)
        .expect("Integer overflow on encryption output size");
    let mut result = Vec::with_capacity(capacity);
    result.extend_from_slice(ephemeral_public.as_bytes());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt note data using X25519-XSalsa20-Poly1305.
///
/// When scanning for notes addressed to us, we try to decrypt each encrypted
/// output. If decryption succeeds, the note was sent to us.
///
/// # Arguments
/// * `private_key_bytes` - Our X25519 encryption private key (32 bytes)
/// * `encrypted_data` - Encrypted data from on-chain event (112+ bytes)
///
/// # Returns
/// - Success: `[amount (8 bytes LE)] [blinding (32 bytes)]` = 40 bytes
/// - Failure: Empty vec (note was not addressed to us)
fn decrypt_note_data(private_key_bytes: &[u8], encrypted_data: &[u8]) -> Result<Vec<u8>> {
    if private_key_bytes.len() != 32 {
        return Err(anyhow!("Private key must be 32 bytes"));
    }

    // Minimum size: ephemeral_pubkey (32) + nonce (24) + min ciphertext (40) + tag
    // (16) = 112
    if encrypted_data.len() < 112 {
        return Err(anyhow!("Encrypted data too short"));
    }

    // Extract components
    let ephemeral_pubkey = &encrypted_data[0..32];
    let nonce_bytes = &encrypted_data[32..56];
    let ciphertext_with_tag = &encrypted_data[56..];

    // Setup our private key
    let our_secret = StaticSecret::from(
        *<&[u8; 32]>::try_from(private_key_bytes).map_err(|_| anyhow!("Invalid private key"))?,
    );

    // ECDH: derive shared secret
    let ephemeral_public = PublicKey::from(
        *<&[u8; 32]>::try_from(ephemeral_pubkey)
            .map_err(|_| anyhow!("Invalid ephemeral public key"))?,
    );
    let shared_secret = our_secret.diffie_hellman(&ephemeral_public);

    // Setup XSalsa20Poly1305 cipher
    let cipher = XSalsa20Poly1305::new(shared_secret.as_bytes().into());

    // Create nonce from bytes (convert to array first)
    let mut nonce_array = [0u8; 24];
    nonce_array.copy_from_slice(nonce_bytes);
    let nonce = Nonce::from(nonce_array);

    // Decrypt
    match cipher.decrypt(&nonce, ciphertext_with_tag) {
        Ok(plaintext) => Ok(plaintext),
        Err(_) => {
            // Decryption failed - this note output is not for us
            Ok(Vec::new()) // Return empty vec
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_derive_keypair_determinism() {
        let signature = EncryptionSignature(vec![1u8; 64]);
        let keys1 = derive_keypair_from_signature(signature.clone()).expect("Derivation failed");
        let keys2 = derive_keypair_from_signature(signature).expect("Derivation failed");
        assert_eq!(keys1.private.0, keys2.private.0);
        assert_eq!(keys1.public.0, keys2.public.0);
        assert_eq!(keys1.private.0.len(), 32);
        assert_eq!(keys1.public.0.len(), 32);
    }

    #[test]
    fn test_encryption_roundtrip() {
        let recipient_sig = EncryptionSignature(vec![2u8; 64]);
        let recip_keys = derive_keypair_from_signature(recipient_sig).expect("Derivation failed");
        let pub_key = recip_keys.public.as_ref();
        let priv_key = recip_keys.private.as_ref();

        // 8 bytes amount + 32 bytes blinding = 40 bytes
        let amount = [10u8; 8];
        let blinding = [20u8; 32];
        let mut plaintext = Vec::with_capacity(40);
        plaintext.extend_from_slice(&amount);
        plaintext.extend_from_slice(&blinding);

        let encrypted = encrypt_note_data(pub_key, &plaintext).expect("Encryption failed");
        assert!(encrypted.len() >= 112);

        let decrypted = decrypt_note_data(priv_key, &encrypted).expect("Decryption failed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_failure_wrong_key() {
        let alice_sig = EncryptionSignature(vec![3u8; 64]);
        let bob_sig = EncryptionSignature(vec![4u8; 64]);

        let alice_keys = derive_keypair_from_signature(alice_sig).expect("Derivation failed");
        let bob_keys = derive_keypair_from_signature(bob_sig).expect("Derivation failed");

        // Encrypt for Alice.
        let alice_pub = alice_keys.public.as_ref();
        let plaintext = [0u8; 40];
        let encrypted = encrypt_note_data(alice_pub, &plaintext).expect("Encryption failed");

        // Bob tries to decrypt.
        let bob_priv = bob_keys.private.as_ref();
        let decrypted = decrypt_note_data(bob_priv, &encrypted)
            .expect("Decryption should handle failure gracefully");

        // Should return empty vec on failure as per implementation
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_invalid_input_lengths() {
        let sig = EncryptionSignature(vec![5u8; 64]);
        let keys = derive_keypair_from_signature(sig)
            .expect("Derivation failed in test_invalid_input_lengths");
        let pub_key = keys.public.as_ref();

        // Invalid plaintext length
        let res = encrypt_note_data(pub_key, &[0u8; 39]);
        assert!(res.is_err());

        // Invalid pubkey length
        let res = encrypt_note_data(&[0u8; 31], &[0u8; 40]);
        assert!(res.is_err());
    }
}
