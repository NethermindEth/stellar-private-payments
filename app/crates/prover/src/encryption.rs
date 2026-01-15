//! Cryptographic key derivation and note encryption.
//!
//! This module implements two key derivation schemes:
//!
//! 1. **Encryption Keys (X25519)**: For encrypting/decrypting note data
//!    off-chain. Derived from Freighter signature using SHA-256.
//!
//! 2. **Note Identity Keys (BN254)**: For proving ownership in ZK circuits.
//!    Also derived from Freighter signature using SHA-256 with a different domain separation.
//!
//! Both key types are deterministically derived from wallet signatures,
//! ensuring users can recover all keys using only their wallet seed phrase.
//! Signature results are not directly used as keys, we apply a hash function over them to break
//! any potential underlying math structure.   
//!
//! # Key Architecture
//!
//! ```text
//! Freighter Wallet (Ed25519)
//!        │
//!        ├── signMessage("Sign to access Privacy Pool [v1]")
//!        │          │
//!        │          └── SHA-256 → X25519 Encryption Keypair. Used for encrypting/decrypting note data.
//!        │
//!        └── signMessage("Spending Key [v1]")
//!                   │
//!                   └── SHA-256 → BN254 Note Private Key. Used for note ownership proofs in ZK circuits.
//!                                      │
//!                                      └── Poseidon2 → Note Public Key
//! ```

use alloc::{format, vec::Vec};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use x25519_dalek::{PublicKey, StaticSecret};
use xsalsa20poly1305::{KeyInit, Nonce, XSalsa20Poly1305, aead::Aead};

/// Encryption key derivation (X25519). Used for off-chain note encryption/decryption
/// Derive X25519 encryption keypair deterministically from a Freighter
/// signature.
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
/// * `signature` - Stellar Ed25519 signature from signing "Sign to access Privacy Pool [v1]"
///
/// # Returns
/// 64 bytes: `[public_key (32), private_key (32)]`
#[wasm_bindgen]
pub fn derive_keypair_from_signature(signature: &[u8]) -> Result<Vec<u8>, JsValue> {
    if signature.len() != 64 {
        return Err(JsValue::from_str("Signature must be 64 bytes (Ed25519)"));
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

    // Return [public_key (32), private_key (32)]
    let mut result = Vec::with_capacity(64);
    result.extend_from_slice(public.as_bytes());
    result.extend_from_slice(&secret.to_bytes());

    Ok(result)
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
/// * `signature` - Stellar Ed25519 signature from signing "Spending Key [v1]"
///
/// # Returns
/// 32 bytes: Note private key (BN254 scalar, little-endian)
#[wasm_bindgen]
pub fn derive_note_private_key(signature: &[u8]) -> Result<Vec<u8>, JsValue> {
    if signature.len() != 64 {
        return Err(JsValue::from_str("Signature must be 64 bytes (Ed25519)"));
    }

    // Hash signature to get 32-byte key
    // SHA-256 output is always < BN254 field modulus, so no reduction needed
    let mut hasher = Sha256::new();
    hasher.update(signature);
    let key = hasher.finalize();

    Ok(key.to_vec())
}

/// Blinding factor generation. Used for note commitment uniqueness
/// Generate a cryptographically random blinding factor for a note.
///
/// Each note requires a unique blinding factor to ensure commitments are unique
/// even when amount and recipient are the same.
///
/// # Returns
/// 32 bytes: Random BN254 scalar (little-endian)
///
/// # Errors
/// Returns an error if the platform's secure random number generator is
/// unavailable. This can happen in HTTP contexts instead of HTTPS.
///
/// # Note
/// Unlike the private keys above, blinding factors are NOT derived
/// deterministically. They are random per-note and must be stored for later use.
#[wasm_bindgen]
pub fn generate_random_blinding() -> Result<Vec<u8>, JsValue> {
    let mut blinding = [0u8; 32];
    getrandom::getrandom(&mut blinding)
        .map_err(|e| JsValue::from_str(&format!("Random generation failed: {}", e)))?;
    Ok(blinding.to_vec())
}

/// Encrypt note data using X25519-XSalsa20-Poly1305 (NaCl library standard)
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
#[wasm_bindgen]
pub fn encrypt_note_data(
    recipient_pubkey_bytes: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, JsValue> {
    if recipient_pubkey_bytes.len() != 32 {
        return Err(JsValue::from_str("Recipient public key must be 32 bytes"));
    }
    if plaintext.len() != 40 {
        return Err(JsValue::from_str(
            "Plaintext must be 40 bytes (8 amount + 32 blinding)",
        ));
    }

    // Generate ephemeral secret key using getrandom directly
    let mut ephemeral_bytes = [0u8; 32];
    getrandom::getrandom(&mut ephemeral_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to generate ephemeral key: {}", e)))?;

    let ephemeral_secret = StaticSecret::from(ephemeral_bytes);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    // ECDH: derive shared secret
    let recipient_public = PublicKey::from(
        *<&[u8; 32]>::try_from(recipient_pubkey_bytes)
            .map_err(|_| JsValue::from_str("Invalid recipient public key"))?,
    );
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_public);

    // Setup XSalsa20Poly1305 cipher with shared secret
    let cipher = XSalsa20Poly1305::new(shared_secret.as_bytes().into());

    // Generate random nonce (24 bytes for XSalsa20) using getrandom
    let mut nonce_bytes = [0u8; 24];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to generate nonce: {}", e)))?;
    let nonce = Nonce::from(nonce_bytes);

    // Encrypt plaintext
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| JsValue::from_str(&format!("Encryption failed: {:?}", e)))?;

    // Pack: [ephemeral_pubkey (32)] [nonce (24)] [ciphertext + tag]
    // 32 (pubkey) + 24 (nonce) = 56 bytes overhead
    let capacity = ciphertext.len().checked_add(56)?;
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
/// - Failure: Empty vec
#[wasm_bindgen]
pub fn decrypt_note_data(
    private_key_bytes: &[u8],
    encrypted_data: &[u8],
) -> Result<Vec<u8>, JsValue> {
    if private_key_bytes.len() != 32 {
        return Err(JsValue::from_str("Private key must be 32 bytes"));
    }

    // Minimum size: ephemeral_pubkey (32) + nonce (24) + min ciphertext (40) + tag (16) = 112
    if encrypted_data.len() < 112 {
        return Err(JsValue::from_str("Encrypted data too short"));
    }

    // Extract components
    let ephemeral_pubkey = &encrypted_data[0..32];
    let nonce_bytes = &encrypted_data[32..56];
    let ciphertext_with_tag = &encrypted_data[56..];

    // Setup our private key
    let our_secret = StaticSecret::from(
        *<&[u8; 32]>::try_from(private_key_bytes)
            .map_err(|_| JsValue::from_str("Invalid private key"))?,
    );

    // ECDH: derive shared secret
    let ephemeral_public = PublicKey::from(
        *<&[u8; 32]>::try_from(ephemeral_pubkey)
            .map_err(|_| JsValue::from_str("Invalid ephemeral public key"))?,
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
