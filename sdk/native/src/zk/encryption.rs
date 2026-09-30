//! Cryptographic key derivation and note encryption.
//!
//! This module derives both privacy keypairs from a single wallet signature.
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
//!        └── signMessage("Privacy Pool Key Derivation [v2]")
//!                   │
//!                   ├── SHA-256("privacy-pool/note-key/v2" || sig)
//!                   │          └── BN254 Note Private Key → Poseidon2 → Note Public Key
//!                   │
//!                   └── SHA-256("privacy-pool/encryption-key/v2" || sig)
//!                              └── X25519 Encryption Keypair
//! ```
//! Note: the original scheme had separate signatures for spending and
//! encryption keys. To improve UX we reduced to a single signature derivation
//! accepting some associated risks like a user signing the message at a scam
//! website (2 separate signatures could create a safety pause to stop and
//! think)
use crate::{
    types::{
        EncryptionKeyPair, EncryptionPrivateKey, EncryptionPublicKey, Field,
        KeyDerivationSignature, NoteAmount, NoteKeyPair, NotePrivateKey, NotePublicKey,
    },
    zk::crypto::derive_public_key,
};
use anyhow::{Result, anyhow};
use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use crypto_secretbox::{KeyInit, Nonce, XSalsa20Poly1305, aead::Aead};
use ed25519_dalek::{Signature as DalekSignature, VerifyingKey};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

// Key derivation constants.
// These MUST remain constant for backwards compatibility.

/// Message signed to derive both privacy keypairs.
pub const KEY_DERIVATION_MESSAGE: &str = "Privacy Pool Key Derivation [v1]";

/// Prefix a SEP-53 wallet puts in front of a message before hashing it.
const SEP53_MESSAGE_PREFIX: &str = "Stellar Signed Message:\n";

/// The bytes a SEP-53 wallet hashes with SHA-256 and signs for `message`.
pub fn sep53_payload(message: &str) -> Vec<u8> {
    [SEP53_MESSAGE_PREFIX.as_bytes(), message.as_bytes()].concat()
}

/// Check that `signature` is `owner_address`'s own SEP-53 signature of
/// `message`.
///
/// The key-derivation signature *is* the note secret, so keys derived from
/// anyone else's signature would be filed under the owner and silently wrong.
/// Comparing addresses cannot rule that out — a wallet may sign with another
/// account than the one it was asked for, and its reply need not say which —
/// so the signature itself is checked against the owner's key.
pub fn verify_owner_signature(
    owner_address: &str,
    message: &str,
    signature: &KeyDerivationSignature,
) -> Result<()> {
    let signature: &[u8; 64] = signature
        .0
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("key-derivation signature must be 64 bytes"))?;
    let owner = stellar_strkey::ed25519::PublicKey::from_string(owner_address)
        .map_err(|_| anyhow!("note owner is not a valid account address"))?;
    let owner_key = VerifyingKey::from_bytes(&owner.0)
        .map_err(|e| anyhow!("note owner key is not a valid Ed25519 key: {e}"))?;

    let digest: [u8; 32] = Sha256::digest(sep53_payload(message)).into();
    // Strict, as the network itself verifies: a small-order owner key or `R`
    // is refused, where the lenient check accepts forgeries for such a key.
    owner_key
        .verify_strict(&digest, &DalekSignature::from_bytes(signature))
        .map_err(|_| anyhow!("the key-derivation signature was not made by the note owner's key"))
}

const NOTE_KEY_DOMAIN: &[u8] = b"privacy-pool/note-key/v1";
const ENCRYPTION_KEY_DOMAIN: &[u8] = b"privacy-pool/encryption-key/v1";
const MEMBERSHIP_BLINDING_DOMAIN: &[u8] = b"privacy-pool/asp-secret/v1";

/// Keypairs derivation
pub fn derive_encryption_and_note_keypairs(
    signature: KeyDerivationSignature,
) -> Result<(NoteKeyPair, EncryptionKeyPair)> {
    let note_private_key = derive_note_private_key(&signature)?;
    let pubkey = derive_public_key(&note_private_key.0)?;
    let note_public_key = NotePublicKey(
        pubkey
            .try_into()
            .map_err(|e: Vec<u8>| anyhow::anyhow!("Expected 32 bytes, but got {}", e.len()))?,
    );
    let note_keypair = NoteKeyPair {
        private: note_private_key,
        public: note_public_key,
    };
    let encryption_keypair = derive_keypair_from_signature(&signature)?;
    Ok((note_keypair, encryption_keypair))
}

/// Deterministically derive the account-scoped ASP membership blinding from
/// the wallet signature plus a stable network context.
pub fn derive_membership_blinding(
    signature: &KeyDerivationSignature,
    network_context: &str,
) -> Result<Field> {
    let KeyDerivationSignature(signature) = signature;
    if signature.len() != 64 {
        return Err(anyhow!("Signature must be 64 bytes (Ed25519)"));
    }

    let key = hash_signature_with_domain_and_context(
        signature,
        MEMBERSHIP_BLINDING_DOMAIN,
        network_context.as_bytes(),
    );
    let field = Fr::from_le_bytes_mod_order(&key);

    let mut result = [0u8; 32];
    field
        .serialize_compressed(&mut result[..])
        .expect("Serialization failed");
    Field::try_from_le_bytes(result)
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
/// * `signature` - Stellar Ed25519 signature from signing
///   `KEY_DERIVATION_MESSAGE`
///
/// # Returns
/// 64 bytes: `[public_key (32), private_key (32)]`
fn derive_keypair_from_signature(signature: &KeyDerivationSignature) -> Result<EncryptionKeyPair> {
    let KeyDerivationSignature(signature) = signature;
    if signature.len() != 64 {
        return Err(anyhow!("Signature must be 64 bytes (Ed25519)"));
    }

    let seed = hash_signature_with_domain(signature, ENCRYPTION_KEY_DOMAIN);

    // Generate X25519 keypair from seed
    let mut secret_bytes = [0u8; 32];
    secret_bytes.copy_from_slice(&seed[..]);

    let secret = StaticSecret::from(secret_bytes);
    let public = PublicKey::from(&secret);

    let keypair = EncryptionKeyPair {
        private: EncryptionPrivateKey(secret.to_bytes()),
        public: EncryptionPublicKey(public.to_bytes()),
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
/// * `signature` - Stellar Ed25519 signature from signing
///   `KEY_DERIVATION_MESSAGE`
///
/// # Returns
/// 32 bytes: Note private key (BN254 scalar, little-endian)
fn derive_note_private_key(signature: &KeyDerivationSignature) -> Result<NotePrivateKey> {
    let KeyDerivationSignature(signature) = signature;
    if signature.len() != 64 {
        return Err(anyhow!("Signature must be 64 bytes (Ed25519)"));
    }

    // Hash the shared signature with an explicit domain tag before reducing to
    // the BN254 field.
    let key = hash_signature_with_domain(signature, NOTE_KEY_DOMAIN);

    // Reduce to BN254 module
    let field = Fr::from_le_bytes_mod_order(&key[..]);

    // Serialize into bytes
    let mut result = [0u8; 32];
    field
        .serialize_compressed(&mut result[..])
        .expect("Serialization failed");

    Ok(NotePrivateKey(result))
}

fn hash_signature_with_domain(signature: &[u8], domain: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(signature);
    hasher.finalize().into()
}

fn hash_signature_with_domain_and_context(
    signature: &[u8],
    domain: &[u8],
    context: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0u8]);
    hasher.update(context);
    hasher.update([0u8]);
    hasher.update(signature);
    hasher.finalize().into()
}

/// Generate a cryptographically random blinding factor for a note.
///
/// Each note requires a unique blinding factor to ensure commitments are unique
/// even when amount and recipient are the same.
///
/// # Returns
/// Random BN254 scalar field element, reduced to the field modulus.
///
/// # Note
/// Unlike the private keys above, blinding factors are NOT derived
/// deterministically. They are random per-note and must be stored for later
/// use.
pub fn generate_random_blinding() -> Result<Field> {
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
    let le: [u8; 32] = result
        .try_into()
        .map_err(|v: Vec<u8>| anyhow!("random blinding: expected 32 bytes, got {}", v.len()))?;
    Field::try_from_le_bytes(le)
}

/// Encrypt output note data for on-chain storage.
///
/// Plaintext format: `amount (16 bytes LE) || blinding (32 bytes)`.
pub fn encrypt_output_note(
    recipient_pubkey: &EncryptionPublicKey,
    amount: NoteAmount,
    blinding: &Field,
) -> Result<Vec<u8>> {
    let mut plaintext = [0u8; 48];
    plaintext[..16].copy_from_slice(&amount.to_le_bytes());
    plaintext[16..].copy_from_slice(&blinding.to_le_bytes());
    encrypt_note_data(recipient_pubkey.as_ref(), &plaintext)
}

/// Decrypt output note data from on-chain storage.
///
/// Returns `Ok(None)` if the ciphertext is not addressed to the given private
/// key.
///
/// Expected plaintext format: `amount (16 bytes LE) || blinding (32 bytes LE)`.
pub fn decrypt_output_note(
    recipient_privkey: &EncryptionPrivateKey,
    encrypted_output: &[u8],
) -> Result<Option<(NoteAmount, Field)>> {
    let plaintext = decrypt_note_data(recipient_privkey.as_ref(), encrypted_output)?;
    if plaintext.is_empty() {
        return Ok(None);
    }
    if plaintext.len() != 48 {
        return Err(anyhow!(
            "Decrypted plaintext must be 48 bytes, got {}",
            plaintext.len()
        ));
    }

    let mut amount_le = [0u8; 16];
    amount_le.copy_from_slice(&plaintext[..16]);
    let amount = NoteAmount::from(u128::from_le_bytes(amount_le));

    let mut blinding_le = [0u8; 32];
    blinding_le.copy_from_slice(&plaintext[16..]);
    let blinding = Field::try_from_le_bytes(blinding_le)?;

    Ok(Some((amount, blinding)))
}

/// Encrypt note data using X25519-XSalsa20-Poly1305 (NaCl crypto_box).
///
/// When sending a note to someone, we encrypt the sensitive data (amount and
/// blinding) with their X25519 public key. Only they can decrypt it.
///
/// # Output Format
/// ```text
/// [ephemeral_pubkey (32)] [nonce (24)] [ciphertext (48) + tag (16)]
/// Total: 120 bytes minimum
/// ```
///
/// # Arguments
/// * `recipient_pubkey_bytes` - Recipient's X25519 encryption public key (32
///   bytes)
/// * `plaintext` - Note data: `[amount (16 bytes LE)] [blinding (32 bytes)]` =
///   48 bytes
///
/// # Returns
/// Encrypted data (120 bytes)
fn encrypt_note_data(recipient_pubkey_bytes: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if recipient_pubkey_bytes.len() != 32 {
        return Err(anyhow!("Recipient public key must be 32 bytes"));
    }
    if plaintext.len() != 48 {
        return Err(anyhow!(
            "Plaintext must be 48 bytes (16 amount + 32 blinding)"
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
/// * `encrypted_data` - Encrypted data from on-chain event (120+ bytes)
///
/// # Returns
/// - Success: `[amount (16 bytes LE)] [blinding (32 bytes)]` = 48 bytes
/// - Failure: Empty vec (note was not addressed to us)
fn decrypt_note_data(private_key_bytes: &[u8], encrypted_data: &[u8]) -> Result<Vec<u8>> {
    if private_key_bytes.len() != 32 {
        return Err(anyhow!("Private key must be 32 bytes"));
    }

    // Minimum size: ephemeral_pubkey (32) + nonce (24) + min ciphertext (48) +
    // tag (16) = 120
    if encrypted_data.len() < 120 {
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
mod owner_signature_tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use ed25519_dalek::{Signer as _, SigningKey};

    /// A genuine `stellar message sign` output (stellar-cli 28.0.0) from a
    /// throwaway key made only for this vector. It pins the SEP-53
    /// reconstruction to what a real signer produces, not to what this module
    /// itself would compute.
    const CLI_ADDRESS: &str = "GDL5QP4UAHS3ASWFKFIDYNF457L3SHWXOLDTKWIFTFTAZ2K23XQH7BXF";
    const CLI_MESSAGE: &str = "spp SEP-53 test vector";
    const CLI_SIGNATURE: &str =
        "jqX/w264/gvaGH3m2jb0SqicoR+dccjQsGWeYgaLknj8Qs5VkUND1c58XjMtWtQ6u8Ye77RX9hA8QAv0H6i8Cw==";

    fn account(seed: u8) -> (SigningKey, String) {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let address = stellar_strkey::ed25519::PublicKey(key.verifying_key().to_bytes())
            .to_string()
            .to_string();
        (key, address)
    }

    fn sign(key: &SigningKey, message: &str) -> KeyDerivationSignature {
        let digest: [u8; 32] = Sha256::digest(sep53_payload(message)).into();
        KeyDerivationSignature(key.sign(&digest).to_bytes().to_vec())
    }

    #[test]
    fn a_signature_from_the_stellar_cli_verifies() {
        let signature = KeyDerivationSignature(STANDARD.decode(CLI_SIGNATURE).expect("base64"));
        verify_owner_signature(CLI_ADDRESS, CLI_MESSAGE, &signature)
            .expect("a real SEP-53 signature by the owner must verify");
    }

    #[test]
    fn the_owners_own_signature_verifies() {
        let (owner, address) = account(1);
        let signature = sign(&owner, KEY_DERIVATION_MESSAGE);
        verify_owner_signature(&address, KEY_DERIVATION_MESSAGE, &signature)
            .expect("the owner signing for itself must verify");
    }

    /// The case the check exists for: a wallet that signed with another
    /// account. Its keys would otherwise be filed under the owner.
    #[test]
    fn a_signature_by_another_account_is_refused() {
        let (_, owner_address) = account(1);
        let (other, _) = account(2);
        let signature = sign(&other, KEY_DERIVATION_MESSAGE);
        assert!(
            verify_owner_signature(&owner_address, KEY_DERIVATION_MESSAGE, &signature).is_err()
        );
    }

    /// The identity point is a valid encoding of a small-order key. Anyone can
    /// forge a signature for it, over any message, that passes the lenient
    /// check: `R` the identity and `s` zero.
    #[test]
    fn a_forged_signature_for_a_small_order_owner_key_is_refused() {
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let owner_address = stellar_strkey::ed25519::PublicKey(identity)
            .to_string()
            .to_string();
        let mut forged = vec![0u8; 64];
        forged[..32].copy_from_slice(&identity);
        let signature = KeyDerivationSignature(forged);
        assert!(
            verify_owner_signature(&owner_address, KEY_DERIVATION_MESSAGE, &signature).is_err()
        );
    }

    #[test]
    fn a_signature_of_the_wrong_length_is_refused() {
        let (owner, address) = account(1);
        let mut signature = sign(&owner, KEY_DERIVATION_MESSAGE);
        signature.0.pop();
        assert!(verify_owner_signature(&address, KEY_DERIVATION_MESSAGE, &signature).is_err());
    }

    #[test]
    fn an_owner_that_is_not_an_account_address_is_refused() {
        let (owner, _) = account(1);
        let signature = sign(&owner, KEY_DERIVATION_MESSAGE);
        assert!(
            verify_owner_signature("not-an-address", KEY_DERIVATION_MESSAGE, &signature).is_err()
        );
    }

    #[test]
    fn a_signature_over_another_message_is_refused() {
        let (owner, address) = account(1);
        let signature = sign(&owner, "some other message");
        assert!(verify_owner_signature(&address, KEY_DERIVATION_MESSAGE, &signature).is_err());
    }

    /// The error reaches a UI toast, where wallet cancellations are recognised
    /// by substring. A signature from the wrong key is not a cancellation.
    #[test]
    fn the_refusal_does_not_read_as_a_wallet_cancellation() {
        let (_, owner_address) = account(1);
        let (other, _) = account(2);
        let rendered = verify_owner_signature(
            &owner_address,
            KEY_DERIVATION_MESSAGE,
            &sign(&other, KEY_DERIVATION_MESSAGE),
        )
        .expect_err("a foreign signature must be refused")
        .to_string()
        .to_ascii_lowercase();
        for word in ["rejected", "denied", "cancelled", "canceled"] {
            assert!(!rendered.contains(word), "{word:?} in: {rendered}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;

    #[test]
    fn test_derive_keypair_determinism() {
        let signature = KeyDerivationSignature(vec![1u8; 64]);
        let keys1 = derive_keypair_from_signature(&signature).expect("Derivation failed");
        let keys2 = derive_keypair_from_signature(&signature).expect("Derivation failed");
        assert_eq!(keys1.private.0, keys2.private.0);
        assert_eq!(keys1.public.0, keys2.public.0);
        assert_eq!(keys1.private.0.len(), 32);
        assert_eq!(keys1.public.0.len(), 32);
    }

    #[test]
    fn test_domain_separation_between_note_and_encryption_keys() {
        let signature = KeyDerivationSignature(vec![7u8; 64]);
        let note_key = derive_note_private_key(&signature).expect("note derivation failed");
        let enc_key =
            derive_keypair_from_signature(&signature).expect("encryption derivation failed");
        assert_ne!(note_key.0, enc_key.private.0);
    }

    #[test]
    fn test_membership_blinding_is_deterministic_per_network() {
        let signature = KeyDerivationSignature(vec![8u8; 64]);
        let first = derive_membership_blinding(&signature, "testnet").expect("derivation failed");
        let second = derive_membership_blinding(&signature, "testnet").expect("derivation failed");
        assert_eq!(first.to_le_bytes(), second.to_le_bytes());
    }

    #[test]
    fn test_membership_blinding_changes_across_networks() {
        let signature = KeyDerivationSignature(vec![8u8; 64]);
        let testnet = derive_membership_blinding(&signature, "testnet").expect("derivation failed");
        let mainnet = derive_membership_blinding(&signature, "mainnet").expect("derivation failed");
        assert_ne!(testnet.to_le_bytes(), mainnet.to_le_bytes());
    }

    #[test]
    fn test_membership_blinding_changes_across_signatures() {
        let first = derive_membership_blinding(&KeyDerivationSignature(vec![8u8; 64]), "testnet")
            .expect("derivation failed");
        let second = derive_membership_blinding(&KeyDerivationSignature(vec![9u8; 64]), "testnet")
            .expect("derivation failed");
        assert_ne!(first.to_le_bytes(), second.to_le_bytes());
    }

    #[test]
    fn test_encryption_roundtrip() {
        let recipient_sig = KeyDerivationSignature(vec![2u8; 64]);
        let recip_keys = derive_keypair_from_signature(&recipient_sig).expect("Derivation failed");
        let pub_key = recip_keys.public.as_ref();
        let priv_key = recip_keys.private.as_ref();

        // 16 bytes amount + 32 bytes blinding = 48 bytes
        let amount = [10u8; 16];
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
        let alice_sig = KeyDerivationSignature(vec![3u8; 64]);
        let bob_sig = KeyDerivationSignature(vec![4u8; 64]);

        let alice_keys = derive_keypair_from_signature(&alice_sig).expect("Derivation failed");
        let bob_keys = derive_keypair_from_signature(&bob_sig).expect("Derivation failed");

        // Encrypt for Alice.
        let alice_pub = alice_keys.public.as_ref();
        let plaintext = [0u8; 48];
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
        let sig = KeyDerivationSignature(vec![5u8; 64]);
        let keys = derive_keypair_from_signature(&sig)
            .expect("Derivation failed in test_invalid_input_lengths");
        let pub_key = keys.public.as_ref();

        // Invalid plaintext length
        let res = encrypt_note_data(pub_key, &[0u8; 39]);
        assert!(res.is_err());

        // Invalid pubkey length
        let res = encrypt_note_data(&[0u8; 31], &[0u8; 48]);
        assert!(res.is_err());
    }

    #[test]
    fn test_decrypt_output_note_roundtrip() -> Result<()> {
        let recipient_sig = KeyDerivationSignature(vec![9u8; 64]);
        let recip_keys = derive_keypair_from_signature(&recipient_sig)?;

        let amount = NoteAmount::from(42);
        let mut blind_le = [0u8; 32];
        blind_le[0] = 1;
        let blinding = Field::try_from_le_bytes(blind_le)?;

        let encrypted = encrypt_output_note(&recip_keys.public, amount, &blinding)?;
        let got = decrypt_output_note(&recip_keys.private, &encrypted)?
            .expect("should decrypt for recipient key");

        assert_eq!(got.0, amount);
        assert_eq!(got.1.to_le_bytes(), blinding.to_le_bytes());
        Ok(())
    }
}
