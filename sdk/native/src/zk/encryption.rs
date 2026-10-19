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
//!        └── signMessage("Privacy Pool Key Derivation [v2] (<kdf_domain>)")
//!                   │
//!                   ├── SHA-256("privacy-pool/note-key/v2" || <sig>)
//!                   │          └── BN254 Note Private Key → Poseidon2 → Note Public Key
//!                   │
//!                   └── SHA-256("privacy-pool/encryption-key/v3" || <sig>)
//!                              └── X-Wing (X25519 + ML-KEM-768) HPKE Keypair
//! ```
//! Notes are encrypted with HPKE (RFC 9180, base mode) using the hybrid X-Wing
//! KEM, HKDF-SHA256 and ChaCha20-Poly1305, so a recipient's long-lived
//! on-chain key stays safe against harvest-now-decrypt-later attacks by a
//! quantum adversary as long as either X25519 or ML-KEM-768 holds.
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
use ed25519_dalek::{Signature as DalekSignature, VerifyingKey};
use hpke::{
    Deserializable, OpModeR, OpModeS, Serializable,
    aead::ChaCha20Poly1305,
    kdf::HkdfSha256,
    kem::{Kem as _, XWing},
    single_shot_open, single_shot_seal_with_rng,
};
use rand_core::{TryCryptoRng, TryRng};
use sha2::{Digest, Sha256};
use std::convert::Infallible;
use zeroize::{Zeroize, Zeroizing};

// Key derivation constants.
// These MUST remain constant for backwards compatibility.

/// Message signed to derive both privacy keypairs.
///
/// `kdf_domain` is trimmed, so stray whitespace does not derive other keys.
pub fn key_derivation_message(kdf_domain: &str) -> String {
    format!("Privacy Pool Key Derivation [v2] ({})", kdf_domain.trim())
}

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

const NOTE_KEY_DOMAIN: &[u8] = b"privacy-pool/note-key/v2";

const ENCRYPTION_KEY_DOMAIN: &[u8] = b"privacy-pool/encryption-key/v2";

/// HPKE `info` binding every note ciphertext to this scheme and version.
const NOTE_HPKE_INFO: &[u8] = b"privacy-pool/note-encryption/v2";

/// Length of the HPKE encapsulated key (X-Wing ciphertext) prefixing each
/// encrypted output.
const ENCAPPED_KEY_LEN: usize = 1120;

/// Plaintext length: `amount (16) || blinding (32)`.
const NOTE_PLAINTEXT_LEN: usize = 48;

/// ChaCha20-Poly1305 authentication tag length.
const AEAD_TAG_LEN: usize = 16;

/// Exact length of an encrypted note output:
/// `encapsulated key (1120) || ciphertext (48) || tag (16)`.
pub const ENCRYPTED_OUTPUT_LEN: usize = ENCAPPED_KEY_LEN + NOTE_PLAINTEXT_LEN + AEAD_TAG_LEN;
const MEMBERSHIP_BLINDING_DOMAIN: &[u8] = b"privacy-pool/asp-secret/v2";

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
    let mut field = Fr::from_le_bytes_mod_order(&key[..]);

    let mut result = Zeroizing::new([0u8; 32]);
    field
        .serialize_compressed(&mut result[..])
        .expect("Serialization failed");
    field.zeroize();
    Field::try_from_le_bytes(*result)
}

/// Encryption key derivation (X-Wing). Used for off-chain note
/// encryption/decryption. Derives the X-Wing (X25519 + ML-KEM-768) HPKE keypair
/// deterministically from a Freighter signature.
///
/// This keypair is used for encrypting note data (amount, blinding) so that
/// only the recipient can decrypt it. The encryption scheme is HPKE base mode
/// with X-Wing, HKDF-SHA256 and ChaCha20-Poly1305.
///
/// # Derivation
/// ```text
/// signature (64 bytes) → SHA-256 → 32-byte ikm → HPKE DeriveKeyPair (X-Wing)
/// ```
/// The private key is the 32-byte X-Wing decapsulation key (a seed that
/// expands to both the ML-KEM-768 and X25519 keys). The public key is the
/// 1216-byte X-Wing encapsulation key.
///
/// # Arguments
/// * `signature` - Stellar Ed25519 signature from signing
///   [`key_derivation_message`]
fn derive_keypair_from_signature(signature: &KeyDerivationSignature) -> Result<EncryptionKeyPair> {
    let KeyDerivationSignature(signature) = signature;
    if signature.len() != 64 {
        return Err(anyhow!("Signature must be 64 bytes (Ed25519)"));
    }

    let ikm = hash_signature_with_domain(signature, ENCRYPTION_KEY_DOMAIN);
    // private has zeroize on drop for its internal type
    let (private, public) = XWing::derive_keypair(&ikm[..]);

    let mut private_bytes = Zeroizing::new([0u8; 32]);
    private_bytes.copy_from_slice(&private.to_bytes());
    let public_bytes = public.to_bytes().to_vec();

    Ok(EncryptionKeyPair {
        private: EncryptionPrivateKey(*private_bytes),
        public: EncryptionPublicKey::try_from(public_bytes)?,
    })
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
///   [`key_derivation_message`]
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
    let mut field = Fr::from_le_bytes_mod_order(&key[..]);

    // Serialize into bytes
    let mut result = Zeroizing::new([0u8; 32]);
    field
        .serialize_compressed(&mut result[..])
        .expect("Serialization failed");
    field.zeroize();

    Ok(NotePrivateKey(*result))
}

/// Derived key material, wiped on drop.
fn hash_signature_with_domain(signature: &[u8], domain: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(signature);
    Zeroizing::new(hasher.finalize().into())
}

fn hash_signature_with_domain_and_context(
    signature: &[u8],
    domain: &[u8],
    context: &[u8],
) -> Zeroizing<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0u8]);
    hasher.update(context);
    hasher.update([0u8]);
    hasher.update(signature);
    Zeroizing::new(hasher.finalize().into())
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

/// Randomness for one HPKE encapsulation, drawn from `getrandom` up front.
///
/// `hpke` wants an infallible `CryptoRng`, while `getrandom` can fail. Filling
/// a small buffer first keeps failures an ordinary `Err` instead of a panic,
/// and makes native and wasm builds use the same `getrandom` backend as the
/// rest of this module. X-Wing base-mode encapsulation consumes 64 bytes.
struct PrefilledRng {
    buf: [u8; Self::LEN],
    pos: usize,
}

impl PrefilledRng {
    const LEN: usize = 128;

    fn new() -> Result<Self> {
        let mut buf = [0u8; Self::LEN];
        getrandom::getrandom(&mut buf)
            .map_err(|e| anyhow!("Failed to generate encapsulation randomness: {}", e))?;
        Ok(Self { buf, pos: 0 })
    }
}

impl Drop for PrefilledRng {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

impl TryRng for PrefilledRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        let end = self
            .pos
            .checked_add(dst.len())
            .filter(|end| *end <= Self::LEN)
            .expect("HPKE encapsulation drew more randomness than prefilled");
        dst.copy_from_slice(&self.buf[self.pos..end]);
        self.pos = end;
        Ok(())
    }
}

impl TryCryptoRng for PrefilledRng {}

/// Encrypt note data with HPKE (RFC 9180, base mode) to a recipient's X-Wing
/// (X25519 + ML-KEM-768) public key.
///
/// When sending a note to someone, we encrypt the sensitive data (amount and
/// blinding) with their static on-chain public key. Only they can decrypt it.
///
/// Suite: KEM = X-Wing, KDF = HKDF-SHA256, AEAD = ChaCha20-Poly1305. The AEAD
/// key and nonce come from the HPKE key schedule, so no nonce is transmitted.
/// There is no `aad`: the note is bound to its commitment by the recipient
/// re-computing the commitment from the decrypted amount and blinding.
///
/// # Output Format
/// ```text
/// [encapsulated_key (1120)] [ciphertext (48) + tag (16)]
/// Total: 1184 bytes
/// ```
///
/// # Arguments
/// * `recipient_pubkey_bytes` - Recipient's X-Wing encryption public key (1216
///   bytes)
/// * `plaintext` - Note data: `[amount (16 bytes LE)] [blinding (32 bytes)]` =
///   48 bytes
///
/// # Returns
/// Encrypted data ([`ENCRYPTED_OUTPUT_LEN`] bytes)
fn encrypt_note_data(recipient_pubkey_bytes: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if recipient_pubkey_bytes.len() != EncryptionPublicKey::LEN {
        return Err(anyhow!(
            "Recipient public key must be {} bytes",
            EncryptionPublicKey::LEN
        ));
    }
    if plaintext.len() != NOTE_PLAINTEXT_LEN {
        return Err(anyhow!(
            "Plaintext must be 48 bytes (16 amount + 32 blinding)"
        ));
    }

    let recipient_public = <XWing as hpke::kem::Kem>::PublicKey::from_bytes(recipient_pubkey_bytes)
        .map_err(|e| anyhow!("Invalid recipient public key: {e}"))?;

    let mut rng = PrefilledRng::new()?;
    let (encapped_key, ciphertext) =
        single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, XWing>(
            &OpModeS::Base,
            &recipient_public,
            NOTE_HPKE_INFO,
            plaintext,
            &[],
            &mut rng,
        )
        .map_err(|e| anyhow!("Encryption failed: {e}"))?;

    let mut result = Vec::with_capacity(ENCRYPTED_OUTPUT_LEN);
    result.extend_from_slice(&encapped_key.to_bytes());
    result.extend_from_slice(&ciphertext);
    if result.len() != ENCRYPTED_OUTPUT_LEN {
        return Err(anyhow!(
            "Encrypted output must be {} bytes, got {}",
            ENCRYPTED_OUTPUT_LEN,
            result.len()
        ));
    }

    Ok(result)
}

/// Decrypt note data with HPKE (RFC 9180, base mode) and the X-Wing private
/// key.
///
/// When scanning for notes addressed to us, we try to decrypt each encrypted
/// output. If decryption succeeds, the note was sent to us.
///
/// # Arguments
/// * `private_key_bytes` - Our X-Wing encryption private key (32 bytes)
/// * `encrypted_data` - Encrypted data from on-chain event (exactly
///   [`ENCRYPTED_OUTPUT_LEN`] bytes)
///
/// # Returns
/// - Success: `[amount (16 bytes LE)] [blinding (32 bytes)]` = 48 bytes
/// - Failure: Empty vec (note was not addressed to us)
fn decrypt_note_data(private_key_bytes: &[u8], encrypted_data: &[u8]) -> Result<Vec<u8>> {
    if private_key_bytes.len() != 32 {
        return Err(anyhow!("Private key must be 32 bytes"));
    }

    if encrypted_data.len() != ENCRYPTED_OUTPUT_LEN {
        return Err(anyhow!(
            "Encrypted data must be {} bytes, got {}",
            ENCRYPTED_OUTPUT_LEN,
            encrypted_data.len()
        ));
    }

    let (encapped_key_bytes, ciphertext_with_tag) = encrypted_data.split_at(ENCAPPED_KEY_LEN);

    let our_secret = <XWing as hpke::kem::Kem>::PrivateKey::from_bytes(private_key_bytes)
        .map_err(|e| anyhow!("Invalid private key: {e}"))?;
    let encapped_key = <XWing as hpke::kem::Kem>::EncappedKey::from_bytes(encapped_key_bytes)
        .map_err(|e| anyhow!("Invalid encapsulated key: {e}"))?;

    match single_shot_open::<ChaCha20Poly1305, HkdfSha256, XWing>(
        &OpModeR::Base,
        &our_secret,
        &encapped_key,
        NOTE_HPKE_INFO,
        ciphertext_with_tag,
        &[],
    ) {
        Ok(plaintext) => Ok(plaintext),
        // Decryption failed - this note output is not for us
        Err(_) => Ok(Vec::new()),
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

    fn message() -> String {
        key_derivation_message("tests")
    }

    #[test]
    fn key_derivation_message_is_fixed() {
        assert_eq!(
            key_derivation_message("tests"),
            "Privacy Pool Key Derivation [v2] (tests)"
        );
    }

    #[test]
    fn key_derivation_message_trims_domain() {
        assert_eq!(
            key_derivation_message(" tests\n"),
            key_derivation_message("tests")
        );
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
        let signature = sign(&owner, &message());
        verify_owner_signature(&address, &message(), &signature)
            .expect("the owner signing for itself must verify");
    }

    /// The case the check exists for: a wallet that signed with another
    /// account. Its keys would otherwise be filed under the owner.
    #[test]
    fn a_signature_by_another_account_is_refused() {
        let (_, owner_address) = account(1);
        let (other, _) = account(2);
        let signature = sign(&other, &message());
        assert!(verify_owner_signature(&owner_address, &message(), &signature).is_err());
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
        assert!(verify_owner_signature(&owner_address, &message(), &signature).is_err());
    }

    #[test]
    fn a_signature_of_the_wrong_length_is_refused() {
        let (owner, address) = account(1);
        let mut signature = sign(&owner, &message());
        signature.0.pop();
        assert!(verify_owner_signature(&address, &message(), &signature).is_err());
    }

    #[test]
    fn an_owner_that_is_not_an_account_address_is_refused() {
        let (owner, _) = account(1);
        let signature = sign(&owner, &message());
        assert!(verify_owner_signature("not-an-address", &message(), &signature).is_err());
    }

    #[test]
    fn a_signature_over_another_message_is_refused() {
        let (owner, address) = account(1);
        let signature = sign(&owner, "some other message");
        assert!(verify_owner_signature(&address, &message(), &signature).is_err());
    }

    /// The error reaches a UI toast, where wallet cancellations are recognised
    /// by substring. A signature from the wrong key is not a cancellation.
    #[test]
    fn the_refusal_does_not_read_as_a_wallet_cancellation() {
        let (_, owner_address) = account(1);
        let (other, _) = account(2);
        let rendered =
            verify_owner_signature(&owner_address, &message(), &sign(&other, &message()))
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
        assert_eq!(keys1.public.0.len(), EncryptionPublicKey::LEN);
    }

    /// Regression pin (not an independent vector) of the wallet-signature to
    /// X-Wing keypair derivation. A change here
    /// silently orphans every note encrypted to existing registry keys, so it
    /// must be a deliberate, versioned change (see `ENCRYPTION_KEY_DOMAIN`).
    #[test]
    fn test_derive_keypair_known_answer() {
        let signature = KeyDerivationSignature(vec![1u8; 64]);
        let keys = derive_keypair_from_signature(&signature).expect("Derivation failed");
        assert_eq!(
            hex::encode(Sha256::digest(keys.private.0)),
            "979232fcab86fa0bb1a5015669cbec3bf1317bd7b002c6b158c0b6e1932016dd"
        );
        assert_eq!(
            hex::encode(Sha256::digest(keys.public.0)),
            "26fedd66dc925ed8a979350c9d2e978e8c0a03ff41405b6d84bb1a12f20230e2"
        );
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
        let mut plaintext = Vec::with_capacity(NOTE_PLAINTEXT_LEN);
        plaintext.extend_from_slice(&amount);
        plaintext.extend_from_slice(&blinding);

        let encrypted = encrypt_note_data(pub_key, &plaintext).expect("Encryption failed");
        assert_eq!(encrypted.len(), ENCRYPTED_OUTPUT_LEN);
        assert_eq!(ENCRYPTED_OUTPUT_LEN, 1184);

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

        // Invalid pubkey length, including a legacy 32-byte X25519 key
        let res = encrypt_note_data(&[0u8; 31], &[0u8; 48]);
        assert!(res.is_err());
        let res = encrypt_note_data(&[0u8; 32], &[0u8; 48]);
        assert!(res.is_err());
    }

    #[test]
    fn test_decrypt_rejects_wrong_ciphertext_length() {
        let keys = derive_keypair_from_signature(&KeyDerivationSignature(vec![5u8; 64]))
            .expect("Derivation failed");
        // The legacy 120-byte X25519 layout and truncated or padded outputs.
        for len in [0, 120, ENCRYPTED_OUTPUT_LEN - 1, ENCRYPTED_OUTPUT_LEN + 1] {
            let res = decrypt_note_data(keys.private.as_ref(), &vec![0u8; len]);
            assert!(res.is_err(), "length {len} must be rejected");
        }
        assert!(decrypt_note_data(&[0u8; 31], &[0u8; ENCRYPTED_OUTPUT_LEN]).is_err());
    }

    #[test]
    fn test_tampered_ciphertext_is_not_decrypted() {
        let keys = derive_keypair_from_signature(&KeyDerivationSignature(vec![6u8; 64]))
            .expect("Derivation failed");
        let plaintext = [7u8; NOTE_PLAINTEXT_LEN];
        let encrypted = encrypt_note_data(keys.public.as_ref(), &plaintext).expect("encrypt");

        // One flipped bit in the encapsulated key, the AEAD ciphertext and the
        // tag must each yield "not for us" rather than altered plaintext.
        for idx in [
            0,
            ENCAPPED_KEY_LEN - 1,
            ENCAPPED_KEY_LEN,
            ENCRYPTED_OUTPUT_LEN - 1,
        ] {
            let mut tampered = encrypted.clone();
            tampered[idx] ^= 1;
            let out = decrypt_note_data(keys.private.as_ref(), &tampered).expect("no hard error");
            assert!(out.is_empty(), "tampering at byte {idx} must not decrypt");
        }
    }

    #[test]
    fn test_encryption_is_randomized() {
        let keys = derive_keypair_from_signature(&KeyDerivationSignature(vec![6u8; 64]))
            .expect("Derivation failed");
        let plaintext = [7u8; NOTE_PLAINTEXT_LEN];
        let a = encrypt_note_data(keys.public.as_ref(), &plaintext).expect("encrypt");
        let b = encrypt_note_data(keys.public.as_ref(), &plaintext).expect("encrypt");
        assert_ne!(a, b);
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
