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
//! Varial Wallet (Ed25519)
//!        │
//!        └── signMessage("Privacy Pool Key Derivation [v1] (<kdf_domain>)
//!                         WARNING: signing this gives full control of …")
//!                   │
//!                   ├── SHA-256("privacy-pool/note-key/v1" || <sig>)
//!                   │          └── BN254 Note Private Key → Poseidon2 → Note Public Key
//!                   │
//!                   └── SHA-256("privacy-pool/encryption-key/v1" || <sig>)
//!                              └── X-Wing (X25519 + ML-KEM-768) Encryption Keypair
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
use ed25519_dalek::{Signature as DalekSignature, VerifyingKey};
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable, aead::ChaCha20Poly1305,
    kdf::HkdfSha256, kem::XWing,
};
use sha2::{
    Digest, Sha256,
    digest::{Output, array::Array},
};
use zeroize::Zeroizing;

// Key derivation constants.
// These MUST remain constant for backwards compatibility.

/// Message signed to derive both privacy keypairs.
///
/// The signature is the user's whole privacy secret, and the keys derived from
/// it can't be rotated, so the second line warns the user to sign it only in
/// the app or CLI.
///
/// `kdf_domain` is trimmed, so stray whitespace does not derive other keys.
pub fn key_derivation_message(kdf_domain: &str) -> String {
    format!(
        "Privacy Pool Key Derivation [v1] ({})\n{KEY_DERIVATION_WARNING}",
        kdf_domain.trim()
    )
}

/// Second line of [`key_derivation_message`].
const KEY_DERIVATION_WARNING: &str = "WARNING: signing this gives full control of your private \
                                      funds. Only sign in the Stellar Private Payments app or CLI.";

/// Prefix a SEP-53 wallet puts in front of a message before hashing it.
const SEP53_MESSAGE_PREFIX: &str = "Stellar Signed Message:\n";

/// The bytes a SEP-53 wallet hashes with SHA-256 and signs for `message`.
pub fn sep53_payload(message: &str) -> Vec<u8> {
    [SEP53_MESSAGE_PREFIX.as_bytes(), message.as_bytes()].concat()
}

/// The SHA-256 of [`sep53_payload`], which a SEP-53 wallet signs.
pub fn sep53_digest(message: &str) -> [u8; 32] {
    Sha256::digest(sep53_payload(message)).into()
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
        .map_err(|_| anyhow!("signature must be 64 bytes"))?;
    let owner = stellar_strkey::ed25519::PublicKey::from_string(owner_address)
        .map_err(|_| anyhow!("note owner is not an account (G...) address"))?;
    let owner_key = VerifyingKey::from_bytes(&owner.0)
        .map_err(|e| anyhow!("note owner key is not a valid Ed25519 key: {e}"))?;

    // Strict, as the network itself verifies: a small-order owner key or `R`
    // is refused, where the lenient check accepts forgeries for such a key.
    owner_key
        .verify_strict(
            &sep53_digest(message),
            &DalekSignature::from_bytes(signature),
        )
        .map_err(|_| anyhow!("the signature was not made by the note owner's key"))
}

const NOTE_KEY_DOMAIN: &[u8] = b"privacy-pool/note-key/v1";
const ENCRYPTION_KEY_DOMAIN: &[u8] = b"privacy-pool/encryption-key/v1";

/// HPKE `info` of a note ciphertext.
const NOTE_ENCRYPTION_INFO: &[u8] = b"privacy-pool/note/v1";
/// Length of the KEM output (`enc`) of X-Wing.
const XWING_ENC_LEN: usize = 1120;
/// Length of an encrypted note: `enc (1120) || ciphertext (48) || tag (16)`.
pub const ENCRYPTED_OUTPUT_LEN: usize = XWING_ENC_LEN + 48 + 16;
const MEMBERSHIP_BLINDING_DOMAIN: &[u8] = b"privacy-pool/asp-secret/v1";

/// Caveat for everything that derives or handles the privacy keys.
pub const MEMORY_PROTECTION_WARNING: &str = "Privacy keys are derived from a wallet signature and \
protected only on a best-effort basis by zeroizing memory after use. Protection against \
side-channel or timing attacks, a weak system random number generator, or other memory \
disclosure cannot be guaranteed.";

/// Keypairs derivation.
///
/// # Security
/// Secret material is wiped from memory on a best-effort basis only (see
/// [`MEMORY_PROTECTION_WARNING`]).
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
    let field = Fr::from_le_bytes_mod_order(&*key);

    let mut result = [0u8; 32];
    field
        .serialize_compressed(&mut result[..])
        .expect("Serialization failed");
    Field::try_from_le_bytes(result)
}

/// Encryption key derivation (X-Wing). Used for off-chain note
/// encryption/decryption. Derives the keypair deterministically from the wallet
/// signature.
///
/// The keypair encrypts note data (amount, blinding) so that only the
/// recipient can decrypt it. X-Wing combines X25519 and ML-KEM-768, so notes
/// stay confidential against harvest-now-decrypt-later if either holds.
///
/// # Derivation
/// ```text
/// signature (64 bytes) → SHA-256 → 32-byte IKM → HPKE DeriveKeyPair → X-Wing keypair
/// ```
///
/// # Arguments
/// * `signature` - Stellar Ed25519 signature from signing
///   [`key_derivation_message`]
///
/// # Returns
/// The 32-byte X-Wing secret key and the 1216-byte public key.
fn derive_keypair_from_signature(signature: &KeyDerivationSignature) -> Result<EncryptionKeyPair> {
    let KeyDerivationSignature(signature) = signature;
    if signature.len() != 64 {
        return Err(anyhow!("Signature must be 64 bytes (Ed25519)"));
    }

    // HPKE `DeriveKeyPair(ikm)`: the SHA-256 output carries 256 bits of
    // entropy, as many as the 32-byte secret key, as RFC 9180 asks of `ikm`.
    let ikm = hash_signature_with_domain(signature, ENCRYPTION_KEY_DOMAIN);
    let (secret, public) = XWing::derive_keypair(&*ikm);

    // The private key is the derived secret key, so scanning does not derive it
    // again for every output it tries.
    // Written straight into the key's own storage: no intermediate array is
    // made, so there is no extra copy to wipe.
    let mut private = EncryptionPrivateKey([0u8; 32]);
    secret.write_exact(&mut private.0);
    Ok(EncryptionKeyPair {
        private,
        public: EncryptionPublicKey::try_from(public.to_bytes().to_vec())?,
    })
}

/// Derive private key (BN254 scalar) deterministically from a Varial
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
    let field = Fr::from_le_bytes_mod_order(&key[..]);

    // Serialize into bytes
    // Serialized in place into the key's own storage, for the same reason.
    let mut private = NotePrivateKey([0u8; 32]);
    field
        .serialize_compressed(&mut private.0[..])
        .expect("Serialization failed");
    Ok(private)
}

/// Finishes `hasher` straight into a buffer that is wiped on drop. `finalize()`
/// would return the digest by value, leaving an unwiped temporary behind.
fn finalize_wiped(hasher: Sha256) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    let view: &mut Output<Sha256> = Array::cast_from_core_mut(&mut out);
    hasher.finalize_into(view);
    out
}

/// The hash is secret key material, so it is wiped on drop.
fn hash_signature_with_domain(signature: &[u8], domain: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(signature);
    finalize_wiped(hasher)
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
    finalize_wiped(hasher)
}

/// Message the owner signs (SEP-53) to register keys with `registry`.
///
/// Byte-identical to the registry's `registration_message`.
pub fn registration_message(
    registry: &str,
    owner: &str,
    note_key: &NotePublicKey,
    encryption_key: &EncryptionPublicKey,
) -> String {
    format!(
        "Privacy Pool Key Registration [v1]\nRegistry: {registry}\nAccount: {owner}\nNote key: \
         0x{}\nEncryption key: 0x{}",
        hex::encode(note_key.0),
        hex::encode(&encryption_key.0),
    )
}

/// SEP-53 digest `D` of a registration message, which the owner signature and
/// the `keyOwnership` proof both cover.
pub fn registration_digest(message: &str) -> [u8; 32] {
    sep53_digest(message)
}

/// The `keyOwnership` circuit's `registrationHash`: `D` read big-endian and
/// reduced mod r, as the registry does.
pub fn registration_hash(digest: &[u8; 32]) -> Field {
    let mut le = *digest;
    le.reverse();
    Field::from_le_bytes_mod_order(le)
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
    encrypt_note_data(recipient_pubkey, &plaintext)
}

/// Decrypt output note data from on-chain storage.
///
/// Returns `Ok(None)` if the ciphertext is not addressed to the given private
/// key or does not hold a well-formed note. The output is chosen by whoever
/// submits the transaction, so malformed contents must not fail the scan.
///
/// Expected plaintext format: `amount (16 bytes LE) || blinding (32 bytes LE)`.
pub fn decrypt_output_note(
    recipient_privkey: &EncryptionPrivateKey,
    encrypted_output: &[u8],
) -> Result<Option<(NoteAmount, Field)>> {
    let Some(plaintext) = decrypt_note_data(recipient_privkey.as_ref(), encrypted_output)? else {
        return Ok(None);
    };
    if plaintext.len() != 48 {
        return Ok(None);
    }

    let mut amount_le = [0u8; 16];
    amount_le.copy_from_slice(&plaintext[..16]);
    let amount = NoteAmount::from(u128::from_le_bytes(amount_le));

    let mut blinding_le = [0u8; 32];
    blinding_le.copy_from_slice(&plaintext[16..]);
    let Ok(blinding) = Field::try_from_le_bytes(blinding_le) else {
        return Ok(None);
    };

    Ok(Some((amount, blinding)))
}

/// Randomness for HPKE from the platform source (`getrandom` works on native
/// and in the browser).
struct SysRng;

impl hpke::rand_core::TryRng for SysRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        // Like the rest of the stack, a failing system RNG is unrecoverable.
        getrandom::getrandom(dest).expect("system randomness unavailable");
        Ok(())
    }
}

impl hpke::rand_core::TryCryptoRng for SysRng {}

/// Encrypt note data with HPKE (base mode): X-Wing (X25519 + ML-KEM-768),
/// HKDF-SHA256, ChaCha20-Poly1305.
///
/// When sending a note to someone, we encrypt the sensitive data (amount and
/// blinding) with their X-Wing public key. Only they can decrypt it.
///
/// # Output Format
/// ```text
/// [enc (1120)] [ciphertext (48) + tag (16)]
/// Total: 1184 bytes
/// ```
///
/// # Arguments
/// * `recipient_pubkey_bytes` - Recipient's X-Wing public key (1216 bytes)
/// * `plaintext` - Note data: `[amount (16 bytes LE)] [blinding (32 bytes)]` =
///   48 bytes
fn encrypt_note_data(recipient_pubkey: &EncryptionPublicKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    let recipient_pubkey_bytes = recipient_pubkey.as_ref();
    if recipient_pubkey_bytes.len() != EncryptionPublicKey::LEN {
        return Err(anyhow!(
            "Recipient public key must be {} bytes",
            EncryptionPublicKey::LEN
        ));
    }
    if plaintext.len() != 48 {
        return Err(anyhow!(
            "Plaintext must be 48 bytes (16 amount + 32 blinding)"
        ));
    }

    let recipient = <XWing as KemTrait>::PublicKey::from_bytes(recipient_pubkey_bytes)
        .map_err(|e| anyhow!("Invalid recipient public key: {e}"))?;
    let (enc, ciphertext) = hpke::single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, XWing>(
        &OpModeS::Base,
        &recipient,
        NOTE_ENCRYPTION_INFO,
        plaintext,
        &[],
        &mut SysRng,
    )
    .map_err(|e| anyhow!("Encryption failed: {e}"))?;

    let mut result = enc.to_bytes().to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt note data sealed by [`encrypt_note_data`].
///
/// When scanning for notes addressed to us, we try to decrypt each encrypted
/// output. If decryption succeeds, the note was sent to us.
///
/// # Arguments
/// * `private_key_bytes` - Our X-Wing secret key (32 bytes)
/// * `encrypted_data` - Encrypted data from on-chain event (1184 bytes)
///
/// # Returns
/// - Success: the decrypted plaintext
/// - `None`: the data has the wrong length or was not addressed to us
fn decrypt_note_data(private_key_bytes: &[u8], encrypted_data: &[u8]) -> Result<Option<Vec<u8>>> {
    // Reject by shape first: building the X-Wing key expands the seed (SHAKE,
    // ML-KEM keygen, X25519), which is far too costly to spend on an output
    // that cannot be ours. A bad key length is reported only for outputs of
    // the right length; the key comes from the account, not from the chain.
    if encrypted_data.len() != ENCRYPTED_OUTPUT_LEN {
        return Ok(None);
    }
    let (enc, ciphertext) = encrypted_data.split_at(XWING_ENC_LEN);
    let Ok(enc) = <XWing as KemTrait>::EncappedKey::from_bytes(enc) else {
        return Ok(None);
    };

    let secret = <XWing as KemTrait>::PrivateKey::from_bytes(private_key_bytes)
        .map_err(|_| anyhow!("Private key must be 32 bytes"))?;

    Ok(
        hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, XWing>(
            &OpModeR::Base,
            &secret,
            &enc,
            NOTE_ENCRYPTION_INFO,
            ciphertext,
            &[],
        )
        .ok(),
    )
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
            "Privacy Pool Key Derivation [v1] (tests)\nWARNING: signing this gives full control \
             of your private funds. Only sign in the Stellar Private Payments app or CLI."
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
        KeyDerivationSignature(key.sign(&sep53_digest(message)).to_bytes().to_vec())
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
        let pub_key = &recip_keys.public;
        let priv_key = recip_keys.private.as_ref();

        // 16 bytes amount + 32 bytes blinding = 48 bytes
        let amount = [10u8; 16];
        let blinding = [20u8; 32];
        let mut plaintext = Vec::with_capacity(40);
        plaintext.extend_from_slice(&amount);
        plaintext.extend_from_slice(&blinding);

        let encrypted = encrypt_note_data(pub_key, &plaintext).expect("Encryption failed");
        assert_eq!(encrypted.len(), ENCRYPTED_OUTPUT_LEN);

        let decrypted = decrypt_note_data(priv_key, &encrypted)
            .expect("Decryption failed")
            .expect("note should be addressed to the recipient");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_failure_wrong_key() {
        let alice_sig = KeyDerivationSignature(vec![3u8; 64]);
        let bob_sig = KeyDerivationSignature(vec![4u8; 64]);

        let alice_keys = derive_keypair_from_signature(&alice_sig).expect("Derivation failed");
        let bob_keys = derive_keypair_from_signature(&bob_sig).expect("Derivation failed");

        // Encrypt for Alice.
        let alice_pub = &alice_keys.public;
        let plaintext = [0u8; 48];
        let encrypted = encrypt_note_data(alice_pub, &plaintext).expect("Encryption failed");

        // Bob tries to decrypt.
        let bob_priv = bob_keys.private.as_ref();
        let decrypted = decrypt_note_data(bob_priv, &encrypted)
            .expect("Decryption should handle failure gracefully");

        assert!(decrypted.is_none());
    }

    #[test]
    fn test_invalid_input_lengths() {
        let sig = KeyDerivationSignature(vec![5u8; 64]);
        let keys = derive_keypair_from_signature(&sig)
            .expect("Derivation failed in test_invalid_input_lengths");
        let pub_key = &keys.public;

        // Invalid plaintext length
        let res = encrypt_note_data(pub_key, &[0u8; 39]);
        assert!(res.is_err());

        // Invalid pubkey length
        let res = encrypt_note_data(
            &EncryptionPublicKey(vec![0u8; EncryptionPublicKey::LEN - 1].into_boxed_slice()),
            &[0u8; 48],
        );
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

    /// Seals an arbitrary plaintext with the note wire format, bypassing the
    /// 48-byte check of `encrypt_note_data`.
    fn seal_raw(recipient: &EncryptionPublicKey, plaintext: &[u8]) -> Vec<u8> {
        let recipient =
            <XWing as KemTrait>::PublicKey::from_bytes(&recipient.0).expect("valid public key");
        let (enc, ciphertext) =
            hpke::single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, XWing>(
                &OpModeS::Base,
                &recipient,
                NOTE_ENCRYPTION_INFO,
                plaintext,
                &[],
                &mut SysRng,
            )
            .expect("encryption failed");
        let mut out = enc.to_bytes().to_vec();
        out.extend_from_slice(&ciphertext);
        out
    }

    #[test]
    fn test_decrypt_output_note_ignores_malformed_outputs() -> Result<()> {
        let keys = derive_keypair_from_signature(&KeyDerivationSignature(vec![6u8; 64]))?;

        assert!(decrypt_output_note(&keys.private, &[]).is_ok_and(|n| n.is_none()));
        assert!(decrypt_output_note(&keys.private, &[1, 2, 3]).is_ok_and(|n| n.is_none()));

        let wrong_length = seal_raw(&keys.public, &[0u8; 49]);
        assert!(decrypt_output_note(&keys.private, &wrong_length).is_ok_and(|n| n.is_none()));

        let mut tampered = seal_raw(&keys.public, &[0u8; 48]);
        assert_eq!(tampered.len(), ENCRYPTED_OUTPUT_LEN);
        tampered[ENCRYPTED_OUTPUT_LEN - 1] ^= 1;
        assert!(decrypt_output_note(&keys.private, &tampered).is_ok_and(|n| n.is_none()));

        let mut non_canonical_blinding = [0xffu8; 48];
        non_canonical_blinding[..16].copy_from_slice(&5u128.to_le_bytes());
        let non_canonical = seal_raw(&keys.public, &non_canonical_blinding);
        assert!(decrypt_output_note(&keys.private, &non_canonical).is_ok_and(|n| n.is_none()));
        Ok(())
    }
}

/// The note encryption runs in the browser, so it is exercised under wasm too.
#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    fn note_roundtrip_with_derived_xwing_keys() {
        let keys = derive_keypair_from_signature(&KeyDerivationSignature(vec![5u8; 64]))
            .expect("derivation");
        let mut blinding = [0u8; 32];
        blinding[0] = 1;
        let blinding = Field::try_from_le_bytes(blinding).expect("field");

        let encrypted =
            encrypt_output_note(&keys.public, NoteAmount::from(42), &blinding).expect("encrypt");
        assert_eq!(encrypted.len(), ENCRYPTED_OUTPUT_LEN);

        let (amount, got) = decrypt_output_note(&keys.private, &encrypted)
            .expect("decrypt")
            .expect("addressed to the key");
        assert_eq!(amount, NoteAmount::from(42));
        assert_eq!(got.to_le_bytes(), blinding.to_le_bytes());
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod registration_tests {
    use super::*;
    use soroban_sdk::{
        Address, Bytes, BytesN, Env, crypto::bn254::Bn254Fr, testutils::Address as _,
    };

    const OWNER: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPP4V";

    fn strkey(address: &Address) -> String {
        let strkey = address.to_string();
        let mut bytes = vec![0u8; strkey.len() as usize];
        strkey.copy_into_slice(&mut bytes);
        String::from_utf8(bytes).expect("strkeys are ASCII")
    }

    /// Keys from the real derivation, for a few wallet signatures.
    fn derived_encryption_keys() -> Vec<EncryptionKeyPair> {
        (0u8..16)
            .map(|seed| {
                derive_keypair_from_signature(&KeyDerivationSignature(vec![seed; 64]))
                    .expect("64-byte signature")
            })
            .collect()
    }

    #[test]
    fn registration_message_and_hash_match_the_registry() {
        let env = Env::default();
        let registry = Address::generate(&env);
        let note_key = NotePublicKey([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ]);
        let encryption_key = derived_encryption_keys().remove(0).public;
        let account = public_key_registry::Account {
            owner: Address::from_str(&env, OWNER),
            encryption_key: Bytes::from_slice(&env, &encryption_key.0),
            note_key: Bytes::from_array(&env, &note_key.0),
        };

        let message = registration_message(&strkey(&registry), OWNER, &note_key, &encryption_key);
        let on_chain = public_key_registry::registration_message(&env, &registry, &account);
        assert_eq!(on_chain.to_alloc_vec(), message.as_bytes());

        let digest = registration_digest(&message);
        assert_eq!(
            public_key_registry::registration_digest(&env, &on_chain).to_array(),
            digest
        );
        assert_eq!(
            u32::try_from(encryption_key.0.len()).expect("fits"),
            public_key_registry::ENCRYPTION_KEY_LEN
        );

        // [0xff; 32] is above r, so it checks the reduction as well.
        for digest in [digest, [0xff; 32]] {
            let on_chain = Bn254Fr::from_bytes(BytesN::from_array(&env, &digest));
            assert_eq!(
                registration_hash(&digest).to_be_bytes(),
                on_chain.to_bytes().to_array()
            );
        }
    }
}

/// Known-answer tests. Everything here is derived from a fixed signature and
/// pinned, so a change in key derivation, X-Wing or the HPKE wire format (for
/// example from an `hpke` upgrade) fails here instead of making existing
/// accounts unable to recover their keys or read their notes.
///
/// Changing any value below means every user's keys or notes change. Do not
/// update a vector to make a test pass without a migration plan.
#[cfg(test)]
mod known_answer_tests {
    use super::*;

    #[test]
    fn wrong_length_outputs_are_skipped_before_the_key_is_built() {
        // A 31-byte key would be an error if it were parsed, so `Ok(None)`
        // shows the length was rejected first.
        let short_key = [0u8; 31];
        for len in [0, 1, ENCRYPTED_OUTPUT_LEN - 1, ENCRYPTED_OUTPUT_LEN + 1] {
            let out = decrypt_note_data(&short_key, &vec![7u8; len]).expect("no error");
            assert!(out.is_none(), "length {len}");
        }
        assert!(decrypt_note_data(&short_key, &vec![7u8; ENCRYPTED_OUTPUT_LEN]).is_err());
    }
    use std::vec;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test;

    /// Not a real signature: bytes `0..64`.
    fn signature() -> KeyDerivationSignature {
        KeyDerivationSignature((0u8..64).collect::<vec::Vec<u8>>())
    }

    const NOTE_PRIVATE_KEY: &str =
        "93cffddaf98d0ce3c510f565f085bcc61ec42855dd2defb559dbe466bc1af52f";
    const NOTE_PUBLIC_KEY: &str =
        "efbecb60293baa5cf5900a6ea8a72f03b77dfbbb2b12f3dbcaf38983dcca5223";
    const ENCRYPTION_PRIVATE_KEY: &str =
        "fcf5e5865468219941ccc3d53bc582ae19438f441fd1673bdc01f4e561b70ed2";
    /// First 32 bytes of the 1216-byte public key; the hash below covers all of
    /// it.
    const ENCRYPTION_PUBLIC_KEY_HEAD: &str =
        "2e0909419c9707d9269883a4222b433a8ca83c1c6e10981e4c75a2d8267a50d2";
    const ENCRYPTION_PUBLIC_KEY_SHA256: &str =
        "3d8177da5d142a790ac7ca4cf3643942039229cd44e03e603268c8a59f64c131";
    const MEMBERSHIP_BLINDING_TESTNET: &str =
        "6f376451fe6b541ef08331b62ca9d092d64fe71a9b9ad0785ff4cedad2a79820";
    /// A 1184-byte note ciphertext produced once for the keys above with
    /// amount 1234567 and blinding `[9; 32]`.
    const NOTE_CIPHERTEXT: &str = include_str!("testdata/note_ciphertext.hex");
    const NOTE_AMOUNT: u128 = 1_234_567;
    const NOTE_BLINDING: [u8; 32] = [9; 32];

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn keys_derived_from_a_fixed_signature_are_pinned() {
        let (note, enc) = derive_encryption_and_note_keypairs(signature()).expect("derivation");
        assert_eq!(hex::encode(note.private.0), NOTE_PRIVATE_KEY);
        assert_eq!(hex::encode(note.public.0), NOTE_PUBLIC_KEY);
        assert_eq!(hex::encode(enc.private.0), ENCRYPTION_PRIVATE_KEY);
        assert_eq!(enc.public.0.len(), EncryptionPublicKey::LEN);
        assert_eq!(hex::encode(&enc.public.0[..32]), ENCRYPTION_PUBLIC_KEY_HEAD);
        assert_eq!(
            hex::encode(Sha256::digest(&enc.public.0)),
            ENCRYPTION_PUBLIC_KEY_SHA256
        );
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn membership_blinding_from_a_fixed_signature_is_pinned() {
        let blinding = derive_membership_blinding(&signature(), "testnet").expect("derivation");
        assert_eq!(
            hex::encode(blinding.to_le_bytes()),
            MEMBERSHIP_BLINDING_TESTNET
        );
    }

    /// Decapsulation and decryption of a stored ciphertext must keep working:
    /// notes already on chain were encrypted by an earlier build.
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn a_pinned_ciphertext_still_decrypts() {
        let (_, enc) = derive_encryption_and_note_keypairs(signature()).expect("derivation");
        let ciphertext = hex::decode(NOTE_CIPHERTEXT.trim()).expect("hex");
        assert_eq!(ciphertext.len(), 1184);
        let (amount, blinding) = decrypt_output_note(&enc.private, &ciphertext)
            .expect("decrypt")
            .expect("note addressed to this key");
        assert_eq!(amount, NoteAmount::from(NOTE_AMOUNT));
        assert_eq!(
            blinding.to_le_bytes(),
            Field::try_from_le_bytes(NOTE_BLINDING)
                .expect("blinding")
                .to_le_bytes()
        );
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn a_pinned_ciphertext_is_not_readable_by_another_key() {
        let other = KeyDerivationSignature(vec![1u8; 64]);
        let (_, enc) = derive_encryption_and_note_keypairs(other).expect("derivation");
        let ciphertext = hex::decode(NOTE_CIPHERTEXT.trim()).expect("hex");
        assert!(
            decrypt_output_note(&enc.private, &ciphertext)
                .expect("decrypt")
                .is_none()
        );
    }

    /// Signature of the real `stellar message sign` vector in
    /// `signer::local` (a genuine 64-byte Ed25519 SEP-53 signature).
    const CLI_SIGNATURE_B64: &str =
        "sVN7t6f95HnWra/b23AqHVVhEXlS2wEBd2Sng7yqHjRKoieWbmbGNnFQST+L08ON4YrUYp9NMaJhdMT0w6jHDg==";

    /// Starts from a real wallet signature, so the derivation is pinned from
    /// what a signer actually returns, not from made-up bytes.
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn keys_derived_from_a_real_wallet_signature_are_pinned() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let bytes = STANDARD.decode(CLI_SIGNATURE_B64).expect("base64");
        let (note, enc) =
            derive_encryption_and_note_keypairs(KeyDerivationSignature(bytes)).expect("keys");
        assert_eq!(
            hex::encode(note.private.0),
            "427ef402c9f0a1acfce1a241ef21941fd06d5702c01cd91a77ba25b441bac029"
        );
        assert_eq!(
            hex::encode(note.public.0),
            "2c7cd526dbb6490b01ec386b8cf663737c6172b57413e7ee28c2e55128cafd23"
        );
        assert_eq!(
            hex::encode(enc.private.0),
            "21209c6ef67311ee14c73275a229848b682817e8929ec937f1f4b2ae416fe314"
        );
        assert_eq!(
            hex::encode(Sha256::digest(&enc.public.0)),
            "3ed452037a37054da3a15456cedea2a6ecf42a1fb78ba940098cbdefa943531f"
        );
    }

    /// Shared with `contracts/public-key-registry` (`registration_vector`),
    /// so the wallet and the registry cannot drift apart.
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn the_registration_digest_and_hash_are_pinned() {
        let message = registration_message(
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPP4V",
            &NotePublicKey([0x11; 32]),
            &EncryptionPublicKey::try_from(vec![0x22u8; EncryptionPublicKey::LEN]).expect("key"),
        );
        let digest = registration_digest(&message);
        assert_eq!(
            hex::encode(digest),
            "a39ca7d52271b2b022415282ca44544ffd86fea8c982bd3178c7415f0fb1631c"
        );
        assert_eq!(
            hex::encode(registration_hash(&digest).to_le_bytes()),
            "1963b13fa36021ad7d6b565ccf45eb84384bc0455f8150f932d2dc7e7cbc6f12"
        );
    }
}
