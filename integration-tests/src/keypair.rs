//! Ephemeral Stellar keypairs for use against a local network.

use ed25519_dalek::{Signer as _, SigningKey};
use stellar_strkey::{Unredacted, ed25519};

/// Generated in-process and funded via friendbot; not persisted anywhere.
pub struct TestKeypair {
    signing_key: SigningKey,
}

impl TestKeypair {
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut rand::thread_rng()),
        }
    }

    /// `G...` public address.
    pub fn address(&self) -> String {
        format!(
            "{}",
            ed25519::PublicKey(self.signing_key.verifying_key().to_bytes())
        )
    }

    /// `S...` secret seed.
    pub fn secret(&self) -> String {
        format!(
            "{}",
            Unredacted(&ed25519::PrivateKey(self.signing_key.to_bytes()))
        )
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }
}
