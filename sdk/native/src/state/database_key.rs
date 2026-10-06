//! Keys for Turso native page encryption. Wallet wrapping is a separate layer.
use anyhow::Result;
use zeroize::{Zeroize, Zeroizing};

pub struct DatabaseKey(Zeroizing<[u8; 32]>);
impl DatabaseKey {
    /// Take ownership of a database key, zeroizing this owned copy on drop.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Generate a fresh database key using the platform cryptographic RNG.
    /// Persist a recoverable wrapped copy before using it to create a database.
    pub fn generate() -> Result<Self> {
        let mut key = Self::new([0; 32]);
        getrandom::getrandom(&mut key[..])
            .map_err(|_| anyhow::anyhow!("database key generation failed"))?;
        Ok(key)
    }
}
impl std::fmt::Debug for DatabaseKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DatabaseKey([REDACTED])")
    }
}
impl std::ops::Deref for DatabaseKey {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for DatabaseKey {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl AsRef<[u8]> for DatabaseKey {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenPurpose {
    /// Create a database; native zero-byte reservations may be retried.
    CreateNew,
    /// Authenticate an existing, nonempty database without creating a file.
    OpenExisting,
}

#[async_trait::async_trait(?Send)]
pub trait DatabaseKeyProvider {
    /// Return the same recoverable key for subsequent opens of this database.
    /// Wrapping and unlocking belong to the provider; Turso only receives the
    /// random database key.
    async fn acquire(&self, database_id: &str, purpose: OpenPurpose) -> Result<DatabaseKey>;
}

/// Clear a transport buffer owned by this layer.
pub fn clear_transport(bytes: &mut [u8]) {
    bytes.zeroize();
}

/// The pinned Turso Rust API accepts encryption separately from the filename.
/// See Turso v0.8.1 tests/integration_tests.rs::test_encryption and manual.md.
pub fn encrypted_builder(path: &str, key: &DatabaseKey) -> turso::Builder {
    turso::Builder::new_local(path)
        .experimental_encryption(true)
        .with_encryption(turso::EncryptionOpts {
            cipher: "aes256gcm".into(),
            hexkey: hex::encode(key.as_ref()),
        })
}
