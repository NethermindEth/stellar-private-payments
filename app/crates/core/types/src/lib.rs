mod amounts;
mod chain_data;
mod ext_data;
pub use amounts::*;
use anyhow::{Result, anyhow};
pub use chain_data::*;
pub use ext_data::*;

use serde::{Deserialize, Serialize};

pub const SMT_DEPTH: u32 = 10;

// scripts/deployments.json
#[derive(Debug, Serialize, Deserialize)]
pub struct ContractConfig {
    pub network: String,
    pub deployer: String,
    pub admin: String,
    /// Ledger sequence at (or immediately before) contract deployment.
    ///
    /// Used as a stable cold-start anchor for fresh local DBs so the indexer
    /// can reconstruct the pool and ASP membership trees from events.
    pub deployment_ledger: u32,
    // Address of ASP membership deployed contract
    pub asp_membership: String,
    // Address of ASP nonmembership deployed contract
    pub asp_non_membership: String,
    pub verifier: String,
    // Address of Pool deployed contract
    pub pool: String,
    pub initialized: bool,
}

/// ASP membership proof data needed by the circuit.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AspMembershipProof {
    /// Membership leaf (BN254 scalar field element).
    pub leaf: Field,
    /// Membership blinding used when the leaf was added (BN254 scalar field
    /// element).
    pub blinding: Field,
    /// Membership Merkle path sibling hashes (BN254 scalar field elements).
    pub path_elements: Vec<Field>,
    /// Membership Merkle path indices packed into a field element.
    pub path_indices: Field,
    /// Membership tree root (BN254 scalar field element).
    pub root: Field,
}

/// User note (UTXO).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserNote {
    /// Commitment hash (hex, primary key).
    pub id: String,
    /// Owner Stellar address.
    pub owner: String,
    /// Note private key (hex).
    pub private_key: String,
    /// Blinding factor (hex).
    pub blinding: String,
    /// Amount as decimal string.
    pub amount: String,
    /// Leaf index; `None` until mined.
    pub leaf_index: Option<u32>,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
    /// Ledger sequence when created.
    pub created_at_ledger: u32,
    /// Whether the note has been spent.
    pub spent: bool,
    /// Ledger sequence when spent; `None` if unspent.
    pub spent_at_ledger: Option<u32>,
    /// `true` if received via transfer.
    pub is_received: bool,
}

/// Registered public key entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyEntry {
    /// Stellar address (primary key).
    pub address: String,
    /// X25519 encryption public key (hex).
    pub encryption_key: EncryptionPublicKey,
    /// BN254 note public key (hex).
    pub note_key: NotePublicKey,
    /// Ledger sequence when registered.
    pub ledger: u32,
}

/// A compact note view for UI rendering and spending selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserNoteSummary {
    /// Pool commitment (hex).
    pub id: Field,
    /// Amount in stroops.
    pub amount: NoteAmount,
    /// Commitment leaf index in the pool Merkle tree.
    pub leaf_index: u32,
    /// Ledger sequence when the commitment event was observed.
    pub created_at_ledger: u32,
    /// Whether the note has been spent (nullifier observed).
    pub spent: bool,
}

/// Aggregated pool activity for a single ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PoolLedgerActivity {
    pub ledger: u32,
    pub commitments: u32,
    pub nullifiers: u32,
}

/// Spending key signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendingSignature(pub Vec<u8>);

/// Encryption key signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionSignature(pub Vec<u8>);

/// Encryption private key
#[derive(Debug, Clone)]
pub struct EncryptionPrivateKey(pub [u8; 32]);
/// Encryption public key
#[derive(Debug, Clone)]
pub struct EncryptionPublicKey(pub [u8; 32]);

/// Encryption key pair
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionKeyPair {
    /// Encryption private key
    pub private: EncryptionPrivateKey,
    /// Encryption public key
    pub public: EncryptionPublicKey,
}

/// Note ownership private key
#[derive(Debug, Clone)]
pub struct NotePrivateKey(pub [u8; 32]);

/// Note ownership public key
#[derive(Debug, Clone)]
pub struct NotePublicKey(pub [u8; 32]);

fn parse_hex_32_bytes(s: &str) -> Result<[u8; 32]> {
    let s = s.trim().strip_prefix("0x").unwrap_or(s.trim());
    if s.len() != 64 {
        return Err(anyhow!("expected 64 hex chars, got {}", s.len()));
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).map_err(|e| anyhow!(e))?;
    Ok(out)
}

impl EncryptionPublicKey {
    /// Parse a `0x`-prefixed (or raw) 32-byte hex string.
    pub fn parse(s: &str) -> Result<Self> {
        Ok(Self(parse_hex_32_bytes(s)?))
    }
}

impl EncryptionPrivateKey {
    /// Parse a `0x`-prefixed (or raw) 32-byte hex string.
    pub fn parse(s: &str) -> Result<Self> {
        Ok(Self(parse_hex_32_bytes(s)?))
    }
}

impl NotePublicKey {
    /// Parse a `0x`-prefixed (or raw) 32-byte hex string.
    pub fn parse(s: &str) -> Result<Self> {
        Ok(Self(parse_hex_32_bytes(s)?))
    }
}

impl NotePrivateKey {
    /// Parse a `0x`-prefixed (or raw) 32-byte hex string.
    pub fn parse(s: &str) -> Result<Self> {
        Ok(Self(parse_hex_32_bytes(s)?))
    }
}

macro_rules! impl_key_serde_hex {
    ($ty:ident) => {
        impl Serialize for $ty {
            fn serialize<S: serde::Serializer>(
                &self,
                serializer: S,
            ) -> core::result::Result<S::Ok, S::Error> {
                crate::chain_data::serde_0x_hex_32::serialize(&self.0, serializer)
            }
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: serde::Deserializer<'de>>(
                deserializer: D,
            ) -> core::result::Result<Self, D::Error> {
                crate::chain_data::serde_0x_hex_32::deserialize(deserializer).map($ty)
            }
        }
    };
}

impl_key_serde_hex!(EncryptionPrivateKey);
impl_key_serde_hex!(EncryptionPublicKey);
impl_key_serde_hex!(NotePrivateKey);
impl_key_serde_hex!(NotePublicKey);

#[cfg(feature = "rusqlite")]
mod rusqlite_key_impls {
    use super::{EncryptionPrivateKey, EncryptionPublicKey, NotePrivateKey, NotePublicKey};
    use rusqlite::types::{
        FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, Value, ValueRef,
    };

    macro_rules! impl_key_rusqlite_blob_32 {
        ($ty:ident) => {
            impl ToSql for $ty {
                fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
                    Ok(ToSqlOutput::Owned(Value::Blob(self.0.to_vec())))
                }
            }

            impl FromSql for $ty {
                fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
                    match value {
                        ValueRef::Blob(b) => {
                            if b.len() != 32 {
                                return Err(FromSqlError::InvalidBlobSize {
                                    expected_size: 32,
                                    blob_size: b.len(),
                                });
                            }
                            let mut out = [0u8; 32];
                            out.copy_from_slice(b);
                            Ok($ty(out))
                        }
                        _ => Err(FromSqlError::InvalidType),
                    }
                }
            }
        };
    }

    impl_key_rusqlite_blob_32!(EncryptionPrivateKey);
    impl_key_rusqlite_blob_32!(EncryptionPublicKey);
    impl_key_rusqlite_blob_32!(NotePrivateKey);
    impl_key_rusqlite_blob_32!(NotePublicKey);
}

#[cfg(test)]
mod key_serde_tests {
    use super::*;
    use anyhow::Result;

    fn pattern_bytes() -> Result<[u8; 32]> {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::try_from(i).map_err(|_| anyhow::anyhow!("index out of range"))?;
        }
        Ok(out)
    }

    macro_rules! hex_key_tests {
        ($ty:ident, $mod_name:ident) => {
            mod $mod_name {
                use super::*;

                #[test]
                fn serde_zero_is_0x_64hex() -> Result<()> {
                    let k = $ty([0u8; 32]);
                    let s = serde_json::to_string(&k)?;
                    assert_eq!(
                        s,
                        "\"0x0000000000000000000000000000000000000000000000000000000000000000\""
                    );
                    let parsed: $ty = serde_json::from_str(&s)?;
                    assert_eq!(parsed.0, k.0);
                    Ok(())
                }

                #[test]
                fn serde_roundtrip_pattern() -> Result<()> {
                    let k = $ty(pattern_bytes()?);
                    let s = serde_json::to_string(&k)?;
                    let parsed: $ty = serde_json::from_str(&s)?;
                    assert_eq!(parsed.0, k.0);
                    Ok(())
                }

                #[test]
                fn serde_accepts_missing_0x_prefix() -> Result<()> {
                    let s = "\"0000000000000000000000000000000000000000000000000000000000000000\"";
                    let parsed: $ty = serde_json::from_str(s)?;
                    let roundtrip = serde_json::to_string(&parsed)?;
                    assert_eq!(
                        roundtrip,
                        "\"0x0000000000000000000000000000000000000000000000000000000000000000\""
                    );
                    Ok(())
                }

                #[test]
                fn serde_rejects_wrong_length() -> Result<()> {
                    let s = "\"0x00\"";
                    assert!(serde_json::from_str::<$ty>(s).is_err());
                    Ok(())
                }

                #[test]
                fn serde_rejects_invalid_hex() -> Result<()> {
                    let s =
                        "\"0xgg00000000000000000000000000000000000000000000000000000000000000\"";
                    assert!(serde_json::from_str::<$ty>(s).is_err());
                    Ok(())
                }

                #[test]
                fn serde_rejects_legacy_byte_array() -> Result<()> {
                    let s = "[0,1,2,3]";
                    assert!(serde_json::from_str::<$ty>(s).is_err());
                    Ok(())
                }
            }
        };
    }

    hex_key_tests!(EncryptionPrivateKey, encryption_private_key);
    hex_key_tests!(EncryptionPublicKey, encryption_public_key);
    hex_key_tests!(NotePrivateKey, note_private_key);
    hex_key_tests!(NotePublicKey, note_public_key);

    #[test]
    fn note_public_key_deserialize_from_plain_str_deserializer() -> Result<()> {
        let raw = "18c7f3bd72cb3170d476aa09ef5e706c33e6b578369a95368bd0f09c82314321";
        let d = serde::de::value::BorrowedStrDeserializer::<serde::de::value::Error>::new(raw);
        let parsed: NotePublicKey = <NotePublicKey as serde::Deserialize>::deserialize(d)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let roundtrip = serde_json::to_string(&parsed)?;
        assert_eq!(roundtrip, format!("\"0x{raw}\""));
        Ok(())
    }
}

/// Note ownership key pair
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteKeyPair {
    /// Note ownership private key
    pub private: NotePrivateKey,
    /// Note ownership public key
    pub public: NotePublicKey,
}

macro_rules! impl_byte_wrapper {
    ($name:ident) => {
        impl std::convert::TryFrom<Vec<u8>> for $name {
            type Error = anyhow::Error;

            fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
                let len = value.len();
                if len != 32 {
                    return Err(anyhow!(
                        "{}: Invalid length. Expected 32, got {}",
                        stringify!($name),
                        len
                    ));
                }
                let array: [u8; 32] = value.try_into().map_err(|_| anyhow!("Conversion failed"))?;
                Ok($name(array))
            }
        }

        impl From<[u8; 32]> for $name {
            fn from(bytes: [u8; 32]) -> Self {
                $name(bytes)
            }
        }

        impl AsRef<[u8; 32]> for $name {
            fn as_ref(&self) -> &[u8; 32] {
                &self.0
            }
        }
    };
}

// Apply the macro to your types
impl_byte_wrapper!(EncryptionPrivateKey);
impl_byte_wrapper!(EncryptionPublicKey);
impl_byte_wrapper!(NotePrivateKey);
impl_byte_wrapper!(NotePublicKey);
