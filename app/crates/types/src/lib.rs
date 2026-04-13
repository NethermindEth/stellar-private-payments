mod chain_data;
mod amounts;
mod ext_data;
pub use chain_data::*;
pub use amounts::*;
pub use ext_data::*;
use anyhow::{Result, anyhow};

use serde::{Deserialize, Serialize};

pub const SMT_DEPTH: u32 = 10;

// scripts/deployments.json
#[derive(Debug, Serialize, Deserialize)]
pub struct ContractConfig {
    pub network: String,
    pub deployer: String,
    pub admin: String,
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
    /// Membership blinding used when the leaf was added (BN254 scalar field element).
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

/// Spending key signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendingSignature(pub Vec<u8>);

/// Encryption key signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionSignature(pub Vec<u8>);

/// Encryption private key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionPrivateKey(#[serde(with = "crate::chain_data::serde_0x_hex_32")] pub [u8; 32]);
/// Encryption public key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionPublicKey(#[serde(with = "crate::chain_data::serde_0x_hex_32")] pub [u8; 32]);

/// Encryption key pair
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionKeyPair {
    /// Encryption private key
    pub private: EncryptionPrivateKey,
    /// Encryption public key
    pub public: EncryptionPublicKey,
}

/// Note ownership private key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotePrivateKey(#[serde(with = "crate::chain_data::serde_0x_hex_32")] pub [u8; 32]);

/// Note ownership public key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotePublicKey(#[serde(with = "crate::chain_data::serde_0x_hex_32")] pub [u8; 32]);

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
                fn serde_rejects_missing_0x_prefix() -> Result<()> {
                    let s =
                        "\"0000000000000000000000000000000000000000000000000000000000000000\"";
                    assert!(serde_json::from_str::<$ty>(s).is_err());
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
                    let s = "\"0xgg00000000000000000000000000000000000000000000000000000000000000\"";
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
                    return Err(anyhow!("{}: Invalid length. Expected 32, got {}", stringify!($name), len));
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
