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
pub struct EncryptionPrivateKey(#[serde(with = "serde_bytes")] pub [u8; 32]);
/// Encryption public key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionPublicKey(#[serde(with = "serde_bytes")] pub [u8; 32]);

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
pub struct NotePrivateKey(#[serde(with = "serde_bytes")] pub [u8; 32]);

/// Note ownership public key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotePublicKey(#[serde(with = "serde_bytes")] pub [u8; 32]);

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
