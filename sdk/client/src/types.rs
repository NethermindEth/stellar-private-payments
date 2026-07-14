pub use ::types::*;

use serde::{Deserialize, Serialize};

/// Circuit bytes for lazy prover init (load via platform I/O before
/// constructing a [`crate::Client`] prover).
#[derive(Debug, Clone)]
pub struct ProverArtifacts {
    pub proving_key: Vec<u8>,
    pub circuit_wasm: Vec<u8>,
    pub circuit_r1cs: Vec<u8>,
}

impl ProverArtifacts {
    pub fn empty() -> Self {
        Self {
            proving_key: Vec::new(),
            circuit_wasm: Vec::new(),
            circuit_r1cs: Vec::new(),
        }
    }
}

/// Per-pool session config (RPC URL, deployment, pool contract, user address).
#[derive(Debug, Clone)]
pub struct PrivatePoolConfig {
    pub rpc_url: String,
    pub contract_config: ContractConfig,
    pub pool_contract_id: String,
    pub user_address: String,
}

impl PrivatePoolConfig {
    pub fn validate(&self) -> Result<(), crate::error::PoolError> {
        if self.pool_contract_id.is_empty() {
            return Err(crate::error::PoolError::InvalidConfig(
                "pool_contract_id must not be empty".into(),
            ));
        }
        if self.user_address.is_empty() {
            return Err(crate::error::PoolError::InvalidConfig(
                "user_address must not be empty".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionResult {
    pub tx_hash: String,
}

#[derive(Debug, Clone)]
pub enum TransferRecipient {
    Address(String),
    Keys {
        note_public_key: NotePublicKey,
        encryption_public_key: EncryptionPublicKey,
    },
}

impl TransferRecipient {
    pub fn keys(
        note_public_key: NotePublicKey,
        encryption_public_key: EncryptionPublicKey,
    ) -> Self {
        Self::Keys {
            note_public_key,
            encryption_public_key,
        }
    }
}

impl From<String> for TransferRecipient {
    fn from(address: String) -> Self {
        Self::Address(address)
    }
}

impl From<&str> for TransferRecipient {
    fn from(address: &str) -> Self {
        Self::Address(address.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Estimate {
    pub tx_count: u32,
}

#[derive(Debug, Clone)]
pub struct SignedTransaction {
    pub signed_xdr: String,
}
