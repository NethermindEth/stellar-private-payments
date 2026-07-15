pub use ::types::*;

use serde::{Deserialize, Serialize};

/// Circuit bytes for in-process transact proving.
#[derive(Debug, Clone)]
pub struct ProverArtifacts {
    pub proving_key: Vec<u8>,
    pub circuit_wasm: Vec<u8>,
    pub circuit_r1cs: Vec<u8>,
}

/// RPC and contract identity for a single pool (chain orchestration only).
#[derive(Debug, Clone)]
pub struct PoolChainConfig {
    pub rpc_url: String,
    pub contract_config: ContractConfig,
    pub pool_contract_id: String,
    pub user_address: String,
}

impl PoolChainConfig {
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
        self.contract_config
            .pool(&self.pool_contract_id)
            .map_err(|e| crate::error::PoolError::InvalidConfig(e.to_string()))?;
        Ok(())
    }
}

impl From<&PrivatePoolConfig> for PoolChainConfig {
    fn from(config: &PrivatePoolConfig) -> Self {
        Self {
            rpc_url: config.rpc_url.clone(),
            contract_config: config.contract_config.clone(),
            pool_contract_id: config.pool_contract_id.clone(),
            user_address: config.user_address.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PrivatePoolConfig {
    pub rpc_url: String,
    pub contract_config: ContractConfig,
    pub pool_contract_id: String,
    pub user_address: String,
    pub storage_path: String,
}

impl PrivatePoolConfig {
    pub fn chain_config(&self) -> PoolChainConfig {
        PoolChainConfig::from(self)
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
