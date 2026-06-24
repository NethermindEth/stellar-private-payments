pub use ::types::*;

use serde::{Deserialize, Serialize};

/// Circuit bytes for lazy prover init (load via platform I/O before pool
/// config).
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
    pub prover_artifacts: ProverArtifacts,
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

impl PrivatePoolConfig {
    pub fn chain_config(&self) -> PoolChainConfig {
        PoolChainConfig::from(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncResult {
    pub from_ledger: u32,
    pub to_ledger: u32,
    pub new_commitments: u32,
    pub new_nullifiers: u32,
    pub new_membership_leaves: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionResult {
    pub tx_hash: String,
}

#[derive(Debug, Clone)]
pub struct TransferRecipient {
    pub note_public_key: NotePublicKey,
    pub encryption_public_key: EncryptionPublicKey,
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

/// On-chain snapshot used when building transact witness inputs.
///
/// Refreshed by [`crate::blocking::PrivatePool::sync`] (RPC + local indexer).
/// Until sync is wired, tests may seed it via
/// [`crate::PoolCore::set_chain_context`].
#[derive(Debug, Clone)]
pub struct TransactChainContext {
    pub pool_root: Field,
    pub pool_next_index: u32,
    pub pool_merkle_levels: u32,
    pub asp_membership_root: Field,
    pub asp_membership_contract_id: String,
    pub asp_membership_ledger: u32,
    pub non_membership_proof: AspNonMembershipProof,
}
