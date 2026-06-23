pub use ::types::*;

use serde::{Deserialize, Serialize};
use stellar::PreparedSorobanTx;

pub type PreparedTransaction = PreparedSorobanTx;

/// Circuit bytes for lazy prover init (load via platform I/O before pool
/// config).
#[derive(Debug, Clone)]
pub struct ProverArtifacts {
    pub proving_key: Vec<u8>,
    pub circuit_wasm: Vec<u8>,
    pub circuit_r1cs: Vec<u8>,
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
/// Refreshed by [`PrivatePool::sync`] (RPC + local indexer). Until sync is
/// wired, tests may seed it via [`PrivatePool::set_chain_context`].
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
