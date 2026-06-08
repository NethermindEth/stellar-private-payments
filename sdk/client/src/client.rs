//! Stellar Private Payments SDK client

use anyhow::Result;
use stellar::StateFetcher;
use types::{AspNonMembershipProof, ContractConfig, ContractsStateData, Field, NotePublicKey};

/// Entry point for Stellar private-payments operations
pub struct Client {
    fetcher: StateFetcher,
}

impl Client {
    /// Connect to Stellar RPC with the given deployment config
    pub fn new(rpc_url: &str, config: ContractConfig) -> Result<Self> {
        Ok(Self {
            fetcher: StateFetcher::new(rpc_url, config)?,
        })
    }

    /// Deployment config (contract addresses, pools, network)
    pub fn config(&self) -> &ContractConfig {
        self.fetcher.contract_config()
    }

    /// Fetch on-chain state for all enabled pools plus shared ASP contracts
    pub async fn all_contracts_data(&self) -> Result<ContractsStateData> {
        self.fetcher.all_contracts_data().await
    }

    /// Fetch on-chain state for a single pool plus shared ASP contracts
    pub async fn contracts_data_for_pool(
        &self,
        pool_contract_id: &str,
    ) -> Result<ContractsStateData> {
        self.fetcher.contracts_data_for_pool(pool_contract_id).await
    }

    /// Fetch ASP membership and non-membership contract state.
    pub async fn asp_state(&self) -> Result<ContractsStateData> {
        self.fetcher.asp_state().await
    }

    /// ASP non-membership proof for a note public key
    pub async fn asp_non_membership_proof(
        &self,
        note_pubkey: &NotePublicKey,
        non_membership_root: Field,
        smt_depth: usize,
        source_account: &str,
    ) -> Result<AspNonMembershipProof> {
        self.fetcher
            .get_nonmembership_proof(note_pubkey, non_membership_root, smt_depth, source_account)
            .await
    }

    /// Low-level state fetcher for callers that need the full API
    pub fn state_fetcher(&self) -> &StateFetcher {
        &self.fetcher
    }
}
