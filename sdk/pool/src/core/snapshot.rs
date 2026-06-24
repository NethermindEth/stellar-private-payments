use types::{AspNonMembershipProof, ContractsStateData, NotePublicKey, SMT_DEPTH};

use crate::{
    error::PoolError,
    types::{PoolChainConfig, TransactChainContext},
};

pub(crate) async fn fetch_snapshot_async(
    config: &PoolChainConfig,
    note_pubkey: &NotePublicKey,
) -> Result<TransactChainContext, PoolError> {
    use stellar::StateFetcher;

    let fetcher = StateFetcher::new(&config.rpc_url, config.contract_config.clone())
        .map_err(|e| PoolError::Other(format!("state fetcher: {e:#}")))?;
    let data = fetcher
        .contracts_data_for_pool(&config.pool_contract_id)
        .await
        .map_err(|e| PoolError::Other(format!("fetch pool state: {e:#}")))?;
    let non_membership_proof = fetcher
        .get_nonmembership_proof(
            note_pubkey,
            data.asp_non_membership.root,
            SMT_DEPTH as usize,
            &config.user_address,
        )
        .await
        .map_err(|e| PoolError::Other(format!("non-membership proof: {e:#}")))?;

    chain_context_from_fetched_state(data, &config.pool_contract_id, non_membership_proof)
}

fn chain_context_from_fetched_state(
    data: ContractsStateData,
    pool_contract_id: &str,
    non_membership_proof: AspNonMembershipProof,
) -> Result<TransactChainContext, PoolError> {
    let pool =
        data.pools.into_iter().next().ok_or_else(|| {
            PoolError::Other(format!("pool data not fetched for {pool_contract_id}"))
        })?;
    let pool_root = pool
        .merkle_root
        .ok_or_else(|| PoolError::Other("pool merkle_root not fetched".into()))?;
    let pool_next_index = pool
        .merkle_next_index
        .parse::<u32>()
        .map_err(|e| PoolError::Other(format!("invalid pool merkle_next_index: {e}")))?;

    Ok(TransactChainContext {
        pool_root,
        pool_next_index,
        pool_merkle_levels: pool.merkle_levels,
        asp_membership_root: data.asp_membership.root,
        asp_membership_contract_id: data.asp_membership.contract_id,
        asp_membership_ledger: data.asp_membership.ledger,
        non_membership_proof,
    })
}
