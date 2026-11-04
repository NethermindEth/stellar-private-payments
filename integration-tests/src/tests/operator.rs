//! Admin calls built by the operator handles, signed and sent on a local
//! network. Each test deploys its own contracts, since it changes their admin
//! state.

use std::{str::FromStr, time::Duration};

use anyhow::{Result, bail, ensure};
use stellar_private_payments::{
    chain::{Limits, LocalSigner, ReadXdr, RpcClient, StateFetcher, TransactionEnvelope, WriteXdr},
    operator::{
        AllowlistOperator, BlocklistOperator, CallStatus, Envelopes, PoolAdmin,
        UnsignedOperatorCall,
    },
    types::{ContractConfig, Field, NotePublicKey},
};

use super::support::deploy_scoped;
use crate::{
    keypair::TestKeypair,
    network::{LocalNetwork, NETWORK_PASSPHRASE},
    pool::PoolOptions,
};

/// Signs `built` with `secret`, sends it and waits until it lands.
async fn send(rpc_url: &str, built: UnsignedOperatorCall, secret: &str) -> Result<()> {
    let envelope = TransactionEnvelope::from_xdr_base64(&built.envelope_xdr, Limits::none())?;
    let signed = LocalSigner::from_secret(secret)?
        .sign_transaction(envelope, NETWORK_PASSPHRASE)?
        .to_xdr_base64(Limits::none())?;
    let envelopes = Envelopes::open(rpc_url, NETWORK_PASSPHRASE)?;
    ensure!(
        envelopes.signing_status(&signed).await?.is_ready(),
        "the admin's own signature must meet its threshold"
    );
    let hash = envelopes.submit(&signed).await?;
    for _ in 0..60 {
        match envelopes.confirm(&hash).await? {
            CallStatus::Success => return Ok(()),
            CallStatus::Failed { detail } => bail!("{} failed{detail}", built.call.method),
            CallStatus::Pending => tokio::time::sleep(Duration::from_millis(500)).await,
        }
    }
    bail!("{} did not land in 30 seconds", built.call.method)
}

async fn deployment(scope: &str) -> Result<(String, ContractConfig, String)> {
    let (config, identity) = deploy_scoped(&[PoolOptions::NONE], scope).await?;
    let rpc_url = LocalNetwork::start().await?.rpc_url().to_string();
    Ok((rpc_url, config, identity.admin_secret))
}

#[tokio::test]
async fn allowlist_operator_appends_a_leaf() -> Result<()> {
    let (rpc_url, config, admin_secret) = deployment("operator-allowlist").await?;
    let operator = AllowlistOperator::open(&rpc_url, config.clone(), &config.asp_membership)?;
    let before: u64 = operator.state().await?.next_index.parse()?;

    let leaf = Field::from_str(&format!("0x{:064x}", 0x5eed_u32))?;
    send(&rpc_url, operator.insert_leaf(leaf).await?, &admin_secret).await?;

    let after: u64 = operator.state().await?.next_index.parse()?;
    assert_eq!(Some(after), before.checked_add(1));
    Ok(())
}

#[tokio::test]
async fn blocklist_operator_blocks_and_unblocks_keys() -> Result<()> {
    let (rpc_url, config, admin_secret) = deployment("operator-blocklist").await?;
    let operator = BlocklistOperator::open(&rpc_url, config.clone(), &config.asp_non_membership)?;
    let before = operator.state().await?.root;
    let keys = [NotePublicKey([3; 32]), NotePublicKey([4; 32])];

    send(&rpc_url, operator.insert_keys(&keys).await?, &admin_secret).await?;
    assert_ne!(operator.state().await?.root, before);

    for key in &keys {
        send(&rpc_url, operator.delete_key(key).await?, &admin_secret).await?;
    }
    assert_eq!(operator.state().await?.root, before);
    Ok(())
}

#[tokio::test]
async fn pool_admin_pauses_and_resumes_deposits() -> Result<()> {
    let (rpc_url, config, admin_secret) = deployment("operator-pause").await?;
    let pool_id = config.pools[0].pool_contract_id.clone();
    let allowlist = config.asp_membership.clone();
    let admin = PoolAdmin::open(&rpc_url, config.clone(), &pool_id)?;
    let fetcher = StateFetcher::new(RpcClient::new(&rpc_url)?, config)?;
    let paused = || async {
        let data = fetcher.contracts_data_for_pool(&pool_id).await?;
        anyhow::Ok(data.pools.first().is_some_and(|pool| pool.deposits_paused))
    };

    send(&rpc_url, admin.pause_deposits().await?, &admin_secret).await?;
    assert!(paused().await?);
    send(&rpc_url, admin.unpause_deposits().await?, &admin_secret).await?;
    assert!(!paused().await?);

    send(
        &rpc_url,
        admin.repoint_allowlist(&allowlist).await?,
        &admin_secret,
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn pool_admin_hands_the_pool_to_a_new_admin() -> Result<()> {
    let (rpc_url, config, admin_secret) = deployment("operator-admin-transfer").await?;
    let pool_id = config.pools[0].pool_contract_id.clone();
    let admin = PoolAdmin::open(&rpc_url, config, &pool_id)?;
    let successor = TestKeypair::generate();
    LocalNetwork::start()
        .await?
        .fund(&successor.address())
        .await?;

    send(
        &rpc_url,
        admin.propose_admin(&successor.address()).await?,
        &admin_secret,
    )
    .await?;
    assert_eq!(
        admin.admin().await?.pending_admin,
        Some(successor.address())
    );
    send(
        &rpc_url,
        admin.cancel_admin_transfer().await?,
        &admin_secret,
    )
    .await?;
    assert_eq!(admin.admin().await?.pending_admin, None);

    send(
        &rpc_url,
        admin.propose_admin(&successor.address()).await?,
        &admin_secret,
    )
    .await?;
    send(&rpc_url, admin.accept_admin().await?, &successor.secret()).await?;
    let state = admin.admin().await?;
    assert_eq!(state.admin, successor.address());
    assert_eq!(state.pending_admin, None);
    Ok(())
}
