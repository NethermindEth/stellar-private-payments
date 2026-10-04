//! Deposits into a real pool contract and checks the resulting wallet
//! balance, plus the ways a deposit can be rejected.

use anyhow::Result;
use stellar_private_payments::{
    Error,
    types::{AssetDescriptor, NoteAmount, TransferRecipient},
};

use super::support::{deploy_default, deploy_scoped, deploy_with_max_deposit, session};
use crate::{network::LocalNetwork, pool::PoolOptions};

const DEPOSIT_STROOPS: u128 = 10_000_000; // 1 XLM

#[tokio::test]
async fn deposit_basic() -> Result<()> {
    let session = session(deploy_default().await?).await?;
    let deposit_amount = NoteAmount::from(DEPOSIT_STROOPS);
    let funded_balance = session.account.balance(&AssetDescriptor::Native).await?;
    let pool = session.pool()?;

    pool.deposit(deposit_amount).await?;

    let balance = pool.balance().await?;
    assert_eq!(balance, deposit_amount);

    let updated_balance = session.account.balance(&AssetDescriptor::Native).await?;
    assert!(funded_balance > updated_balance);

    Ok(())
}

#[tokio::test]
async fn deposit_exceeds_max_deposit() -> Result<()> {
    const MAX_DEPOSIT_STROOPS: u128 = 5_000_000;
    let session =
        session(deploy_with_max_deposit(MAX_DEPOSIT_STROOPS, &[PoolOptions::NONE]).await?).await?;

    let deposit = session
        .pool()?
        .deposit(NoteAmount::from(MAX_DEPOSIT_STROOPS.saturating_add(1)))
        .await;
    assert!(
        deposit.is_err(),
        "a deposit above the pool's max_deposit cap must be rejected"
    );

    Ok(())
}

#[tokio::test]
async fn deposit_insufficient_balance() -> Result<()> {
    let session = session(deploy_default().await?).await?;
    let funded_balance = session.account.balance(&AssetDescriptor::Native).await?;

    let deposit = session
        .pool()?
        .deposit(NoteAmount::from(
            funded_balance.saturating_add(DEPOSIT_STROOPS),
        ))
        .await;
    assert!(
        deposit.is_err(),
        "depositing more than the wallet's classic balance must be rejected"
    );

    Ok(())
}

#[tokio::test]
async fn deposit_refused_while_paused() -> Result<()> {
    // Scoped, because pausing a shared pool would refuse the other tests'
    // deposits.
    let session = session(deploy_scoped(&[PoolOptions::NONE], "deposits-paused").await?).await?;
    let pool = session.pool()?;
    let pool_contract_id = &pool.config().pool_contract_id;
    let admin_secret = &session.identity.admin_secret;
    let network = LocalNetwork::start().await?;
    let deposit_amount = NoteAmount::from(DEPOSIT_STROOPS);

    pool.deposit(deposit_amount).await?;
    network
        .set_deposits_paused(pool_contract_id, admin_secret, true)
        .await?;

    let refused = pool.deposit(deposit_amount).await;
    assert!(
        matches!(refused, Err(Error::DepositsPaused { .. })),
        "a deposit into a paused pool must be refused: {refused:?}"
    );

    // A private transfer moves no tokens into the pool, so it still lands.
    let (note_public_key, encryption_public_key) = session.account.privacy_keys().await?;
    pool.transfer(
        TransferRecipient::keys(note_public_key, encryption_public_key),
        deposit_amount,
    )
    .await?;
    assert_eq!(pool.balance().await?, deposit_amount);

    pool.withdraw(deposit_amount, session.wallet.address())
        .await?;
    assert_eq!(pool.balance().await?, NoteAmount::ZERO);

    network
        .set_deposits_paused(pool_contract_id, admin_secret, false)
        .await?;
    pool.deposit(deposit_amount).await?;
    assert_eq!(pool.balance().await?, deposit_amount);

    Ok(())
}
