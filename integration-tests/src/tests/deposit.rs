//! Deposits into a real pool contract and checks the resulting wallet
//! balance, plus the ways a deposit can be rejected.

use anyhow::Result;
use stellar_private_payments::types::{AssetDescriptor, NoteAmount};

use super::support::{deploy_default, deploy_with_max_deposit, session};
use crate::pool::PoolOptions;

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
