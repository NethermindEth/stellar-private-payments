//! Deposits into a real pool contract and checks the resulting wallet
//! balance, plus the ways a deposit can be rejected.

use anyhow::Result;
use stellar_private_payments::types::{AssetDescriptor, NoteAmount};

use super::support::{assert_contract_error, deploy_default, deploy_with_max_deposit, session};
use crate::pool::PoolOptions;

const DEPOSIT_STROOPS: u128 = 10_000_000; // 1 XLM
const LOW_CAP_STROOPS: u128 = 5_000_000;

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

/// The pool refuses the deposit with `WrongExtAmount` (code 6), where
/// `is_err()` also passed on a failure inside the SDK.
#[tokio::test]
async fn deposit_exceeds_max_deposit() -> Result<()> {
    let session =
        session(deploy_with_max_deposit(LOW_CAP_STROOPS, &[PoolOptions::NONE]).await?).await?;

    let err = session
        .pool()?
        .deposit(NoteAmount::from(LOW_CAP_STROOPS.saturating_add(1)))
        .await
        .expect_err("a deposit above the pool's max_deposit cap must be rejected");
    assert_contract_error(err, 6);

    Ok(())
}

#[tokio::test]
async fn deposit_at_max_deposit() -> Result<()> {
    let session =
        session(deploy_with_max_deposit(LOW_CAP_STROOPS, &[PoolOptions::NONE]).await?).await?;
    let pool = session.pool()?;
    let max_deposit = NoteAmount::from(LOW_CAP_STROOPS);

    pool.deposit(max_deposit).await?;

    assert_eq!(pool.balance().await?, max_deposit);

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
