//! Deposits then withdraws from a real pool contract, checking the wallet
//! balance after each step, plus the ways a withdrawal can be rejected.

use anyhow::Result;
use stellar_private_payments::types::NoteAmount;

use super::support::{deploy_default, session};

const DEPOSIT_STROOPS: u128 = 10_000_000; // 1 XLM

#[tokio::test]
async fn withdraw_basic() -> Result<()> {
    let session = session(deploy_default().await?).await?;
    let deposit_amount = NoteAmount::from(DEPOSIT_STROOPS);
    let pool = session.pool()?;

    pool.deposit(deposit_amount).await?;
    let balance_after_deposit = pool.balance().await?;
    assert_eq!(balance_after_deposit, deposit_amount);

    pool.withdraw(deposit_amount, session.wallet.address())
        .await?;
    let balance_after_withdraw = pool.balance().await?;
    assert_eq!(balance_after_withdraw, NoteAmount::ZERO);

    Ok(())
}

#[tokio::test]
async fn withdraw_insufficient_balance() -> Result<()> {
    let session = session(deploy_default().await?).await?;
    let pool = session.pool()?;

    pool.deposit(NoteAmount::from(DEPOSIT_STROOPS)).await?;

    let withdrawal = pool
        .withdraw(
            NoteAmount::from(DEPOSIT_STROOPS.saturating_add(1)),
            session.wallet.address(),
        )
        .await;
    assert!(
        withdrawal.is_err(),
        "withdrawing more than the wallet's pool balance must be rejected"
    );

    Ok(())
}

#[tokio::test]
async fn withdraw_malformed_address() -> Result<()> {
    let session = session(deploy_default().await?).await?;
    let pool = session.pool()?;

    pool.deposit(NoteAmount::from(DEPOSIT_STROOPS)).await?;

    let withdrawal = pool
        .withdraw(NoteAmount::from(DEPOSIT_STROOPS), "not-a-real-address")
        .await;
    assert!(
        withdrawal.is_err(),
        "withdrawing to a syntactically invalid address must be rejected"
    );

    Ok(())
}

#[tokio::test]
async fn withdraw_double_spend() -> Result<()> {
    let session = session(deploy_default().await?).await?;
    let pool = session.pool()?;

    pool.deposit(NoteAmount::from(DEPOSIT_STROOPS)).await?;

    let wallet = pool.spendable_notes().await?;
    assert_eq!(
        wallet.len(),
        1,
        "a single deposit should produce exactly one spendable note"
    );

    let half = NoteAmount::from(DEPOSIT_STROOPS / 2);

    let mut plan_a = pool.prepare_withdraw(&wallet, half, session.wallet.address())?;
    let prepared_a = pool.prove_next(&mut plan_a).await?;
    let signed_a = pool.sign(&prepared_a).await?;
    let hash_a = pool.submit(signed_a).await?;
    pool.confirm(&hash_a).await?;

    let mut plan_b = pool.prepare_withdraw(&wallet, half, session.wallet.address())?;
    let prepared_b = pool.prove_next(&mut plan_b).await?;
    let signed_b = pool.sign(&prepared_b).await?;
    let rejected = match pool.submit(signed_b).await {
        Err(_) => true,
        Ok(hash_b) => pool.confirm(&hash_b).await.is_err(),
    };
    assert!(
        rejected,
        "spending the same note a second time must be rejected on-chain"
    );

    Ok(())
}
