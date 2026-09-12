//! Deposits then withdraws from a real pool contract, checking the wallet
//! balance after each step.

use anyhow::Result;
use stellar_private_payments::types::NoteAmount;

use super::support::setup;

const DEPOSIT_STROOPS: u128 = 10_000_000; // 1 XLM

#[tokio::test]
async fn withdraw_basic() -> Result<()> {
    let session = setup().await?;
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
