//! Deposits into a real pool contract and checks the resulting wallet
//! balance.

use anyhow::Result;
use stellar_private_payments::types::NoteAmount;

use super::support::setup;

const DEPOSIT_STROOPS: u128 = 10_000_000; // 1 XLM

#[tokio::test]
async fn deposit_basic() -> Result<()> {
    let session = setup().await?;
    let deposit_amount = NoteAmount::from(DEPOSIT_STROOPS);
    let pool = session.pool()?;

    pool.deposit(deposit_amount).await?;

    let balance = pool.balance().await?;
    assert_eq!(balance, deposit_amount);

    Ok(())
}
