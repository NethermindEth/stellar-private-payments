//! Raw transactions the SDK refuses before proving.

use anyhow::Result;
use stellar_private_payments::{
    Error,
    planner::Transact,
    types::{ExtAmount, NoteAmount},
};

use super::support::{FEE_STROOPS, MIN_DEPOSIT_STROOPS, deploy_default, session};

const DEPOSIT_STROOPS: u128 = 10_000_000; // 1 XLM

/// The proof builder refuses with `Error::Other`, so a typed error shows the
/// SDK refused first.
#[tokio::test]
async fn an_unbalanced_transaction_is_refused_before_proving() -> Result<()> {
    let session = session(deploy_default().await?).await?;
    let pool = session.pool()?;
    let config = pool.config();
    let pool_id = config.pool_contract_id.clone();
    let token_id = config
        .contract_config
        .pool(&pool_id)?
        .token_contract_id
        .clone();

    pool.deposit(NoteAmount::from(DEPOSIT_STROOPS)).await?;
    let wallet = pool.spendable_notes().await?;
    let [note] = wallet.as_slice() else {
        anyhow::bail!("one deposit gives one note: {wallet:?}");
    };
    let after_fee = note.amount - NoteAmount::from(FEE_STROOPS);
    let short_by_the_fee = ExtAmount::from(-i128::try_from(FEE_STROOPS)?);
    let raw = |inputs, output, ext_amount, recipient: &str| {
        Transact::new(
            inputs,
            [output, NoteAmount::ZERO],
            ext_amount,
            recipient.to_string(),
            [None, None],
            [None, None],
        )
    };

    let unbalanced = raw(
        vec![note.commitment],
        note.amount,
        ExtAmount::ZERO,
        &pool_id,
    );
    let result = pool.transact(unbalanced.clone()).await;
    assert!(
        matches!(result, Err(Error::NotBalanced { gap }) if gap == short_by_the_fee),
        "{result:?}"
    );

    let below_minimum = raw(
        vec![],
        NoteAmount::from(MIN_DEPOSIT_STROOPS),
        ExtAmount::from(i128::try_from(MIN_DEPOSIT_STROOPS + FEE_STROOPS - 1)?),
        &pool_id,
    );
    let result = pool.transact(below_minimum.clone()).await;
    assert!(
        matches!(result, Err(Error::DepositBelowMinimum { .. })),
        "{result:?}"
    );

    // `spendable_notes` above synced the note; `check_transact` does not sync.
    let result = pool.check_transact(&unbalanced).await;
    assert!(
        matches!(result, Err(Error::NotBalanced { gap }) if gap == short_by_the_fee),
        "{result:?}"
    );
    let result = pool.check_transact(&below_minimum).await;
    assert!(
        matches!(result, Err(Error::DepositBelowMinimum { .. })),
        "{result:?}"
    );
    // Unbalanced too, so the recipient is checked first.
    let to_token = raw(
        vec![note.commitment],
        NoteAmount::ZERO,
        -ExtAmount::try_from(note.amount)?,
        &token_id,
    );
    let result = pool.check_transact(&to_token).await;
    assert!(
        matches!(result, Err(Error::WithdrawalToContract)),
        "{result:?}"
    );

    let transfer = raw(vec![note.commitment], after_fee, ExtAmount::ZERO, &pool_id);
    let deposit = raw(
        vec![],
        NoteAmount::from(MIN_DEPOSIT_STROOPS),
        ExtAmount::from(i128::try_from(MIN_DEPOSIT_STROOPS + FEE_STROOPS)?),
        &pool_id,
    );
    let withdrawal = raw(
        vec![note.commitment],
        NoteAmount::ZERO,
        -ExtAmount::try_from(after_fee)?,
        &session.wallet.address(),
    );
    for step in [transfer, deposit, withdrawal] {
        pool.check_transact(&step).await?;
    }

    Ok(())
}
