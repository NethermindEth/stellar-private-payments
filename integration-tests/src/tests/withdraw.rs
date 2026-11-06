//! Deposits then withdraws from a real pool contract, checking the wallet
//! balance after each step, plus the ways a withdrawal can be rejected.

use anyhow::Result;
use stellar_private_payments::{
    Error,
    planner::Transact,
    types::{AssetDescriptor, ExtAmount, NoteAmount},
};

use super::support::{FEE_STROOPS, assert_contract_error, deploy_default, note_states, session};

const DEPOSIT_STROOPS: u128 = 10_000_000; // 1 XLM

#[tokio::test]
async fn withdraw_basic() -> Result<()> {
    let session = session(deploy_default().await?).await?;
    let deposit_amount = NoteAmount::from(DEPOSIT_STROOPS);
    let pool = session.pool()?;

    pool.deposit(deposit_amount).await?;
    let balance_after_deposit = pool.balance().await?;
    assert_eq!(balance_after_deposit, deposit_amount);

    pool.withdraw(
        NoteAmount::from(DEPOSIT_STROOPS - FEE_STROOPS),
        session.wallet.address(),
    )
    .await?;
    let balance_after_withdraw = pool.balance().await?;
    assert_eq!(balance_after_withdraw, NoteAmount::ZERO);

    Ok(())
}

#[tokio::test]
async fn withdraw_multi_tx() -> Result<()> {
    let session = session(deploy_default().await?).await?;
    let pool = session.pool()?;

    let deposit_amount = NoteAmount::from(DEPOSIT_STROOPS);
    pool.deposit(deposit_amount).await?;
    pool.deposit(deposit_amount).await?;
    pool.deposit(deposit_amount).await?;

    // Three notes take two steps, and each step pays the fee.
    let total = NoteAmount::from(3 * DEPOSIT_STROOPS - 2 * FEE_STROOPS);
    let estimate = pool.estimate(total).await?;
    assert_eq!(
        estimate.tx_count, 2,
        "combining 3 notes with a 2-input circuit should take 2 transactions"
    );

    let results = pool.withdraw(total, session.wallet.address()).await?;
    assert_eq!(results.len(), 2);

    let balance = pool.balance().await?;
    assert_eq!(balance, NoteAmount::ZERO);

    Ok(())
}

/// Declining the wallet prompt leaves the note unspent, so the same
/// withdrawal retried right after lands (#428).
#[tokio::test]
async fn withdraw_retry_after_wallet_rejection() -> Result<()> {
    let session = session(deploy_default().await?).await?;
    let pool = session.pool()?;
    let deposit_amount = NoteAmount::from(DEPOSIT_STROOPS);
    let withdraw_amount = NoteAmount::from(DEPOSIT_STROOPS - FEE_STROOPS);

    pool.deposit(deposit_amount).await?;
    let notes = note_states(&pool).await?;
    let funded_balance = session.account.balance(&AssetDescriptor::Native).await?;

    session.reject_next_transaction();
    let rejected = pool
        .withdraw(withdraw_amount, session.wallet.address())
        .await;
    assert!(
        matches!(rejected, Err(Error::UserRejected(_))),
        "the withdrawal must fail with the wallet's rejection: {rejected:?}"
    );
    assert_eq!(note_states(&pool).await?, notes);
    assert_eq!(pool.balance().await?, deposit_amount);
    assert_eq!(
        session.account.balance(&AssetDescriptor::Native).await?,
        funded_balance
    );

    pool.withdraw(withdraw_amount, session.wallet.address())
        .await?;

    assert_eq!(pool.balance().await?, NoteAmount::ZERO);
    assert!(session.account.balance(&AssetDescriptor::Native).await? > funded_balance);

    Ok(())
}

/// Declining the second transaction of a two-step withdrawal keeps the
/// confirmed first step, and a fresh withdrawal planned from the notes that
/// step left lands (#428).
#[tokio::test]
async fn withdraw_multi_tx_retry_after_second_step_rejection() -> Result<()> {
    let session = session(deploy_default().await?).await?;
    let pool = session.pool()?;

    let deposit_amount = NoteAmount::from(DEPOSIT_STROOPS);
    pool.deposit(deposit_amount).await?;
    pool.deposit(deposit_amount).await?;
    pool.deposit(deposit_amount).await?;
    // Three notes take two steps, and each step pays the fee.
    let total = NoteAmount::from(3 * DEPOSIT_STROOPS - 2 * FEE_STROOPS);

    session.reject_transaction(2);
    let rejected = pool.withdraw(total, session.wallet.address()).await;
    let Err(Error::PlanExecution(stopped)) = &rejected else {
        panic!("the withdrawal must stop after its first step: {rejected:?}");
    };
    assert_eq!(stopped.completed.len(), 1);
    assert!(
        matches!(stopped.cause(), Error::UserRejected(_)),
        "the second step must fail with the wallet's rejection: {rejected:?}"
    );
    // The first step merged two notes, so the balance is still in the pool,
    // less that step's fee.
    assert_eq!(
        pool.balance().await?,
        NoteAmount::from(3 * DEPOSIT_STROOPS - FEE_STROOPS)
    );
    assert_eq!(pool.spendable_notes().await?.len(), 2);

    let results = pool.withdraw(total, session.wallet.address()).await?;
    assert_eq!(results.len(), 1);

    assert_eq!(pool.balance().await?, NoteAmount::ZERO);

    Ok(())
}

#[tokio::test]
async fn withdraw_insufficient_balance() -> Result<()> {
    let session = session(deploy_default().await?).await?;
    let pool = session.pool()?;

    pool.deposit(NoteAmount::from(DEPOSIT_STROOPS)).await?;

    let withdrawal = pool
        .withdraw(
            NoteAmount::from(DEPOSIT_STROOPS - FEE_STROOPS + 1),
            session.wallet.address(),
        )
        .await;
    assert!(
        matches!(withdrawal, Err(Error::SpendSession(_))),
        "a withdrawal the notes cannot pay with the fee must not plan: {withdrawal:?}"
    );

    Ok(())
}

#[tokio::test]
async fn withdraw_malformed_address() -> Result<()> {
    let session = session(deploy_default().await?).await?;
    let pool = session.pool()?;

    pool.deposit(NoteAmount::from(DEPOSIT_STROOPS)).await?;

    let withdrawal = pool
        .withdraw(
            NoteAmount::from(DEPOSIT_STROOPS - FEE_STROOPS),
            "not-a-real-address",
        )
        .await;
    // The XDR error for the recipient does not name the address, so this pins
    // that planning passed and the recipient was refused.
    assert!(
        withdrawal
            .as_ref()
            .is_err_and(|error| error.to_string().contains("xdr value invalid")),
        "withdrawing to a syntactically invalid address must be rejected for the address: {withdrawal:?}"
    );

    Ok(())
}

#[tokio::test]
async fn a_raw_withdrawal_to_the_token_is_refused() -> Result<()> {
    let session = session(deploy_default().await?).await?;
    let pool = session.pool()?;
    let config = pool.config();
    let token_id = config
        .contract_config
        .pool(&config.pool_contract_id)?
        .token_contract_id
        .clone();

    // No proof exists, so only a refusal before proving gets here.
    let result = pool
        .transact(Transact::new(
            vec![],
            [NoteAmount::ZERO; 2],
            ExtAmount::from(-1_000_000),
            token_id,
            [None, None],
            [None, None],
        ))
        .await;
    assert!(
        matches!(result, Err(Error::WithdrawalToContract)),
        "{result:?}"
    );

    Ok(())
}

/// Once the first spend is in a ledger, the pool refuses the second with
/// `AlreadySpentNullifier` (code 9), not just any failure up to confirm.
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

    let mut plan_a = pool
        .prepare_withdraw(&wallet, half, session.wallet.address())
        .await?;
    let mut prepared_a = pool.prove_next(&mut plan_a).await?;

    let mut plan_b = pool
        .prepare_withdraw(&wallet, half, session.wallet.address())
        .await?;
    let mut prepared_b = pool.prove_next(&mut plan_b).await?;

    pool.simulate(&mut prepared_a).await?;
    let signed_a = pool.sign(&prepared_a).await?;
    let hash_a = pool.submit(signed_a).await?;
    pool.confirm(&hash_a).await?;

    let err = pool
        .simulate(&mut prepared_b)
        .await
        .expect_err("spending the same note a second time must be rejected on-chain");
    assert_contract_error(err, 9);

    Ok(())
}
