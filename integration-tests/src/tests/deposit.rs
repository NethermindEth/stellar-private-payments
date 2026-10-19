//! Deposits into a real pool contract and checks the resulting wallet
//! balance, plus the ways a deposit can be rejected.

use anyhow::Result;
use stellar_private_payments::{
    Error,
    types::{AssetDescriptor, ExtAmount, NoteAmount, TransferRecipient},
};

use super::support::{
    FEE_STROOPS, MIN_DEPOSIT_STROOPS, deploy_default, deploy_scoped, deploy_with_max_deposit,
    session,
};
use crate::{network::LocalNetwork, pool::PoolOptions};

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

/// The SDK refuses the deposit before proving and names the cap and the
/// largest deposit, so nothing reaches the network.
#[tokio::test]
async fn deposit_exceeds_max_deposit() -> Result<()> {
    let session =
        session(deploy_with_max_deposit(LOW_CAP_STROOPS, &[PoolOptions::NONE]).await?).await?;
    let funded_balance = session.account.balance(&AssetDescriptor::Native).await?;
    let cap = ExtAmount::try_from(NoteAmount::from(LOW_CAP_STROOPS))?;
    let largest = NoteAmount::from(LOW_CAP_STROOPS - FEE_STROOPS);

    // The pool caps what the deposit sends, which is the note plus the fee.
    let deposit = session
        .pool()?
        .deposit(NoteAmount::from(LOW_CAP_STROOPS - FEE_STROOPS + 1))
        .await;
    assert!(
        matches!(
            deposit,
            Err(Error::DepositAboveMaximum { maximum, largest_deposit })
                if maximum == cap && largest_deposit == largest
        ),
        "a deposit whose note and fee exceed the cap must be refused before proving: {deposit:?}"
    );

    let unchanged_balance = session.account.balance(&AssetDescriptor::Native).await?;
    assert_eq!(
        unchanged_balance, funded_balance,
        "a refused deposit must not submit a transaction"
    );

    Ok(())
}

/// The largest deposit leaves room for the fee under the cap.
#[tokio::test]
async fn deposit_at_max_deposit() -> Result<()> {
    let session =
        session(deploy_with_max_deposit(LOW_CAP_STROOPS, &[PoolOptions::NONE]).await?).await?;
    let pool = session.pool()?;
    let max_deposit = NoteAmount::from(LOW_CAP_STROOPS - FEE_STROOPS);

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

#[tokio::test]
async fn deposit_refused_while_paused() -> Result<()> {
    // Scoped: pausing a shared pool would refuse other tests' deposits.
    let session = session(deploy_scoped(&[PoolOptions::NONE], "deposits-paused").await?).await?;
    let pool = session.pool()?;
    let pool_contract_id = &pool.config().pool_contract_id;
    let admin_secret = &session.identity.admin_secret;
    let network = LocalNetwork::start().await?;
    let deposit_amount = NoteAmount::from(DEPOSIT_STROOPS);
    let fees_before = network.fees_total(pool_contract_id, admin_secret).await?;

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
        pool.max_spend(pool.fee().await?).await?,
    )
    .await?;
    assert_eq!(
        pool.balance().await?,
        NoteAmount::from(DEPOSIT_STROOPS - FEE_STROOPS)
    );

    pool.withdraw(
        pool.max_spend(pool.fee().await?).await?,
        session.wallet.address(),
    )
    .await?;
    assert_eq!(pool.balance().await?, NoteAmount::ZERO);

    network
        .set_deposits_paused(pool_contract_id, admin_secret, false)
        .await?;
    pool.deposit(deposit_amount).await?;
    assert_eq!(pool.balance().await?, deposit_amount);

    let fees_after = network.fees_total(pool_contract_id, admin_secret).await?;
    assert_eq!(
        fees_after.checked_sub(fees_before),
        Some(i128::try_from(4 * FEE_STROOPS)?),
        "two deposits, a transfer and a withdrawal pay one fee each; the refused deposit none"
    );

    Ok(())
}

#[tokio::test]
async fn deposit_below_minimum_is_refused() -> Result<()> {
    let session = session(deploy_default().await?).await?;
    let funded_balance = session.account.balance(&AssetDescriptor::Native).await?;

    let deposit = session
        .pool()?
        .deposit(NoteAmount::from(MIN_DEPOSIT_STROOPS - 1))
        .await;
    assert!(
        matches!(
            deposit,
            Err(Error::DepositBelowMinimum { minimum })
                if minimum == NoteAmount::from(MIN_DEPOSIT_STROOPS)
        ),
        "a deposit below the pool minimum must be refused before proving: {deposit:?}"
    );

    let unchanged_balance = session.account.balance(&AssetDescriptor::Native).await?;
    assert_eq!(
        unchanged_balance, funded_balance,
        "a refused deposit must not submit a transaction"
    );

    Ok(())
}
