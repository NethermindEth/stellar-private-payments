use anyhow::{Context, Result};
use stellar_private_payments::types::{AssetDescriptor, NoteAmount};

use super::support::{deploy, deploy_default, session};
use crate::{network::LocalNetwork, pool::PoolOptions};

const DEPOSIT_STROOPS: u128 = 10_000_000; // 1 XLM
const TRANSFER_STROOPS: u128 = 4_000_000;

#[tokio::test]
async fn user_notes_basic() -> Result<()> {
    let session = session(deploy_default().await?).await?;

    // deposit, 1 note
    let deposit_amount = NoteAmount::from(DEPOSIT_STROOPS);
    session.pool()?.deposit(deposit_amount).await?;
    let notes = session.account.user_notes(10).await?;
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].amount, deposit_amount);

    // deposit again, 2 notes
    let deposit_amount2 = NoteAmount::from(DEPOSIT_STROOPS.saturating_mul(2));
    session.pool()?.deposit(deposit_amount2).await?;
    let notes = session.account.user_notes(10).await?;
    assert_eq!(notes.len(), 2);
    assert_eq!(notes[0].amount, deposit_amount2);

    // truncated, most recent note
    let notes = session.account.user_notes(1).await?;
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].amount, deposit_amount2);

    Ok(())
}

#[tokio::test]
async fn user_notes_transfer() -> Result<()> {
    let config = deploy_default().await?;
    let sender = session(config.clone()).await?;
    let recipient = session(config).await?;
    recipient.account.register_public_keys(None, None).await?;

    let deposit_amount = NoteAmount::from(DEPOSIT_STROOPS);
    let transfer_amount = NoteAmount::from(TRANSFER_STROOPS);
    sender.pool()?.deposit(deposit_amount).await?;
    sender
        .pool()?
        .transfer(recipient.wallet.address(), transfer_amount)
        .await?;

    let sender_notes = sender.account.user_notes(10).await?;
    assert_eq!(
        sender_notes.len(),
        2,
        "the deposit note was spent, creating one additional note"
    );
    assert_eq!(
        sender_notes[0].amount,
        deposit_amount
            .checked_sub(transfer_amount)
            .expect("transfer amount fits within deposit")
    );

    let recipient_notes = recipient.account.user_notes(10).await?;
    assert_eq!(recipient_notes.len(), 1);
    assert_eq!(recipient_notes[0].amount, transfer_amount);

    Ok(())
}

#[tokio::test]
async fn sync_inline_idempotent() -> Result<()> {
    let session = session(deploy_default().await?).await?;
    let deposit_amount = NoteAmount::from(DEPOSIT_STROOPS);
    session.pool()?.deposit(deposit_amount).await?;

    session.account.sync().await?;
    session.account.sync().await?;

    let notes = session.account.user_notes(10).await?;
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].amount, deposit_amount);

    Ok(())
}

#[tokio::test]
async fn unknown_pool() -> Result<()> {
    let session = session(deploy_default().await?).await?;
    let pool_res = session.account.pool("unknown-pool-contract-id");
    assert!(pool_res.is_err());

    Ok(())
}

#[tokio::test]
async fn is_registered() -> Result<()> {
    let session = session(deploy_default().await?).await?;
    assert!(!session.account.is_registered().await?);

    session.account.register_public_keys(None, None).await?;
    assert!(session.account.is_registered().await?);

    Ok(())
}

#[tokio::test]
async fn portfolio_basic() -> Result<()> {
    let session = session(deploy_default().await?).await?;
    let deposit_amount = NoteAmount::from(DEPOSIT_STROOPS);
    session.pool()?.deposit(deposit_amount).await?;

    let portfolio = session.account.portfolio().await?;
    assert_eq!(
        portfolio.len(),
        1,
        "only one pool is deployed in this suite"
    );
    assert_eq!(
        portfolio[0].pool_contract_id,
        session.pool()?.config().pool_contract_id
    );
    assert_eq!(portfolio[0].amount, deposit_amount);
    assert_eq!(portfolio[0].note_count, 1);

    Ok(())
}

#[tokio::test]
async fn portfolio_multi_pool() -> Result<()> {
    let config = deploy(&[PoolOptions::NONE, PoolOptions::NONE]).await?;
    let session = session(config).await?;
    let pool_a = session.pool_at(0)?;
    let pool_b = session.pool_at(1)?;

    let amount_a = NoteAmount::from(DEPOSIT_STROOPS);
    let amount_b = NoteAmount::from(TRANSFER_STROOPS);
    pool_a.deposit(amount_a).await?;
    pool_b.deposit(amount_b).await?;
    pool_b.deposit(amount_b).await?;

    let portfolio = session.account.portfolio().await?;
    assert_eq!(portfolio.len(), 2, "both deployed pools should be reported");

    let entry_a = portfolio
        .iter()
        .find(|entry| entry.pool_contract_id == pool_a.config().pool_contract_id)
        .context("pool_a missing from portfolio")?;
    assert_eq!(entry_a.amount, amount_a);
    assert_eq!(entry_a.note_count, 1);

    let entry_b = portfolio
        .iter()
        .find(|entry| entry.pool_contract_id == pool_b.config().pool_contract_id)
        .context("pool_b missing from portfolio")?;
    assert_eq!(
        entry_b.amount,
        amount_b.checked_add(amount_b).context("two deposits fit")?
    );
    assert_eq!(entry_b.note_count, 2);

    let notes = session.account.user_notes(10).await?;
    assert_eq!(
        notes.len(),
        3,
        "user_notes should aggregate notes across both pools"
    );

    let notes_a = pool_a.notes().await?;
    assert_eq!(
        notes_a.len(),
        1,
        "fetching notes for pool_a must not include pool_b's notes"
    );
    assert!(
        notes_a
            .iter()
            .all(|note| note.pool_contract_id == pool_a.config().pool_contract_id)
    );

    let notes_b = pool_b.notes().await?;
    assert_eq!(
        notes_b.len(),
        2,
        "fetching notes for pool_b must not include pool_a's notes"
    );
    assert!(
        notes_b
            .iter()
            .all(|note| note.pool_contract_id == pool_b.config().pool_contract_id)
    );

    Ok(())
}

#[tokio::test]
async fn balance_native() -> Result<()> {
    let session = session(deploy_default().await?).await?;
    let funded_balance = session.account.balance(&AssetDescriptor::Native).await?;
    assert!(
        funded_balance > 0,
        "friendbot should have funded the account"
    );

    let deposit_amount = NoteAmount::from(DEPOSIT_STROOPS);
    session.pool()?.deposit(deposit_amount).await?;

    let balance_after_deposit = session.account.balance(&AssetDescriptor::Native).await?;
    assert!(
        balance_after_deposit <= funded_balance.saturating_sub(DEPOSIT_STROOPS),
        "depositing {DEPOSIT_STROOPS} stroops (plus fees) should reduce the classical balance"
    );

    Ok(())
}

#[tokio::test]
async fn balance_classic() -> Result<()> {
    let session = session(deploy_default().await?).await?;
    let network = LocalNetwork::shared().await?;

    network
        .establish_trustline(&session.wallet.secret(), "TEST")
        .await?;

    const PAYMENT_STROOPS: u128 = 4_200_000;
    network
        .send_classic_payment(&session.wallet.address(), "TEST", PAYMENT_STROOPS)
        .await?;

    let balance = session
        .account
        .balance(&AssetDescriptor::Classic {
            code: "TEST".to_string(),
            issuer: network.admin().address(),
        })
        .await?;
    assert_eq!(balance, PAYMENT_STROOPS);

    Ok(())
}

#[tokio::test]
async fn balance_contract() -> Result<()> {
    let session = session(deploy_default().await?).await?;
    let network = LocalNetwork::shared().await?;

    let contract_id = network.deploy_asset_sac("TOK").await?;
    network
        .establish_trustline(&session.wallet.secret(), "TOK")
        .await?;

    const PAYMENT_STROOPS: u128 = 1_300_000;
    network
        .send_classic_payment(&session.wallet.address(), "TOK", PAYMENT_STROOPS)
        .await?;

    let balance = session
        .account
        .balance(&AssetDescriptor::Contract {
            contract_id,
            symbol: "TOK".to_string(),
        })
        .await?;
    assert_eq!(balance, PAYMENT_STROOPS);

    Ok(())
}
