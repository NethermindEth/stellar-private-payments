use anyhow::Result;
use stellar_private_payments::types::{AssetDescriptor, NoteAmount};

use super::support::setup;

const DEPOSIT_STROOPS: u128 = 10_000_000; // 1 XLM
const TRANSFER_STROOPS: u128 = 4_000_000;

#[tokio::test]
async fn user_notes_basic() -> Result<()> {
    let session = setup().await?;
    let deposit_amount = NoteAmount::from(DEPOSIT_STROOPS);
    session.pool()?.deposit(deposit_amount).await?;

    let notes = session.account.user_notes(10).await?;
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].amount, deposit_amount);

    let deposit_amount2 = NoteAmount::from(DEPOSIT_STROOPS.saturating_mul(2));
    session.pool()?.deposit(deposit_amount2).await?;
    let notes = session.account.user_notes(10).await?;
    assert_eq!(notes.len(), 2);
    assert_eq!(notes[0].amount, deposit_amount);

    Ok(())
}

#[tokio::test]
async fn user_notes_transfer() -> Result<()> {
    let sender = setup().await?;
    let recipient = setup().await?;
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
        1,
        "the deposit note was spent, leaving one change note"
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
async fn balance_native() -> Result<()> {
    let session = setup().await?;
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
async fn is_registered() -> Result<()> {
    let session = setup().await?;
    assert!(!session.account.is_registered().await?);

    session.account.register_public_keys(None, None).await?;
    assert!(session.account.is_registered().await?);

    Ok(())
}
