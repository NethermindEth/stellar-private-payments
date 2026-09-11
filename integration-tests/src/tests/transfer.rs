//! Transfers between two wallets on a real pool contract, checking both
//! balances afterward.

use anyhow::{Context, Result};
use stellar_private_payments::types::{NoteAmount, TransferRecipient};

use super::support::setup;

const DEPOSIT_STROOPS: u128 = 10_000_000; // 1 XLM
const TRANSFER_STROOPS: u128 = 4_000_000;

#[tokio::test]
async fn transfer_via_address() -> Result<()> {
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

    let sender_balance = sender.pool()?.balance().await?;
    assert_eq!(
        sender_balance,
        deposit_amount
            .checked_sub(transfer_amount)
            .context("transfer amount fits within deposit")?
    );

    let recipient_balance = recipient.pool()?.balance().await?;
    assert_eq!(recipient_balance, transfer_amount);

    Ok(())
}

#[tokio::test]
async fn transfer_via_keys() -> Result<()> {
    let sender = setup().await?;
    let recipient = setup().await?;
    let (note_public_key, encryption_public_key) = recipient.account.user_public_keys().await?;

    let deposit_amount = NoteAmount::from(DEPOSIT_STROOPS);
    let transfer_amount = NoteAmount::from(TRANSFER_STROOPS);

    sender.pool()?.deposit(deposit_amount).await?;
    sender
        .pool()?
        .transfer(
            TransferRecipient::keys(note_public_key, encryption_public_key),
            transfer_amount,
        )
        .await?;

    let sender_balance = sender.pool()?.balance().await?;
    assert_eq!(
        sender_balance,
        deposit_amount
            .checked_sub(transfer_amount)
            .context("transfer amount fits within deposit")?
    );

    let recipient_balance = recipient.pool()?.balance().await?;
    assert_eq!(recipient_balance, transfer_amount);

    Ok(())
}
