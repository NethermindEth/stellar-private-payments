//! Transfers between two wallets on a real pool contract, checking both
//! balances afterward, plus the ways a transfer can be rejected.

use anyhow::{Context, Result};
use stellar_private_payments::types::{NoteAmount, TransferRecipient};

use super::support::{deploy_default, session};

const DEPOSIT_STROOPS: u128 = 10_000_000; // 1 XLM
const TRANSFER_STROOPS: u128 = 4_000_000;

#[tokio::test]
async fn transfer_via_address() -> Result<()> {
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
    let config = deploy_default().await?;
    let sender = session(config.clone()).await?;
    let recipient = session(config).await?;
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

#[tokio::test]
async fn transfer_insufficient_balance() -> Result<()> {
    let config = deploy_default().await?;
    let sender = session(config.clone()).await?;
    let recipient = session(config).await?;
    recipient.account.register_public_keys(None, None).await?;

    sender
        .pool()?
        .deposit(NoteAmount::from(DEPOSIT_STROOPS))
        .await?;

    let transfer = sender
        .pool()?
        .transfer(
            recipient.wallet.address(),
            NoteAmount::from(DEPOSIT_STROOPS.saturating_add(1)),
        )
        .await;
    assert!(
        transfer.is_err(),
        "transferring more than the wallet's pool balance must be rejected"
    );

    Ok(())
}

#[tokio::test]
async fn transfer_unregistered_recipient() -> Result<()> {
    let config = deploy_default().await?;
    let sender = session(config.clone()).await?;
    let recipient = session(config).await?;

    sender
        .pool()?
        .deposit(NoteAmount::from(DEPOSIT_STROOPS))
        .await?;

    let transfer = sender
        .pool()?
        .transfer(
            recipient.wallet.address(),
            NoteAmount::from(TRANSFER_STROOPS),
        )
        .await;
    assert!(
        transfer.is_err(),
        "transferring to an address with no registered public keys must be rejected"
    );

    Ok(())
}

#[tokio::test]
async fn transfer_double_spend() -> Result<()> {
    let config = deploy_default().await?;
    let sender = session(config.clone()).await?;
    let recipient = session(config).await?;
    recipient.account.register_public_keys(None, None).await?;
    let pool = sender.pool()?;

    pool.deposit(NoteAmount::from(DEPOSIT_STROOPS)).await?;

    let wallet = pool.spendable_notes().await?;
    assert_eq!(
        wallet.len(),
        1,
        "a single deposit should produce exactly one spendable note"
    );

    let half = NoteAmount::from(DEPOSIT_STROOPS / 2);
    let recipient_address = recipient.wallet.address();

    let mut plan_a = pool
        .prepare_transfer(&wallet, recipient_address.as_str(), half)
        .await?;
    let prepared_a = pool.prove_next(&mut plan_a).await?;
    let signed_a = pool.sign(&prepared_a).await?;
    let hash_a = pool.submit(signed_a).await?;
    pool.confirm(&hash_a).await?;

    let mut plan_b = pool
        .prepare_transfer(&wallet, recipient_address.as_str(), half)
        .await?;
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
