//! One wallet used under several `kdf_domain`s: each domain derives its own
//! keys, and notes are only visible and spendable under the domain whose keys
//! they were sent to.

use anyhow::Result;
use stellar_private_payments::types::{ContractConfig, NoteAmount};

use super::support::{deploy_default, session};

const DEPOSIT_STROOPS: u128 = 10_000_000; // 1 XLM
const TRANSFER_STROOPS: u128 = 4_000_000;
const OTHER_DOMAIN: &str = "other-domain";

fn with_kdf_domain(mut config: ContractConfig, kdf_domain: &str) -> ContractConfig {
    config.kdf_domain = kdf_domain.to_string();
    config
}

#[tokio::test]
async fn notes_domain_scoped() -> Result<()> {
    let deployment = deploy_default().await?;
    let config = deployment.0.clone();
    let session_a = session(deployment).await?;
    let session_b = session_a
        .fork(with_kdf_domain(config, OTHER_DOMAIN))
        .await?;

    let deposit_amount = NoteAmount::from(DEPOSIT_STROOPS);
    session_a.pool()?.deposit(deposit_amount).await?;

    assert!(session_b.account.user_notes(10).await?.is_empty());
    assert!(session_b.pool()?.spendable_notes().await?.is_empty());
    assert!(
        session_b
            .account
            .portfolio()
            .await?
            .iter()
            .all(|balance| balance.amount == NoteAmount::ZERO)
    );

    let notes = session_a.account.user_notes(10).await?;
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].amount, deposit_amount);
    assert_eq!(session_a.pool()?.spendable_notes().await?.len(), 1);

    Ok(())
}

#[tokio::test]
async fn transfer_cross_domain() -> Result<()> {
    let deployment = deploy_default().await?;
    let config = deployment.0.clone();
    let sender = session(deployment.clone()).await?;
    let recipient_a = session(deployment).await?;
    let recipient_b = recipient_a
        .fork(with_kdf_domain(config, OTHER_DOMAIN))
        .await?;
    recipient_b.account.register_public_keys().await?;

    let deposit_amount = NoteAmount::from(DEPOSIT_STROOPS);
    let transfer_amount = NoteAmount::from(TRANSFER_STROOPS);
    sender.pool()?.deposit(deposit_amount).await?;
    sender
        .pool()?
        .transfer(recipient_b.wallet.address(), transfer_amount)
        .await?;

    let sender_notes = sender.account.user_notes(10).await?;
    assert_eq!(
        sender_notes[0].amount,
        deposit_amount
            .checked_sub(transfer_amount)
            .expect("transfer amount fits within deposit")
    );

    let recipient_notes = recipient_b.account.user_notes(10).await?;
    assert_eq!(recipient_notes.len(), 1);
    assert_eq!(recipient_notes[0].amount, transfer_amount);
    assert!(recipient_a.account.user_notes(10).await?.is_empty());

    Ok(())
}
