//! Deposits, transfers and withdrawals on a pool whose token is a classic
//! asset, which an account holds in a trustline, plus the refusals for an
//! account that has no trustline or too little in it.

use anyhow::Result;
use stellar_private_payments::{
    Error,
    types::{ContractConfig, NoteAmount, TransferRecipient},
};

use super::support::{FEE_STROOPS, TestSession, deploy_classic, note_states, session};
use crate::{
    keypair::TestKeypair,
    network::{CLASSIC_ASSET_CODE, ClassicAsset, DeploymentIdentity, LocalNetwork},
};

const FUNDED: u128 = 50_000_000;
const DEPOSIT: u128 = 10_000_000;
const TRANSFER: u128 = 4_000_000;

/// A wallet session whose account holds `amount` of `asset` in a trustline.
async fn funded_session(
    deployment: (ContractConfig, DeploymentIdentity),
    asset: &ClassicAsset,
    amount: u128,
) -> Result<TestSession> {
    let session = session(deployment).await?;
    let network = LocalNetwork::start().await?;
    network
        .trust_classic_asset(&session.wallet.secret(), asset)
        .await?;
    if amount > 0 {
        network
            .pay_classic_asset(asset, &session.wallet.address(), amount)
            .await?;
    }
    Ok(session)
}

#[tokio::test]
async fn classic_deposit() -> Result<()> {
    let (deployment, asset) = deploy_classic().await?;
    let session = funded_session(deployment, &asset, FUNDED).await?;
    let pool = session.pool()?;

    pool.deposit(NoteAmount::from(DEPOSIT)).await?;

    assert_eq!(pool.balance().await?, NoteAmount::from(DEPOSIT));
    assert_eq!(
        session.account.balance(&asset.descriptor()).await?,
        FUNDED - DEPOSIT - FEE_STROOPS,
        "the deposit and its fee leave the trustline"
    );

    Ok(())
}

#[tokio::test]
async fn classic_transfer() -> Result<()> {
    let (deployment, asset) = deploy_classic().await?;
    let sender = funded_session(deployment.clone(), &asset, FUNDED).await?;
    // Notes need no trustline: only the pool's token contract moves the asset.
    let recipient = session(deployment).await?;
    let (note_public_key, encryption_public_key) = recipient.account.privacy_keys().await?;

    sender.pool()?.deposit(NoteAmount::from(DEPOSIT)).await?;
    sender
        .pool()?
        .transfer(
            TransferRecipient::keys(note_public_key, encryption_public_key),
            NoteAmount::from(TRANSFER),
        )
        .await?;

    assert_eq!(
        sender.pool()?.balance().await?,
        NoteAmount::from(DEPOSIT - TRANSFER - FEE_STROOPS)
    );
    assert_eq!(
        recipient.pool()?.balance().await?,
        NoteAmount::from(TRANSFER)
    );

    Ok(())
}

#[tokio::test]
async fn classic_withdraw() -> Result<()> {
    let (deployment, asset) = deploy_classic().await?;
    let session = funded_session(deployment, &asset, FUNDED).await?;
    let pool = session.pool()?;

    pool.deposit(NoteAmount::from(DEPOSIT)).await?;
    pool.withdraw(
        NoteAmount::from(DEPOSIT - FEE_STROOPS),
        session.wallet.address(),
    )
    .await?;

    assert_eq!(pool.balance().await?, NoteAmount::ZERO);
    assert_eq!(
        session.account.balance(&asset.descriptor()).await?,
        FUNDED - 2 * FEE_STROOPS,
        "the withdrawal returns the deposit less the two pool fees"
    );

    Ok(())
}

/// The asset's contract traps on a transfer from an account with no trustline
/// (its error 13), so the deposit is refused before a proof is built.
#[tokio::test]
async fn classic_deposit_without_trustline() -> Result<()> {
    let (deployment, _asset) = deploy_classic().await?;
    let session = session(deployment).await?;
    let pool = session.pool()?;
    let amount = NoteAmount::from(DEPOSIT);

    let checked = pool.check_deposit(amount).await;
    assert!(
        matches!(checked, Err(Error::TrustlineMissing { ref code, .. }) if code == CLASSIC_ASSET_CODE),
        "the check must name the missing trustline: {checked:?}"
    );
    let refused = pool.deposit(amount).await;
    assert!(
        matches!(refused, Err(Error::TrustlineMissing { ref code, .. }) if code == CLASSIC_ASSET_CODE),
        "the deposit must name the missing trustline: {refused:?}"
    );
    assert_eq!(
        session.transaction_prompts(),
        0,
        "a deposit refused before proving must never reach the wallet"
    );
    assert!(pool.notes().await?.is_empty());

    Ok(())
}

/// A trustline that holds the deposit but not its fee (the asset contract's
/// error 10).
#[tokio::test]
async fn classic_deposit_above_trustline_balance() -> Result<()> {
    let (deployment, asset) = deploy_classic().await?;
    let session = funded_session(deployment, &asset, DEPOSIT).await?;
    let pool = session.pool()?;

    let refused = pool.deposit(NoteAmount::from(DEPOSIT)).await;
    match refused {
        Err(Error::InsufficientBalance { needed, available }) => {
            assert_eq!(needed, NoteAmount::from(DEPOSIT + FEE_STROOPS));
            assert_eq!(available, NoteAmount::from(DEPOSIT));
        }
        other => panic!("the deposit must be refused for its balance: {other:?}"),
    }
    assert_eq!(
        session.transaction_prompts(),
        0,
        "a deposit refused before proving must never reach the wallet"
    );
    assert_eq!(session.account.balance(&asset.descriptor()).await?, DEPOSIT);

    Ok(())
}

/// The asset's contract cannot pay an account with no trustline, so the
/// withdrawal is refused before a proof is built and the note stays unspent.
#[tokio::test]
async fn classic_withdraw_to_account_without_trustline() -> Result<()> {
    let (deployment, asset) = deploy_classic().await?;
    let session = funded_session(deployment, &asset, FUNDED).await?;
    let pool = session.pool()?;
    let recipient = TestKeypair::generate();
    LocalNetwork::start()
        .await?
        .fund(&recipient.address())
        .await?;

    pool.deposit(NoteAmount::from(DEPOSIT)).await?;
    let notes_before = note_states(&pool).await?;

    let refused = pool
        .withdraw(NoteAmount::from(DEPOSIT - FEE_STROOPS), recipient.address())
        .await;
    assert!(
        matches!(refused, Err(Error::RecipientTrustlineMissing { ref code, .. }) if code == CLASSIC_ASSET_CODE),
        "the withdrawal must name the recipient's missing trustline: {refused:?}"
    );
    assert_eq!(
        session.transaction_prompts(),
        1,
        "only the deposit reaches the wallet"
    );
    assert_eq!(note_states(&pool).await?, notes_before);

    Ok(())
}
