use anyhow::Result;
use stellar_private_payments::types::{NoteAmount, PolicyFlags};

use super::support::{deploy, session};
use crate::{
    network::LocalNetwork,
    pool::{PoolAsset, PoolOptions},
};

const DEPOSIT_STROOPS: u128 = 10_000_000; // 1 XLM

#[tokio::test]
async fn blocklist_block() -> Result<()> {
    let session = session(
        deploy(&[PoolOptions {
            policy_flags: PolicyFlags::BLOCKLIST,
            asset: PoolAsset::Native,
            ..PoolOptions::NONE
        }])
        .await?,
    )
    .await?;
    let pool = session.pool()?;

    let deposit_amount = NoteAmount::from(DEPOSIT_STROOPS);
    pool.deposit(deposit_amount).await?;
    let balance = pool.balance().await?;
    assert_eq!(balance, deposit_amount);

    let (note_public_key, _) = session.account.user_public_keys().await?;

    let network = LocalNetwork::shared().await?;
    network
        .insert_asp_non_membership_leaf(
            &pool.config().contract_config.asp_non_membership,
            note_public_key,
        )
        .await?;

    let blocked_deposit = pool.deposit(deposit_amount).await;
    assert!(
        blocked_deposit.is_err(),
        "a blocked wallet should not be able to deposit"
    );

    let balance_after_block = pool.balance().await?;
    assert_eq!(
        balance_after_block, balance,
        "the rejected deposit must not change the balance"
    );

    Ok(())
}

#[tokio::test]
async fn blocklist_unblock() -> Result<()> {
    let session = session(
        deploy(&[PoolOptions {
            policy_flags: PolicyFlags::BLOCKLIST,
            asset: PoolAsset::Native,
            ..PoolOptions::NONE
        }])
        .await?,
    )
    .await?;
    let pool = session.pool()?;

    let (note_public_key, _) = session.account.user_public_keys().await?;

    let network = LocalNetwork::shared().await?;
    network
        .insert_asp_non_membership_leaf(
            &pool.config().contract_config.asp_non_membership,
            note_public_key.clone(),
        )
        .await?;

    let deposit_amount = NoteAmount::from(DEPOSIT_STROOPS);
    let blocked_deposit = pool.deposit(deposit_amount).await;
    assert!(
        blocked_deposit.is_err(),
        "a blocked wallet should not be able to deposit"
    );

    let balance_after_block = pool.balance().await?;
    assert_eq!(
        balance_after_block,
        0.into(),
        "the rejected deposit must not change the balance"
    );

    network
        .delete_asp_non_membership_leaf(
            &pool.config().contract_config.asp_non_membership,
            note_public_key,
        )
        .await?;

    pool.deposit(deposit_amount).await?;
    let balance = pool.balance().await?;
    assert_eq!(balance, deposit_amount);

    Ok(())
}

#[tokio::test]
async fn allowlist() -> Result<()> {
    let session = session(
        deploy(&[PoolOptions {
            policy_flags: PolicyFlags::ALLOWLIST,
            asset: PoolAsset::Native,
            ..PoolOptions::NONE
        }])
        .await?,
    )
    .await?;
    let pool = session.pool()?;

    let deposit_amount = NoteAmount::from(DEPOSIT_STROOPS);
    let blocked_deposit = pool.deposit(deposit_amount).await;
    assert!(
        blocked_deposit.is_err(),
        "a blocked wallet should not be able to deposit"
    );

    let balance_after_block = pool.balance().await?;
    assert_eq!(
        balance_after_block,
        0.into(),
        "the rejected deposit must not change the balance"
    );

    let leaf = session.account.derive_asp_user_leaf().await?;

    let network = LocalNetwork::shared().await?;
    network
        .insert_asp_membership_leaf(&pool.config().contract_config.asp_membership, leaf)
        .await?;

    pool.deposit(deposit_amount).await?;
    let balance = pool.balance().await?;
    assert_eq!(balance, deposit_amount);

    Ok(())
}

#[tokio::test]
async fn none() -> Result<()> {
    let session = session(deploy(&[PoolOptions::NONE]).await?).await?;
    let pool = session.pool()?;

    let deposit_amount = NoteAmount::from(DEPOSIT_STROOPS);
    pool.deposit(deposit_amount).await?;
    let balance = pool.balance().await?;
    assert_eq!(balance, deposit_amount);

    Ok(())
}

#[tokio::test]
async fn none_unblockable() -> Result<()> {
    let session = session(
        deploy(&[
            PoolOptions::NONE,
            PoolOptions {
                policy_flags: PolicyFlags::BLOCKLIST,
                asset: PoolAsset::Native,
                ..PoolOptions::NONE
            },
        ])
        .await?,
    )
    .await?;
    let pool = session.pool_at(0)?;
    let network = LocalNetwork::shared().await?;

    // add to blocklist
    let (note_public_key, _) = session.account.user_public_keys().await?;
    network
        .insert_asp_non_membership_leaf(
            &pool.config().contract_config.asp_non_membership,
            note_public_key,
        )
        .await?;

    // deposit on none pool
    let deposit_amount = NoteAmount::from(DEPOSIT_STROOPS);
    pool.deposit(deposit_amount).await?;
    let balance = pool.balance().await?;
    assert_eq!(balance, deposit_amount);

    Ok(())
}

#[tokio::test]
async fn allowlist_unblockable() -> Result<()> {
    let session = session(
        deploy(&[
            PoolOptions {
                policy_flags: PolicyFlags::ALLOWLIST,
                asset: PoolAsset::Native,
                ..PoolOptions::NONE
            },
            PoolOptions {
                policy_flags: PolicyFlags::BLOCKLIST,
                asset: PoolAsset::Native,
                ..PoolOptions::NONE
            },
        ])
        .await?,
    )
    .await?;
    let pool = session.pool_at(0)?;
    let network = LocalNetwork::shared().await?;

    // add to allowlist
    let leaf = session.account.derive_asp_user_leaf().await?;
    network
        .insert_asp_membership_leaf(&pool.config().contract_config.asp_membership, leaf)
        .await?;

    // add to blocklist
    let (note_public_key, _) = session.account.user_public_keys().await?;
    network
        .insert_asp_non_membership_leaf(
            &pool.config().contract_config.asp_non_membership,
            note_public_key,
        )
        .await?;

    // deposit on allowlist pool
    let deposit_amount = NoteAmount::from(DEPOSIT_STROOPS);
    pool.deposit(deposit_amount).await?;
    let balance = pool.balance().await?;
    assert_eq!(balance, deposit_amount);

    Ok(())
}

#[tokio::test]
async fn none_allowed() -> Result<()> {
    let session = session(
        deploy(&[
            PoolOptions::NONE,
            PoolOptions {
                policy_flags: PolicyFlags::ALLOWLIST,
                asset: PoolAsset::Native,
                ..PoolOptions::NONE
            },
        ])
        .await?,
    )
    .await?;
    let pool = session.pool_at(0)?;

    let deposit_amount = NoteAmount::from(DEPOSIT_STROOPS);
    pool.deposit(deposit_amount).await?;
    let balance = pool.balance().await?;
    assert_eq!(balance, deposit_amount);

    Ok(())
}

#[tokio::test]
async fn blocklist_allowed() -> Result<()> {
    let session = session(
        deploy(&[
            PoolOptions {
                policy_flags: PolicyFlags::BLOCKLIST,
                asset: PoolAsset::Native,
                ..PoolOptions::NONE
            },
            PoolOptions {
                policy_flags: PolicyFlags::ALLOWLIST,
                asset: PoolAsset::Native,
                ..PoolOptions::NONE
            },
        ])
        .await?,
    )
    .await?;
    let pool = session.pool_at(0)?;

    let deposit_amount = NoteAmount::from(DEPOSIT_STROOPS);
    pool.deposit(deposit_amount).await?;
    let balance = pool.balance().await?;
    assert_eq!(balance, deposit_amount);

    Ok(())
}

#[tokio::test]
async fn blocklist_per_user() -> Result<()> {
    let options = PoolOptions {
        policy_flags: PolicyFlags::BLOCKLIST,
        asset: PoolAsset::Native,
        ..PoolOptions::NONE
    };
    let config = deploy(std::slice::from_ref(&options)).await?;
    let alice = session(config.clone()).await?;
    let bob = session(config).await?;
    let network = LocalNetwork::shared().await?;

    let deposit_amount = NoteAmount::from(DEPOSIT_STROOPS);

    alice.pool()?.deposit(deposit_amount).await?;
    let alice_balance = alice.pool()?.balance().await?;
    assert_eq!(alice_balance, deposit_amount);

    bob.pool()?.deposit(deposit_amount).await?;
    let bob_balance = bob.pool()?.balance().await?;
    assert_eq!(bob_balance, deposit_amount);

    // block alice only
    let (alice_note_public_key, _) = alice.account.user_public_keys().await?;
    network
        .insert_asp_non_membership_leaf(
            &alice.pool()?.config().contract_config.asp_non_membership,
            alice_note_public_key,
        )
        .await?;

    let alice_blocked_deposit = alice.pool()?.deposit(deposit_amount).await;
    assert!(
        alice_blocked_deposit.is_err(),
        "a blocked wallet should not be able to deposit"
    );
    let alice_balance_after_block = alice.pool()?.balance().await?;
    assert_eq!(alice_balance_after_block, alice_balance);

    bob.pool()?.deposit(deposit_amount).await?;
    let bob_balance_after = bob.pool()?.balance().await?;
    assert_eq!(
        bob_balance_after,
        NoteAmount::from(DEPOSIT_STROOPS.saturating_mul(2)),
        "blocking alice should not affect bob"
    );

    Ok(())
}

#[tokio::test]
async fn allowlist_per_user() -> Result<()> {
    let options = PoolOptions {
        policy_flags: PolicyFlags::ALLOWLIST,
        asset: PoolAsset::Native,
        ..PoolOptions::NONE
    };
    let config = deploy(std::slice::from_ref(&options)).await?;
    let alice = session(config.clone()).await?;
    let bob = session(config).await?;
    let network = LocalNetwork::shared().await?;

    let deposit_amount = NoteAmount::from(DEPOSIT_STROOPS);

    let alice_not_allowed = alice.pool()?.deposit(deposit_amount).await;
    assert!(alice_not_allowed.is_err());
    assert_eq!(alice.pool()?.balance().await?, 0.into());

    let bob_not_allowed = bob.pool()?.deposit(deposit_amount).await;
    assert!(bob_not_allowed.is_err());
    assert_eq!(bob.pool()?.balance().await?, 0.into());

    // allow alice only
    let alice_leaf = alice.account.derive_asp_user_leaf().await?;
    network
        .insert_asp_membership_leaf(
            &alice.pool()?.config().contract_config.asp_membership,
            alice_leaf,
        )
        .await?;

    alice.pool()?.deposit(deposit_amount).await?;
    let alice_balance = alice.pool()?.balance().await?;
    assert_eq!(alice_balance, deposit_amount);

    let bob_still_not_allowed = bob.pool()?.deposit(deposit_amount).await;
    assert!(
        bob_still_not_allowed.is_err(),
        "allowing alice should not allow bob"
    );
    assert_eq!(bob.pool()?.balance().await?, 0.into());

    Ok(())
}

#[tokio::test]
async fn both() -> Result<()> {
    let session = session(
        deploy(&[PoolOptions {
            policy_flags: PolicyFlags::ALLOWLIST | PolicyFlags::BLOCKLIST,
            asset: PoolAsset::Native,
            ..PoolOptions::NONE
        }])
        .await?,
    )
    .await?;
    let pool = session.pool()?;
    let network = LocalNetwork::shared().await?;
    let deposit_amount = NoteAmount::from(DEPOSIT_STROOPS);

    let not_allowed_deposit = pool.deposit(deposit_amount).await;
    assert!(
        not_allowed_deposit.is_err(),
        "a wallet not on the allowlist should not be able to deposit"
    );

    let leaf = session.account.derive_asp_user_leaf().await?;
    network
        .insert_asp_membership_leaf(&pool.config().contract_config.asp_membership, leaf)
        .await?;

    pool.deposit(deposit_amount).await?;
    let balance = pool.balance().await?;
    assert_eq!(balance, deposit_amount);

    let (note_public_key, _) = session.account.user_public_keys().await?;
    network
        .insert_asp_non_membership_leaf(
            &pool.config().contract_config.asp_non_membership,
            note_public_key,
        )
        .await?;

    // blocklist takes precedence over allowlist membership
    let blocked_deposit = pool.deposit(deposit_amount).await;
    assert!(
        blocked_deposit.is_err(),
        "an allowed but blocked wallet should not be able to deposit"
    );

    let balance_after_block = pool.balance().await?;
    assert_eq!(
        balance_after_block, balance,
        "the rejected deposit must not change the balance"
    );

    Ok(())
}
