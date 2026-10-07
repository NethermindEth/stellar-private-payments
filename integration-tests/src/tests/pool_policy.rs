use anyhow::Result;
use stellar_private_payments::{
    CircuitStore, Client, LocalProver, LocalSigner,
    types::{
        NoteAmount, NoteOwnerAddress, NotePublicKey, PolicyFlags, SignerAddress, TreeConfigEntry,
    },
};

use super::support::{deploy, deploy_scoped, session};
use crate::{
    network::{LocalNetwork, NETWORK_PASSPHRASE, lock_asp_tree, repo_root},
    pool::{PoolAsset, PoolOptions},
};

const DEPOSIT_STROOPS: u128 = 10_000_000; // 1 XLM

/// Membership tree depth the suite deploys with.
const ASP_LEVELS: u32 = 10;

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
    let _lock = lock_asp_tree(&pool.config().contract_config.asp_non_membership).await?;

    let deposit_amount = NoteAmount::from(DEPOSIT_STROOPS);
    pool.deposit(deposit_amount).await?;
    let balance = pool.balance().await?;
    assert_eq!(balance, deposit_amount);

    let (note_public_key, _) = session.account.privacy_keys().await?;

    let network = LocalNetwork::start().await?;
    network
        .insert_asp_non_membership_leaf(
            &pool.config().contract_config.asp_non_membership,
            &session.identity.admin_secret,
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
    let _lock = lock_asp_tree(&pool.config().contract_config.asp_non_membership).await?;

    let (note_public_key, _) = session.account.privacy_keys().await?;

    let network = LocalNetwork::start().await?;
    network
        .insert_asp_non_membership_leaf(
            &pool.config().contract_config.asp_non_membership,
            &session.identity.admin_secret,
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
            &session.identity.admin_secret,
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

    let network = LocalNetwork::start().await?;
    network
        .insert_asp_membership_leaf(
            &pool.config().contract_config.asp_membership,
            &session.identity.admin_secret,
            leaf,
        )
        .await?;

    pool.deposit(deposit_amount).await?;
    let balance = pool.balance().await?;
    assert_eq!(balance, deposit_amount);

    Ok(())
}

#[tokio::test]
async fn allowlist_repoint() -> Result<()> {
    let options = PoolOptions {
        policy_flags: PolicyFlags::ALLOWLIST,
        asset: PoolAsset::Native,
        ..PoolOptions::NONE
    };
    // Scoped: re-pointing a shared pool would break tests that use the
    // manifest's allowlist.
    let (config, identity) =
        deploy_scoped(std::slice::from_ref(&options), "allowlist-repoint").await?;
    let session = session((config.clone(), identity)).await?;
    let pool = session.pool()?;
    let pool_contract_id = &pool.config().pool_contract_id;
    let admin_secret = &session.identity.admin_secret;
    let network = LocalNetwork::start().await?;
    let deposit_amount = NoteAmount::from(DEPOSIT_STROOPS);

    let leaf = session.account.derive_asp_user_leaf().await?;
    network
        .insert_asp_membership_leaf(&config.asp_membership, admin_secret, leaf)
        .await?;
    pool.deposit(deposit_amount).await?;

    let (allowlist, deployment_ledger) = network
        .deploy_asp_membership(admin_secret, ASP_LEVELS)
        .await?;
    network
        .insert_asp_membership_leaf(&allowlist, admin_secret, leaf)
        .await?;
    network
        .update_asp_membership(pool_contract_id, admin_secret, &allowlist)
        .await?;

    let unnamed = pool
        .withdraw(deposit_amount, session.wallet.address())
        .await;
    assert!(
        unnamed
            .as_ref()
            .is_err_and(|e| e.to_string().contains("add it to added_asp_memberships")),
        "a manifest without the pool's allowlist must be refused: {unnamed:?}"
    );

    let stem = config.pool(pool_contract_id)?.circuit_stem();
    let mut named = config;
    named.added_asp_memberships.push(TreeConfigEntry {
        contract_id: allowlist,
        deployment_ledger,
    });
    let lock = stellar_private_payments::circuit_lock(&std::fs::read_to_string(
        repo_root().join("deployments/testnet/circuits.json"),
    )?)?;
    let artifacts = CircuitStore::open(repo_root().join("target/circuits-artifacts"), lock)
        .artifacts(&stem.to_string())?;
    let client = Client::init(
        network.rpc_url(),
        session.account.storage().fork()?,
        LocalProver::from_artifacts(&[(stem, artifacts)])?.into(),
        named,
        None,
    )?;
    let signer = LocalSigner::new(
        &session.wallet.secret(),
        NETWORK_PASSPHRASE,
        SignerAddress::new(session.wallet.address()),
    )?;
    let named_pool = client
        .account(
            NoteOwnerAddress::new(session.wallet.address()),
            signer.into(),
        )?
        .pool(pool_contract_id)?;
    named_pool
        .withdraw(deposit_amount, session.wallet.address())
        .await?;
    assert_eq!(named_pool.balance().await?, 0.into());

    Ok(())
}

#[tokio::test]
async fn blocklist_repoint() -> Result<()> {
    let options = PoolOptions {
        policy_flags: PolicyFlags::BLOCKLIST,
        asset: PoolAsset::Native,
        ..PoolOptions::NONE
    };
    // Scoped: re-pointing a shared pool would break tests that use the
    // manifest's blocklist.
    let (config, identity) =
        deploy_scoped(std::slice::from_ref(&options), "blocklist-repoint").await?;
    let session = session((config.clone(), identity)).await?;
    let pool = session.pool()?;
    let pool_contract_id = &pool.config().pool_contract_id;
    let admin_secret = &session.identity.admin_secret;
    let network = LocalNetwork::start().await?;
    let deposit_amount = NoteAmount::from(DEPOSIT_STROOPS);
    pool.deposit(deposit_amount).await?;

    let (note_public_key, _) = session.account.privacy_keys().await?;
    network
        .insert_asp_non_membership_leaf(
            &config.asp_non_membership,
            admin_secret,
            note_public_key.clone(),
        )
        .await?;
    let blocklist = network.deploy_asp_non_membership(admin_secret).await?;
    // A nonzero root makes the client query the tree, not assume it empty.
    network
        .insert_asp_non_membership_leaf(&blocklist, admin_secret, NotePublicKey([1; 32]))
        .await?;
    network
        .update_asp_non_membership(pool_contract_id, admin_secret, &blocklist)
        .await?;
    // A blocklist pool never proves against its allowlist, so an unnamed
    // allowlist must not stop the client.
    let (allowlist, _) = network
        .deploy_asp_membership(admin_secret, ASP_LEVELS)
        .await?;
    network
        .update_asp_membership(pool_contract_id, admin_secret, &allowlist)
        .await?;

    // The manifest still names the blocklist that lists the user, but the pool
    // reads the new one, which does not.
    pool.withdraw(deposit_amount, session.wallet.address())
        .await?;
    assert_eq!(pool.balance().await?, 0.into());

    network
        .insert_asp_non_membership_leaf(&blocklist, admin_secret, note_public_key)
        .await?;
    let blocked = pool.deposit(deposit_amount).await;
    assert!(
        blocked
            .as_ref()
            .is_err_and(|e| e.to_string().contains("user is blocklisted")),
        "a key in the pool's new blocklist must be refused: {blocked:?}"
    );

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
    let network = LocalNetwork::start().await?;

    // add to blocklist
    let (note_public_key, _) = session.account.privacy_keys().await?;
    network
        .insert_asp_non_membership_leaf(
            &pool.config().contract_config.asp_non_membership,
            &session.identity.admin_secret,
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
    let network = LocalNetwork::start().await?;

    // add to allowlist
    let leaf = session.account.derive_asp_user_leaf().await?;
    network
        .insert_asp_membership_leaf(
            &pool.config().contract_config.asp_membership,
            &session.identity.admin_secret,
            leaf,
        )
        .await?;

    // add to blocklist
    let (note_public_key, _) = session.account.privacy_keys().await?;
    network
        .insert_asp_non_membership_leaf(
            &pool.config().contract_config.asp_non_membership,
            &session.identity.admin_secret,
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
    let deployment = deploy(std::slice::from_ref(&options)).await?;
    let alice = session(deployment.clone()).await?;
    let bob = session(deployment).await?;
    let network = LocalNetwork::start().await?;
    let _lock = lock_asp_tree(&alice.pool()?.config().contract_config.asp_non_membership).await?;

    let deposit_amount = NoteAmount::from(DEPOSIT_STROOPS);

    alice.pool()?.deposit(deposit_amount).await?;
    let alice_balance = alice.pool()?.balance().await?;
    assert_eq!(alice_balance, deposit_amount);

    bob.pool()?.deposit(deposit_amount).await?;
    let bob_balance = bob.pool()?.balance().await?;
    assert_eq!(bob_balance, deposit_amount);

    // block alice only
    let (alice_note_public_key, _) = alice.account.privacy_keys().await?;
    network
        .insert_asp_non_membership_leaf(
            &alice.pool()?.config().contract_config.asp_non_membership,
            &alice.identity.admin_secret,
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
    let deployment = deploy(std::slice::from_ref(&options)).await?;
    let alice = session(deployment.clone()).await?;
    let bob = session(deployment).await?;
    let network = LocalNetwork::start().await?;

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
            &alice.identity.admin_secret,
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
    let network = LocalNetwork::start().await?;
    let deposit_amount = NoteAmount::from(DEPOSIT_STROOPS);

    let not_allowed_deposit = pool.deposit(deposit_amount).await;
    assert!(
        not_allowed_deposit.is_err(),
        "a wallet not on the allowlist should not be able to deposit"
    );

    let leaf = session.account.derive_asp_user_leaf().await?;
    network
        .insert_asp_membership_leaf(
            &pool.config().contract_config.asp_membership,
            &session.identity.admin_secret,
            leaf,
        )
        .await?;

    pool.deposit(deposit_amount).await?;
    let balance = pool.balance().await?;
    assert_eq!(balance, deposit_amount);

    let (note_public_key, _) = session.account.privacy_keys().await?;
    network
        .insert_asp_non_membership_leaf(
            &pool.config().contract_config.asp_non_membership,
            &session.identity.admin_secret,
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
