//! History a bootnode withholds or alters, checked against the pool's own
//! state.
//!
//! The wallet's database stands in for history a bootnode served. The pool's
//! storage is the truth the main RPC reports. Where the two disagree, the
//! wallet must refuse to report or spend from that history, and must not ask
//! the RPC about its own nullifiers to find out where they differ.

use super::{
    deployment::FEE,
    offline_pool::{OWNER, OfflinePool},
};
use anyhow::Result;
use stellar_private_payments::{Error, types::NoteAmount};

/// The bootnode withholds the `NewNullifierEvent` of a spent note, so the
/// wallet still lists the note. A withdrawal of both notes must be refused
/// before proving, and so must the balance built on that history.
#[tokio::test]
async fn a_spend_of_a_note_spent_on_chain_is_refused_before_proving() -> Result<()> {
    let h = OfflinePool::builder()
        .notes(&[10, 20])
        .spent_on_chain(&[0])
        .build()
        .await?;
    // Both notes in one step, less the fee.
    let amount = NoteAmount::from(30 - u128::from(FEE));

    let result = h.pool.withdraw(amount, OWNER).await;

    assert!(
        matches!(result, Err(Error::EventHistoryIncomplete { .. })),
        "a withdrawal spending a note the pool reports spent went through: {result:?}"
    );
    assert_eq!(h.prover.calls(), 0);
    assert_eq!(h.rpc.count("sendTransaction").await, 0);
    let balance = h.pool.balance().await;
    assert!(
        matches!(balance, Err(Error::EventHistoryIncomplete { .. })),
        "a balance was reported from history missing a nullifier the pool holds: {balance:?}"
    );
    Ok(())
}

/// Asking the RPC whether a note is spent ties its nullifier to this wallet,
/// so the next spend of that note is linked to the owner. The pool's event
/// chain makes the question unnecessary: neither reads nor spends may ask, not
/// even to locate where the wallet's history differs from the pool's.
#[tokio::test]
async fn the_wallet_asks_the_rpc_about_no_nullifier() -> Result<()> {
    let h = OfflinePool::builder()
        .notes(&[10, 20])
        .spent_on_chain(&[0])
        .build()
        .await?;
    let amount = NoteAmount::from(30 - u128::from(FEE));

    // Only the requests matter here; the history does not match, so these may
    // fail.
    let _ = h.pool.balance().await;
    let _ = h.pool.notes().await;
    let _ = h.pool.spendable_notes().await;
    let _ = h.pool.withdraw(amount, OWNER).await;

    assert_eq!(h.rpc.nullifier_lookups().await, 0);
    Ok(())
}

/// The bootnode alters a `NewCommitmentEvent`, so the wallet holds a note the
/// pool's tree does not. The root no longer matches, and the wallet must not
/// report a balance built on that history.
#[tokio::test]
async fn a_balance_is_refused_when_a_commitment_differs_from_the_chain() -> Result<()> {
    let h = OfflinePool::builder()
        .notes(&[10, 20])
        .replaced_on_chain(&[1])
        .build()
        .await?;

    let result = h.pool.balance().await;

    assert!(
        matches!(result, Err(Error::EventHistoryMismatch { .. })),
        "a balance was reported from history whose root the pool does not hold: {result:?}"
    );
    Ok(())
}

/// The bootnode withholds `NewCommitmentEvent`s, so the wallet holds fewer
/// leaves than the pool. The wallet must not report a balance built on that
/// history.
#[tokio::test]
async fn a_balance_is_refused_when_commitments_are_missing() -> Result<()> {
    let h = OfflinePool::builder()
        .notes(&[10, 20])
        .extra_on_chain(2)
        .build()
        .await?;

    let result = h.pool.balance().await;

    assert!(
        matches!(result, Err(Error::EventHistoryIncomplete { .. })),
        "a balance was reported from history missing leaves the pool holds: {result:?}"
    );
    Ok(())
}

/// The bootnode alters the `encrypted_output` of a note sent to the wallet.
/// The commitment still matches the pool's tree, so the root does not notice,
/// but the wallet never finds the note and reports too little. It must not
/// report a balance built on that history.
#[tokio::test]
async fn a_balance_is_refused_when_a_ciphertext_differs_from_the_chain() -> Result<()> {
    let h = OfflinePool::builder()
        .notes(&[10, 20])
        .garbled_outputs(&[1])
        .build()
        .await?;

    let result = h.pool.balance().await;

    assert!(
        matches!(result, Err(Error::EventHistoryMismatch { .. })),
        "a balance was reported from history with a ciphertext the pool did not emit: {result:?}"
    );
    Ok(())
}

/// The bootnode withholds the `NewNullifierEvent` of another user's spend.
/// The wallet's own notes are untouched, but its history is incomplete and it
/// cannot tell whose event is missing, so it must not report a balance.
#[tokio::test]
async fn a_balance_is_refused_when_another_users_nullifier_is_missing() -> Result<()> {
    let h = OfflinePool::builder()
        .notes(&[10, 20])
        .foreign_spent_on_chain(1)
        .build()
        .await?;

    let result = h.pool.balance().await;

    assert!(
        matches!(result, Err(Error::EventHistoryIncomplete { .. })),
        "a balance was reported from history missing a nullifier the pool holds: {result:?}"
    );
    Ok(())
}

/// History that matches the pool raises no alarm: the wallet reports its
/// balance and spends.
#[tokio::test]
async fn a_wallet_whose_history_matches_the_pool_reads_and_spends() -> Result<()> {
    let h = OfflinePool::builder().notes(&[10, 20]).build().await?;
    let amount = NoteAmount::from(30 - u128::from(FEE));

    assert_eq!(h.pool.balance().await?, NoteAmount::from(30u128));
    h.pool.withdraw(amount, OWNER).await?;

    assert_eq!(h.prover.calls(), 1);
    assert_eq!(h.rpc.count("sendTransaction").await, 1);
    Ok(())
}

/// The pool holds events the wallet has not synced yet, and the RPC serves
/// them. The wallet catches up instead of reporting a mismatch.
#[tokio::test]
async fn a_wallet_behind_the_pool_catches_up_and_spends() -> Result<()> {
    let h = OfflinePool::builder()
        .notes(&[10, 20])
        .unsynced_on_chain(2)
        .build()
        .await?;
    let amount = NoteAmount::from(30 - u128::from(FEE));

    assert_eq!(h.pool.balance().await?, NoteAmount::from(30u128));
    h.pool.withdraw(amount, OWNER).await?;

    assert_eq!(h.prover.calls(), 1);
    assert_eq!(h.rpc.count("sendTransaction").await, 1);
    Ok(())
}

/// In the background, sync finds the altered event after a round, and the
/// next read reports it instead of a balance.
#[tokio::test]
async fn background_sync_reports_altered_history_to_the_next_read() -> Result<()> {
    let mut h = OfflinePool::builder()
        .notes(&[10, 20])
        .replaced_on_chain(&[1])
        .background_sync()
        .build()
        .await?;
    let background = h.background.take().expect("a background sync task");
    let stop = background.stop_handle();

    let reads = async {
        for _ in 0..50 {
            h.pool.balance().await?;
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        h.pool.balance().await
    };
    let (sync, result) = tokio::join!(background.run(), async {
        let result = reads.await;
        stop.request();
        result
    });

    sync?;
    assert!(
        matches!(result, Err(Error::EventHistoryMismatch { .. })),
        "a read after background sync found altered history: {result:?}"
    );
    Ok(())
}
