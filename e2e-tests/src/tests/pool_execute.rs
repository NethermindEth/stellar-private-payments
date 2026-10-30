//! [`PrivatePool`] plan execution, offline.
//!
//! Each test drives a public entry point through an [`OfflinePool`] and checks
//! the outcome and which chain-facing calls were made: a stage that fails must
//! stop every stage after it.
//!
//! [`PrivatePool`]: stellar_private_payments::PrivatePool

use super::offline_pool::{BuildParams, OWNER, OfflinePool, tx_hash};
use anyhow::Result;
use serde_json::json;
use stellar_private_payments::{
    Error,
    types::{AspMembershipSync, NoteAmount},
};

/// The calls that act on a transaction, in order. Reads (ledger entries,
/// events, the latest ledger) are left out.
async fn stages(pool: &OfflinePool) -> Vec<String> {
    pool.rpc
        .calls()
        .await
        .into_iter()
        .filter(|method| {
            matches!(
                method.as_str(),
                "simulateTransaction" | "sendTransaction" | "getTransaction"
            )
        })
        .collect()
}

const SIMULATE_SEND_CONFIRM: [&str; 3] =
    ["simulateTransaction", "sendTransaction", "getTransaction"];

#[tokio::test]
async fn a_deposit_is_simulated_sent_and_confirmed_once() -> Result<()> {
    let h = OfflinePool::builder().build().await?;

    let result = h.pool.deposit(NoteAmount::from(10u128)).await?;

    assert_eq!(result.tx_hash, tx_hash(0));
    assert_eq!(stages(&h).await, SIMULATE_SEND_CONFIRM);
    assert_eq!(h.storage.build_transact_params_calls(), 1);
    assert_eq!(h.prover.calls(), 1);
    assert_eq!(h.signer.calls(), 1);
    // One catch-up, before proving.
    assert_eq!(h.rpc.count("getLatestLedger").await, 1);
    Ok(())
}

#[tokio::test]
async fn a_deposit_waiting_for_sync_once_syncs_again_and_sends_once() -> Result<()> {
    let h = OfflinePool::builder().build().await?;
    h.storage
        .script_build_transact_params([BuildParams::SyncRequired]);

    let result = h.pool.deposit(NoteAmount::from(10u128)).await?;

    assert_eq!(result.tx_hash, tx_hash(0));
    assert_eq!(h.storage.build_transact_params_calls(), 2);
    assert_eq!(h.prover.calls(), 1);
    // Before each of the two attempts, and once more after the refusal.
    assert_eq!(h.rpc.count("getLatestLedger").await, 3);
    assert_eq!(stages(&h).await, SIMULATE_SEND_CONFIRM);
    Ok(())
}

/// Waits through `SYNC_MAX_RETRIES` (50) polls of `POLL_INTERVAL_MS` (200 ms),
/// so this test takes about ten seconds.
#[tokio::test]
async fn a_deposit_still_waiting_for_sync_after_the_last_retry_sends_nothing() -> Result<()> {
    let h = OfflinePool::builder().build().await?;
    h.storage
        .script_build_transact_params(vec![BuildParams::SyncRequired; 51]);

    let err = h
        .pool
        .deposit(NoteAmount::from(10u128))
        .await
        .expect_err("the retries run out");

    assert!(
        matches!(
            err,
            Error::MembershipSync(AspMembershipSync::SyncRequired(None))
        ),
        "{err:?}"
    );
    assert_eq!(h.storage.build_transact_params_calls(), 51);
    assert_eq!(h.prover.calls(), 0);
    assert!(stages(&h).await.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_prover_error_stops_the_deposit_before_simulation() -> Result<()> {
    let h = OfflinePool::builder().build().await?;
    h.prover.fail_next("prover crashed");

    let err = h
        .pool
        .deposit(NoteAmount::from(10u128))
        .await
        .expect_err("the prover fails");

    assert_eq!(err.to_string(), "prover crashed");
    assert!(stages(&h).await.is_empty());
    assert_eq!(h.signer.calls(), 0);
    Ok(())
}

#[tokio::test]
async fn a_failed_simulation_stops_the_deposit_before_signing() -> Result<()> {
    let h = OfflinePool::builder().build().await?;
    h.rpc.answer_next(
        "simulateTransaction",
        json!({ "latestLedger": 100, "error": "HostError: Error(Contract, #18)" }),
    );

    let err = h
        .pool
        .deposit(NoteAmount::from(10u128))
        .await
        .expect_err("the simulation fails");

    assert_eq!(
        format!("{err:#}"),
        "simulate transaction: transaction simulation failed: HostError: Error(Contract, #18)"
    );
    assert_eq!(stages(&h).await, ["simulateTransaction"]);
    assert_eq!(h.signer.calls(), 0);
    Ok(())
}

#[tokio::test]
async fn a_refused_signature_sends_nothing() -> Result<()> {
    let h = OfflinePool::builder().build().await?;
    h.signer.refuse_next();

    let err = h
        .pool
        .deposit(NoteAmount::from(10u128))
        .await
        .expect_err("the signer refuses");

    assert!(matches!(err, Error::UserRejected(_)), "{err:?}");
    assert_eq!(stages(&h).await, ["simulateTransaction"]);
    Ok(())
}

#[tokio::test]
async fn a_rejected_submission_is_not_confirmed() -> Result<()> {
    let h = OfflinePool::builder().build().await?;
    h.rpc.answer_next(
        "sendTransaction",
        json!({
            "hash": tx_hash(0),
            "status": "ERROR",
            "errorResultXdr": "AAAAAAAAAGT////7AAAAAA==",
            "latestLedger": 100,
        }),
    );

    let err = h
        .pool
        .deposit(NoteAmount::from(10u128))
        .await
        .expect_err("the submission is rejected");

    assert!(
        format!("{err:#}").contains("sendTransaction failed: AAAAAAAAAGT////7AAAAAA=="),
        "{err:#}"
    );
    assert_eq!(stages(&h).await, ["simulateTransaction", "sendTransaction"]);
    Ok(())
}

/// Polls once a second (`CONFIRM_POLL_INTERVAL_MS`), so this test takes about
/// two seconds.
#[tokio::test]
async fn a_pending_transaction_is_polled_until_it_succeeds() -> Result<()> {
    let h = OfflinePool::builder().build().await?;
    h.rpc
        .answer_next("getTransaction", json!({ "status": "PENDING" }));
    h.rpc
        .answer_next("getTransaction", json!({ "status": "PENDING" }));

    let result = h.pool.deposit(NoteAmount::from(10u128)).await?;

    assert_eq!(result.tx_hash, tx_hash(0));
    assert_eq!(
        stages(&h).await,
        [
            "simulateTransaction",
            "sendTransaction",
            "getTransaction",
            "getTransaction",
            "getTransaction",
        ]
    );
    Ok(())
}

#[tokio::test]
async fn a_transaction_that_failed_on_chain_fails_the_deposit() -> Result<()> {
    let h = OfflinePool::builder().build().await?;
    h.rpc.answer_next(
        "getTransaction",
        json!({ "status": "FAILED", "resultXdr": "AAAAAAAAAGT////7AAAAAA==" }),
    );

    let err = h
        .pool
        .deposit(NoteAmount::from(10u128))
        .await
        .expect_err("the transaction failed");

    assert_eq!(
        err.to_string(),
        "transaction failed (resultXdr: AAAAAAAAAGT////7AAAAAA==)"
    );
    // A final status is not polled again.
    assert_eq!(stages(&h).await, SIMULATE_SEND_CONFIRM);
    Ok(())
}

#[tokio::test]
async fn a_plan_failing_at_its_second_step_reports_the_first_as_completed() -> Result<()> {
    let h = OfflinePool::builder().notes(&[1, 2, 3, 5]).build().await?;
    let amount = NoteAmount::from(10u128);
    assert_eq!(h.pool.estimate(amount).await?.tx_count, 2);
    h.storage
        .script_build_transact_params([BuildParams::Real, BuildParams::Fail("step two broke")]);

    let err = h
        .pool
        .withdraw(amount, OWNER)
        .await
        .expect_err("the second step fails");

    let Error::PlanExecution(plan) = &err else {
        panic!("expected a plan execution error, got {err:?}");
    };
    let completed: Vec<&str> = plan.completed.iter().map(|r| r.tx_hash.as_str()).collect();
    assert_eq!(completed, [tx_hash(0)]);
    assert_eq!(plan.cause().to_string(), "step two broke");
    assert_eq!(
        err.to_string(),
        "plan failed after 1 confirmed transaction(s): step two broke"
    );
    assert_eq!(stages(&h).await, SIMULATE_SEND_CONFIRM);
    Ok(())
}

#[tokio::test]
async fn a_paused_pool_refuses_a_deposit_before_proving() -> Result<()> {
    let h = OfflinePool::builder().deposits_paused().build().await?;

    let err = h
        .pool
        .deposit(NoteAmount::from(10u128))
        .await
        .expect_err("deposits are paused");

    assert!(matches!(err, Error::DepositsPaused { .. }), "{err:?}");
    assert_eq!(h.storage.build_transact_params_calls(), 0);
    assert_eq!(h.prover.calls(), 0);
    assert!(stages(&h).await.is_empty());
    Ok(())
}
