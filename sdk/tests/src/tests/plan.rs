//! PrivatePool per-step planning.

use crate::pool::{test_pool, test_recipient};
use stellar_private_payments::{Error, types::NoteAmount};

#[test]
fn transfer_two_steps() {
    let pool = test_pool(Some(&[2, 3, 5])).expect("test pool");

    let amount = NoteAmount::from(10u128);
    let recipient = test_recipient();

    let estimate = pool.estimate(amount, NoteAmount::ZERO).expect("estimate");
    assert_eq!(estimate.tx_count, 2, "expected two txs for transfer");

    let wallet = pool.spendable_notes().expect("spendable notes");
    let plan = pool
        .prepare_transfer(&wallet, recipient, amount, NoteAmount::ZERO)
        .expect("prepare transfer");
    assert_eq!(plan.tx_count(), 2);
    assert_eq!(plan.current_tx(), 0);
    assert!(!plan.is_complete());
}

#[test]
fn deposit_single_step_plan() {
    let pool = test_pool(Some(&[2, 3, 5])).expect("test pool");

    let plan = pool
        .prepare_deposit(NoteAmount::from(5u128))
        .expect("prepare deposit");

    assert_eq!(plan.tx_count(), 1);
    assert_eq!(plan.current_tx(), 0);
    assert!(!plan.is_complete());
}

#[test]
fn transfer_one_step_exact() {
    let pool = test_pool(Some(&[10])).expect("test pool");

    let amount = NoteAmount::from(10u128);
    let estimate = pool.estimate(amount, NoteAmount::ZERO).expect("estimate");
    assert_eq!(estimate.tx_count, 1);

    let wallet = pool.spendable_notes().expect("spendable notes");
    let plan = pool
        .prepare_transfer(&wallet, test_recipient(), amount, NoteAmount::ZERO)
        .expect("prepare transfer");
    assert_eq!(plan.tx_count(), 1);
    assert!(!plan.is_complete());
}

#[test]
fn withdraw_single_step() {
    let pool = test_pool(Some(&[10])).expect("test pool");

    let amount = NoteAmount::from(10u128);
    let wallet = pool.spendable_notes().expect("spendable notes");
    let plan = pool
        .prepare_withdraw(
            &wallet,
            amount,
            pool.config().user_address.as_str().to_string(),
            NoteAmount::ZERO,
        )
        .expect("prepare withdraw");

    assert_eq!(plan.tx_count(), 1);
    assert_eq!(plan.current_tx(), 0);
    assert!(!plan.is_complete());
}

/// A `SpendSession(_)` match also passes for an empty wallet. `PlanError` is
/// not exported, so the `Debug` form names the variant.
#[test]
fn transfer_insufficient_funds() {
    let pool = test_pool(Some(&[2, 3])).expect("test pool");

    let wallet = pool.spendable_notes().expect("spendable notes");
    let err = pool
        .prepare_transfer(
            &wallet,
            test_recipient(),
            NoteAmount::from(100u128),
            NoteAmount::ZERO,
        )
        .expect_err("transfer above wallet sum should not plan");

    assert_eq!(format!("{err:?}"), "SpendSession(Plan(NoCombination))");
}

/// Three notes of 10 at fee 1 take two steps: 28 is the most one spend can
/// send, its estimate charges two fees, and 29 does not plan.
#[test]
fn withdraw_max_spend_plans_and_one_more_does_not() {
    let pool = test_pool(Some(&[10, 10, 10])).expect("test pool");
    let fee = NoteAmount::ONE;
    let recipient = pool.config().user_address.as_str().to_string();

    let max = pool.max_spend(fee).expect("max spend");
    assert_eq!(max, NoteAmount::from(28u128));
    let estimate = pool.estimate(max, fee).expect("estimate");
    assert_eq!(estimate.fees, NoteAmount::from(2u128));

    let wallet = pool.spendable_notes().expect("spendable notes");
    pool.prepare_withdraw(&wallet, max, recipient.clone(), fee)
        .expect("max spend plans");
    let err = pool
        .prepare_withdraw(&wallet, NoteAmount::from(29u128), recipient, fee)
        .expect_err("one unit more does not plan");
    assert!(matches!(err, Error::SpendSession(_)));
}

#[test]
fn estimate_empty_wallet() {
    let pool = test_pool(Some(&[])).expect("test pool");

    let err = pool
        .estimate(NoteAmount::from(10u128), NoteAmount::ZERO)
        .expect_err("empty wallet should not estimate");

    assert!(matches!(err, Error::Plan(_)));
}

#[test]
fn prepare_deposit_zero() {
    let pool = test_pool(Some(&[])).expect("test pool");

    let err = pool
        .prepare_deposit(NoteAmount::ZERO)
        .expect_err("zero deposit should not plan");

    assert!(matches!(err, Error::InvalidConfig(_)));
}

#[test]
fn transfer_zero() {
    let pool = test_pool(Some(&[10])).expect("test pool");

    let wallet = pool.spendable_notes().expect("spendable notes");
    let err = pool
        .prepare_transfer(
            &wallet,
            test_recipient(),
            NoteAmount::ZERO,
            NoteAmount::ZERO,
        )
        .expect_err("zero transfer should not plan");

    assert!(matches!(err, Error::InvalidConfig(_)));
}

#[test]
fn withdraw_zero() {
    let pool = test_pool(Some(&[])).expect("test pool");

    let err = pool
        .prepare_withdraw(
            &[],
            NoteAmount::ZERO,
            pool.config().user_address.as_str().to_string(),
            NoteAmount::ZERO,
        )
        .expect_err("zero withdraw should not plan");

    assert!(matches!(err, Error::InvalidConfig(_)));
}
