//! PrivatePool per-step planning.

use crate::pool::{test_pool, test_recipient};
use stellar_private_payments_sdk::types::NoteAmount;

#[test]
fn transfer_two_steps() {
    let pool = test_pool(Some(&[2, 3, 5])).expect("test pool");

    let amount = NoteAmount::from(10u128);
    let recipient = test_recipient();

    let wallet = pool.wallet().expect("wallet");
    let estimate = pool.estimate(&wallet, amount).expect("estimate");
    assert_eq!(estimate.tx_count, 2, "expected two txs for transfer");

    let plan = pool
        .core()
        .prepare_transfer(&wallet, recipient, amount)
        .expect("prepare transfer");
    assert_eq!(plan.tx_count(), 2);
    assert_eq!(plan.current_tx(), 0);
    assert!(!plan.is_complete());
}
