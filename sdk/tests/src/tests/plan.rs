//! PrivatePool per-step loop — plan first, then resolve each step for signing.

use std::path::Path;

use crate::{
    pool::{test_pool, test_recipient},
    seed,
};
use stellar_private_payments_sdk::types::NoteAmount;

#[test]
fn transfer_two_steps() {
    let mut pool = test_pool(Some(&[2, 3, 5])).expect("test pool");
    let storage_path = pool.config().storage_path.clone();
    let pool_contract_id = pool.config().pool_contract_id.clone();
    let asp_membership_contract_id = pool.config().contract_config.asp_membership.clone();
    let user_address = pool.config().user_address.clone();

    let amount = NoteAmount::from(10u128);
    let recipient = test_recipient();

    let estimate = pool.estimate(amount).expect("estimate");
    assert_eq!(estimate.tx_count, 2, "expected two txs for transfer");

    let mut plan = pool
        .prepare_transfer(recipient, amount)
        .expect("prepare transfer");
    assert_eq!(plan.tx_count(), 2);
    assert_eq!(plan.current_tx(), 0);
    assert!(!plan.is_complete());

    while !plan.is_complete() {
        let prepared = pool
            .next_prepared_transaction(&mut plan)
            .expect("prepare step");

        let chain = seed::apply_proved_step(
            Path::new(&storage_path),
            &pool_contract_id,
            &asp_membership_contract_id,
            &user_address,
            seed::TEST_NETWORK,
            &prepared,
        )
        .expect("apply prepared step to test wallet");
        pool.set_chain_context(chain);

        // submit() requires a real signed envelope XDR + live RPC (see
        // PrivatePool::submit).
    }

    assert!(plan.is_complete());
}
