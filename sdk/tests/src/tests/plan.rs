//! PrivatePool per-step loop — plan first, then resolve each step for signing.

use crate::pool::{test_pool, test_recipient};
use stellar_private_payments_sdk::{SignedTransaction, TransactChainContext, types::NoteAmount};
use types::Field;

#[test]
#[ignore = "requires prover artifacts and chain-aligned wallet seed"]
fn transfer_two_steps() {
    fn test_chain_context() -> TransactChainContext {
        TransactChainContext {
            pool_root: Field::ZERO,
            pool_next_index: 0,
            pool_merkle_levels: 20,
            asp_membership_root: Field::ZERO,
            asp_membership_contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
                .into(),
            asp_membership_ledger: 1,
            non_membership_proof: types::AspNonMembershipProof {
                key: Field::ZERO,
                old_key: Field::ZERO,
                old_value: Field::ZERO,
                is_old0: true,
                siblings: vec![Field::ZERO; types::SMT_DEPTH as usize],
                root: Field::ZERO,
            },
        }
    }

    let mut pool = test_pool(Some(&[2, 3, 5])).expect("test pool");
    pool.set_chain_context(test_chain_context());

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
            .expect("prove and prepare step");

        let signed = SignedTransaction {
            signed_xdr: format!("signed:{}", prepared.tx_xdr),
        };
        let result = pool.submit(signed).expect("submit step");
        assert_eq!(result.tx_hash, "stub-tx-hash");
    }

    assert!(plan.is_complete());
}
