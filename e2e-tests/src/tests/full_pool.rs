//! A pool whose commitment tree runs out of leaves, with real proofs.
//!
//! Every `transact` inserts its two output commitments, withdrawals included,
//! so a full tree refuses every transaction and the funds still in the pool
//! cannot leave it. The app warns about this before it happens; these tests
//! pin the behaviour the warning describes.
//!
//! The pool keeps its real 20-level tree, since the circuits prove paths of
//! that depth. [`fast_forward_pool_tree`] moves the leaf counter to the end of
//! the tree instead of inserting a million leaves.

use super::utils::{
    LEVELS, TransactOutcome, deploy_contracts, fast_forward_pool_tree, prove_transaction,
    scalar_to_u256, sync_contract_state, test_env, transact,
};
use anyhow::Result;
use ark_bn254::Fr as Scalar;
use pool::{Error, PoolContractClient, merkle_with_history::MerkleTreeWithHistory};
use soroban_sdk::{Address, U256};

/// Leaves in the pool's tree.
const CAPACITY: u64 = 1 << LEVELS;

/// Proves a transaction, syncs the pool to the state it was made against,
/// moves the leaf counter to `next_index`, and sends it.
fn transact_at(
    in_amounts: [u64; 2],
    out_amounts: [u64; 2],
    ext_amount: i32,
    next_index: u64,
) -> Result<(TransactOutcome, u64)> {
    let env = test_env();
    env.mock_all_auths();
    let contracts = deploy_contracts(&env);
    let mut proven = prove_transaction(&env, &contracts, in_amounts, out_amounts, ext_amount, 0)?;
    let roots = sync_contract_state(
        &env,
        &contracts,
        &proven.case,
        &mut proven.leaves,
        &proven.membership_trees,
        &proven.witness,
    );
    fast_forward_pool_tree(&env, &contracts.pool, &proven.leaves, next_index);
    let ext_data = proven.ext_data.clone();
    let proof = proven.into_proof(&env, &roots);

    let outcome = transact(&env, &contracts, &proof, &ext_data);
    let state: pool::merkle_with_history::TreeState = env.as_contract(&contracts.pool, || {
        env.storage()
            .persistent()
            .get(&pool::merkle_with_history::MerkleDataKey::State)
            .expect("the pool stores its tree")
    });
    Ok((outcome, state.next_index))
}

/// The last two leaves take one more transaction, which leaves the tree full.
#[test]
#[cfg_attr(miri, ignore)]
fn a_real_withdrawal_takes_the_last_two_leaves() -> Result<()> {
    let (outcome, next_index) = transact_at([13, 0], [0, 0], -13, CAPACITY - 2)?;

    assert_eq!(outcome, Ok(Ok(())));
    assert_eq!(next_index, CAPACITY);
    Ok(())
}

/// A full tree refuses a deposit, a transfer and a withdrawal alike, each with
/// a valid proof, so funds left in the pool cannot be withdrawn.
#[test]
#[cfg_attr(miri, ignore)]
fn a_full_pool_refuses_every_real_transaction() -> Result<()> {
    let cases: [(&str, [u64; 2], [u64; 2], i32); 3] = [
        ("deposit", [0, 0], [13, 0], 13),
        ("transfer", [0, 13], [13, 0], 0),
        ("withdrawal", [13, 0], [0, 0], -13),
    ];
    for (name, in_amounts, out_amounts, ext_amount) in cases {
        let (outcome, next_index) = transact_at(in_amounts, out_amounts, ext_amount, CAPACITY)?;

        assert_eq!(
            outcome,
            Err(Ok(Error::MerkleTreeFull)),
            "a {name} on a full pool"
        );
        assert_eq!(next_index, CAPACITY, "a refused {name} inserts nothing");
    }
    Ok(())
}

/// A fast-forwarded pool builds the same tree as one that got there by
/// inserting empty leaves: every later insertion gives the same root.
#[test]
#[cfg_attr(miri, ignore)]
fn fast_forwarding_matches_inserting_empty_leaves() {
    let env = test_env();
    env.mock_all_auths();
    let real = deploy_contracts(&env).pool;
    let forwarded = deploy_contracts(&env).pool;
    let leaf = |value: u64| scalar_to_u256(&env, Scalar::from(value));
    let insert = |pool: &Address, left: U256, right: U256| {
        env.as_contract(pool, || {
            MerkleTreeWithHistory::insert_two_leaves(&env, left, right).expect("the tree has room")
        });
    };
    let root = |pool: &Address| PoolContractClient::new(&env, pool).get_root();

    let prefix: std::vec::Vec<Scalar> = (1..=6u64).map(Scalar::from).collect();
    for pool in [&real, &forwarded] {
        for pair in prefix.chunks_exact(2) {
            insert(
                pool,
                scalar_to_u256(&env, pair[0]),
                scalar_to_u256(&env, pair[1]),
            );
        }
    }
    // From 6 to 150 the insertion path changes sides at several levels.
    let empty = soroban_utils::zero_hash(&env, 0).expect("the empty leaf");
    for _ in (6..150).step_by(2) {
        insert(&real, empty.clone(), empty.clone());
    }
    fast_forward_pool_tree(&env, &forwarded, &prefix, 150);
    assert_eq!(root(&real), root(&forwarded));

    for value in (100..110u64).step_by(2) {
        for pool in [&real, &forwarded] {
            insert(pool, leaf(value), leaf(value + 1));
        }
        assert_eq!(
            root(&real),
            root(&forwarded),
            "after inserting leaves {value} and {}",
            value + 1
        );
    }
}
