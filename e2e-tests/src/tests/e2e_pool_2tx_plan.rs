//! E2E: tx-planner spend session multi-step spend (consolidate + final) with
//! real proofs.

use super::utils::{
    DeployedContracts, LEVELS, NonMembership, build_membership_trees, bytes32_to_bigint,
    deploy_contracts, generate_proof, non_membership_overrides_from_pubs, scalar_to_u256, test_env,
    u256_to_scalar, wrap_groth16_proof,
};
use anyhow::Result;
use asp_membership::ASPMembershipClient;
use asp_non_membership::ASPNonMembershipClient;
use circuits::test::utils::{
    general::{poseidon2_hash2, scalar_to_bigint},
    keypair::derive_public_key,
    merkle_tree::merkle_root,
    transaction::{commitment, prepopulated_leaves},
    transaction_case::{InputNote, OutputNote, TxCase, prepare_transaction_witness},
};
use pool::{ExtData, PoolContractClient, Proof, hash_ext_data};
use soroban_sdk::{Address, Bytes, Env, I256, U256, Vec as SorobanVec, testutils::Address as _};
use tx_planner::{SpendSession, SpendTarget, SpendableNote, Transact};
use types::{EncryptionPublicKey, Field, NoteAmount, NotePublicKey};
use zkhash::{
    ark_ff::{BigInteger, PrimeField},
    fields::bn256::FpBN256 as Scalar,
};

const USER_SKEY: u64 = 1001;
const POOL_ADDRESS: &str = "POOL";

struct TestNote {
    input: InputNote,
}

impl TestNote {
    fn new(leaf_index: usize, priv_key: u64, blinding: u64, amount: u64) -> Self {
        Self {
            input: InputNote {
                leaf_index,
                priv_key: Scalar::from(priv_key),
                blinding: Scalar::from(blinding),
                amount: Scalar::from(amount),
            },
        }
    }

    fn commitment(&self) -> Field {
        scalar_to_field(commitment(
            self.input.amount,
            derive_public_key(self.input.priv_key),
            self.input.blinding,
        ))
    }

    fn as_spendable_note(&self) -> SpendableNote {
        SpendableNote {
            commitment: self.commitment(),
            amount: note_amount(self.input.amount),
        }
    }

    fn set_in_tree(&self, leaves: &mut [Scalar]) {
        let pub_key = derive_public_key(self.input.priv_key);
        leaves[self.input.leaf_index] = commitment(self.input.amount, pub_key, self.input.blinding);
    }
}

fn scalar_to_field(s: Scalar) -> Field {
    let bytes = s.into_bigint().to_bytes_be();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&bytes);
    Field::try_from_be_bytes(buf).expect("valid field element")
}

fn note_amount(amount: Scalar) -> NoteAmount {
    NoteAmount::from(u128::from(
        amount.into_bigint().as_ref().first().copied().unwrap_or(0),
    ))
}

fn spendable_notes(notes: &[TestNote]) -> Vec<SpendableNote> {
    notes.iter().map(|n| n.as_spendable_note()).collect()
}

fn transfer_target() -> SpendTarget {
    SpendTarget::transfer(
        NotePublicKey::parse("0x0000000000000000000000000000000000000000000000000000000000000501")
            .expect("test recipient note key"),
        EncryptionPublicKey::parse(
            "0x0000000000000000000000000000000000000000000000000000000000000601",
        )
        .expect("test recipient enc key"),
    )
}

fn tx_case_for_transact(
    step: &Transact,
    consolidate: bool,
    wallet: &[TestNote],
    user_pub: Scalar,
) -> TxCase {
    let find_note = |commitment: Field| -> &TestNote {
        wallet
            .iter()
            .find(|n| n.commitment() == commitment)
            .expect("wallet note for commitment")
    };

    let inputs = step
        .input_commitments
        .iter()
        .map(|c| find_note(*c).input.clone())
        .collect::<Vec<_>>();

    let out0 = Scalar::from(u128::from(step.output_amounts[0]));
    let out1 = Scalar::from(u128::from(step.output_amounts[1]));

    if consolidate {
        return TxCase::new(
            inputs,
            vec![
                OutputNote {
                    pub_key: user_pub,
                    blinding: Scalar::from(900u64),
                    amount: out0,
                },
                OutputNote {
                    pub_key: Scalar::from(0u64),
                    blinding: Scalar::from(0u64),
                    amount: Scalar::from(0u64),
                },
            ],
        );
    }

    let outputs = if step.output_amounts[1].is_zero() {
        vec![
            OutputNote {
                pub_key: Scalar::from(501u64),
                blinding: Scalar::from(601u64),
                amount: out0,
            },
            OutputNote {
                pub_key: Scalar::from(0u64),
                blinding: Scalar::from(0u64),
                amount: Scalar::from(0u64),
            },
        ]
    } else {
        vec![
            OutputNote {
                pub_key: Scalar::from(501u64),
                blinding: Scalar::from(601u64),
                amount: out0,
            },
            OutputNote {
                pub_key: user_pub,
                blinding: Scalar::from(602u64),
                amount: out1,
            },
        ]
    };

    TxCase::new(inputs, outputs)
}

fn remove_spent_test_notes(wallet: &mut Vec<TestNote>, spent: &[Field]) {
    wallet.retain(|n| !spent.contains(&n.commitment()));
}

fn apply_consolidate_to_harness(
    step: &Transact,
    wallet: &mut Vec<TestNote>,
    leaves: &mut [Scalar],
    merge_leaf_index: usize,
    pool_client: &PoolContractClient,
) {
    let merge_amount =
        u64::try_from(u128::from(step.output_amounts[0])).expect("note amount fits in u64");
    let merged_note = TestNote::new(merge_leaf_index, USER_SKEY, 900, merge_amount);
    merged_note.set_in_tree(leaves);

    let dummy_leaf_index = merge_leaf_index
        .checked_add(1)
        .expect("merge output pair index");
    leaves[dummy_leaf_index] =
        commitment(Scalar::from(0u64), Scalar::from(0u64), Scalar::from(0u64));

    assert_eq!(
        merkle_root(leaves.to_vec()),
        u256_to_scalar(&pool_client.get_root()),
        "off-chain leaves must match pool after consolidate"
    );

    remove_spent_test_notes(wallet, &step.input_commitments);
    wallet.push(merged_note);
}

fn run_step(
    env: &Env,
    contracts: &DeployedContracts,
    case: &TxCase,
    leaves: &mut [Scalar],
    ext_data: &ExtData,
    bootstrap_pool_through: Option<usize>,
) -> Result<()> {
    let asp_membership = ASPMembershipClient::new(env, &contracts.asp_membership);
    let asp_non_membership = ASPNonMembershipClient::new(env, &contracts.asp_non_membership);
    let pool_client = PoolContractClient::new(env, &contracts.pool);
    let ext_data_hash_bytes = hash_ext_data(env, ext_data);

    let mut membership_trees =
        build_membership_trees(case, |j| 0xFEED_FACEu64 ^ ((j as u64) << 40));
    membership_trees[0].index = 0;
    membership_trees[1].index = 1;

    let keys = case
        .inputs
        .iter()
        .map(|input| NonMembership {
            key_non_inclusion: scalar_to_bigint(derive_public_key(input.priv_key)),
        })
        .collect::<Vec<_>>();

    let witness = prepare_transaction_witness(case, leaves.to_vec(), LEVELS)?;
    let result = generate_proof(
        case,
        leaves.to_vec(),
        Scalar::from(0u64),
        &membership_trees,
        &keys,
        Some(bytes32_to_bigint(&ext_data_hash_bytes)),
    )?;
    assert!(result.verified, "Proof should verify locally");

    if bootstrap_pool_through.is_some() {
        let mut memb_leaves = membership_trees[0].leaves;
        memb_leaves[membership_trees[0].index] = poseidon2_hash2(
            witness.public_keys[0],
            membership_trees[0].blinding,
            Some(Scalar::from(1u64)),
        );
        memb_leaves[membership_trees[1].index] = poseidon2_hash2(
            witness.public_keys[1],
            membership_trees[1].blinding,
            Some(Scalar::from(1u64)),
        );
        for leaf in memb_leaves {
            asp_membership.insert_leaf(&scalar_to_u256(env, leaf));
        }

        for (key, value) in non_membership_overrides_from_pubs(&witness.public_keys) {
            let key_bytes = key.to_bytes_be().1;
            let mut padded_key = [0u8; 32];
            let start = padded_key.len().saturating_sub(key_bytes.len());
            padded_key[start..].copy_from_slice(&key_bytes);

            let value_bytes = value.to_bytes_be().1;
            let mut padded_value = [0u8; 32];
            let start = padded_value.len().saturating_sub(value_bytes.len());
            padded_value[start..].copy_from_slice(&value_bytes);
            asp_non_membership.insert_leaf(
                &U256::from_be_bytes(env, &Bytes::from_array(env, &padded_key)),
                &U256::from_be_bytes(env, &Bytes::from_array(env, &padded_value)),
            );
        }
    }

    for note in &case.inputs {
        let pk = derive_public_key(note.priv_key);
        leaves[note.leaf_index] = commitment(note.amount, pk, note.blinding);
    }

    if let Some(pool_through) = bootstrap_pool_through {
        assert_eq!(leaves.len() % 2, 0, "Leaves should be even for this test");
        for pair in leaves[..pool_through].chunks_exact(2) {
            let leaf_1 = scalar_to_u256(env, pair[0]);
            let leaf_2 = scalar_to_u256(env, pair[1]);
            env.as_contract(&contracts.pool, || {
                let _ = pool::merkle_with_history::MerkleTreeWithHistory::insert_two_leaves(
                    env, leaf_1, leaf_2,
                );
            });
        }
    }

    let circuit_root = scalar_to_u256(env, witness.root);
    assert_eq!(
        circuit_root,
        pool_client.get_root(),
        "Pool root should match circuit root"
    );

    let asp_membership_root = asp_membership.get_root();
    let asp_non_membership_root = asp_non_membership.get_root();

    let groth16_proof = wrap_groth16_proof(env, result);
    let mut input_nullifiers = SorobanVec::new(env);
    for nul in &witness.nullifiers {
        input_nullifiers.push_back(scalar_to_u256(env, *nul));
    }

    let output_commitment0 = scalar_to_u256(
        env,
        commitment(
            case.outputs[0].amount,
            case.outputs[0].pub_key,
            case.outputs[0].blinding,
        ),
    );
    let output_commitment1 = scalar_to_u256(
        env,
        commitment(
            case.outputs[1].amount,
            case.outputs[1].pub_key,
            case.outputs[1].blinding,
        ),
    );

    let proof = Proof {
        proof: groth16_proof,
        root: circuit_root,
        input_nullifiers,
        output_commitment0,
        output_commitment1,
        public_amount: U256::from_u32(env, 0),
        ext_data_hash: ext_data_hash_bytes,
        asp_membership_root,
        asp_non_membership_root,
    };

    let sender = Address::generate(env);
    match pool_client.try_transact(&proof, ext_data, &sender) {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => panic!("Transaction failed: {e:?}"),
        Err(e) => panic!("Transaction invoke failed: {e:?}"),
    }

    Ok(())
}

/// Wallet [2, 3, 5], spend 10 → consolidate then final, two on-chain txs.
#[test]
#[cfg_attr(miri, ignore)]
fn test_e2e_planned_consolidate_final() -> Result<()> {
    let env = test_env();
    env.mock_all_auths();

    let user_pub = derive_public_key(Scalar::from(USER_SKEY));

    let mut test_wallet = vec![
        TestNote::new(0, USER_SKEY, 201, 2),
        TestNote::new(1, USER_SKEY, 211, 3),
        TestNote::new(6, USER_SKEY, 221, 5),
    ];

    let mut session = SpendSession::setup(
        spendable_notes(&test_wallet),
        NoteAmount::from(10u128),
        POOL_ADDRESS.to_string(),
        transfer_target(),
    )?;
    assert_eq!(session.len(), 2);

    let mut leaves = prepopulated_leaves(LEVELS, 0xDEAD_BEEFu64, &[0, 1, 6], 24);
    for note in &test_wallet {
        note.set_in_tree(&mut leaves);
    }

    let zero = U256::from_be_bytes(
        &env,
        &Bytes::from_array(
            &env,
            &[
                37, 48, 34, 136, 219, 153, 53, 3, 68, 151, 65, 131, 206, 49, 13, 99, 181, 58, 187,
                158, 240, 248, 87, 87, 83, 238, 211, 110, 1, 24, 249, 206,
            ],
        ),
    );
    let reserved_leaves = session.len().checked_mul(2).expect("reserved leaf count");
    let first_merge_leaf_index = leaves
        .len()
        .checked_sub(reserved_leaves)
        .expect("tree has reserved tail");
    for leaf in &mut leaves[first_merge_leaf_index..] {
        *leaf = u256_to_scalar(&zero);
    }

    let ext_data = ExtData {
        recipient: Address::generate(&env),
        ext_amount: I256::from_i32(&env, 0),
        encrypted_output0: Bytes::new(&env),
        encrypted_output1: Bytes::new(&env),
    };
    let contracts = deploy_contracts(&env);
    let pool_client = PoolContractClient::new(&env, &contracts.pool);

    let mut next_merge_leaf_index = first_merge_leaf_index;
    let mut step_count = 0usize;

    while let Some(step) = session.step()? {
        let consolidate = session.is_consolidate_step();
        let case = tx_case_for_transact(&step, consolidate, &test_wallet, user_pub);
        let bootstrap = (step_count == 0).then_some(first_merge_leaf_index);
        run_step(&env, &contracts, &case, &mut leaves, &ext_data, bootstrap)?;

        let output_commitments = [
            scalar_to_field(commitment(
                case.outputs[0].amount,
                case.outputs[0].pub_key,
                case.outputs[0].blinding,
            )),
            scalar_to_field(commitment(
                case.outputs[1].amount,
                case.outputs[1].pub_key,
                case.outputs[1].blinding,
            )),
        ];

        if consolidate {
            apply_consolidate_to_harness(
                &step,
                &mut test_wallet,
                &mut leaves,
                next_merge_leaf_index,
                &pool_client,
            );
            next_merge_leaf_index = next_merge_leaf_index
                .checked_add(2)
                .expect("next merge leaf index");
        } else {
            remove_spent_test_notes(&mut test_wallet, &step.input_commitments);
        }

        session.complete_step(&output_commitments)?;
        step_count += 1;
    }

    assert_eq!(step_count, 2);
    assert!(session.is_done());
    Ok(())
}
