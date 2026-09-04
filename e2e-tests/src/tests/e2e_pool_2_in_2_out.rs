//! End-to-end tests for the Pool contract with real Groth16 proofs.
//!
//! Every case is 2 inputs and 2 outputs. The witness comes from the committed
//! `*.graph.bin` graph, the proof from `stellar_private_payments::zk::prover`,
//! and the verification from the pool contract. That is the pipeline the CLI,
//! the SDK and the browser use.
use super::utils::{
    DeployedContracts, LEAF_PREFIX, LEVELS, NonMembership, TRANSACT_STEMS, build_membership_trees,
    build_policy_inputs, bytes32_to_bigint, deploy_contracts, generate_proof, prove_with_graph,
    scalar_to_u256, sync_contract_state, test_env, wrap_groth16_proof,
};
use anyhow::Result;
use ark_bn254::Fr as Scalar;
use circuits::test::utils::{
    circom_tester::Inputs,
    general::scalar_to_bigint,
    keypair::derive_public_key,
    transaction::{commitment, prepopulated_prefix},
    transaction_case::{InputNote, OutputNote, TxCase, prepare_transaction_witness},
};
use contract_types::Groth16Error;
use pool::{Error, ExtData, PoolContractClient, Proof, hash_ext_data};
use soroban_sdk::{
    Address, Bytes, I256, InvokeError, U256, Vec as SorobanVec, testutils::Address as _,
};
use stellar_private_payments::types::PolicyFlags;

/// Result of `PoolContractClient::try_transact`.
///
/// The outer error holds the contract error, and the inner one holds a return
/// value conversion error.
type TransactOutcome =
    Result<Result<(), soroban_sdk::ConversionError>, Result<Error, soroban_sdk::InvokeError>>;

/// A pool transaction that is ready for `transact`, with its proof made from
/// the committed witness graph.
struct TransactFixture {
    env: soroban_sdk::Env,
    contracts: DeployedContracts,
    proof: Proof,
    ext_data: ExtData,
}

impl TransactFixture {
    /// Send the transaction to the pool contract.
    fn transact(&self) -> TransactOutcome {
        let sender = Address::generate(&self.env);
        PoolContractClient::new(&self.env, &self.contracts.pool).try_transact(
            &self.proof,
            &self.ext_data,
            &sender,
        )
    }
}

/// Build a 2-in/2-out pool transaction and prove it from the witness graph.
///
/// The amounts must balance: `inputs + ext_amount = outputs`. A positive
/// `ext_amount` is a deposit, and zero is a private transfer.
fn transact_fixture(
    in_amounts: [u64; 2],
    out_amounts: [u64; 2],
    ext_amount: i32,
) -> Result<TransactFixture> {
    assert!(ext_amount >= 0, "this fixture only covers deposits");
    let env = test_env();
    let recipient = Address::generate(&env);

    // Deployed before the hash: `hash_ext_data` binds the hash to the pool's
    // own address and configured token, so both must exist first. Witness
    // generation below needs the resulting hash as a circuit input, which is
    // why deployment moves ahead of it here rather than staying next to
    // `sync_contract_state`.
    env.mock_all_auths();
    let contracts = deploy_contracts(&env);

    let ext_data = ExtData {
        recipient,
        ext_amount: I256::from_i32(&env, ext_amount),
        encrypted_output0: Bytes::new(&env),
        encrypted_output1: Bytes::new(&env),
    };
    let ext_data_hash_bytes = env.as_contract(&contracts.pool, || {
        hash_ext_data(&env, &ext_data, &contracts.token)
    });
    let ext_data_hash_bigint = bytes32_to_bigint(&ext_data_hash_bytes);

    let case = TxCase::new(
        vec![
            InputNote {
                leaf_index: 0,
                priv_key: Scalar::from(101u64),
                blinding: Scalar::from(201u64),
                amount: Scalar::from(in_amounts[0]),
            },
            InputNote {
                leaf_index: 1,
                priv_key: Scalar::from(102u64),
                blinding: Scalar::from(211u64),
                amount: Scalar::from(in_amounts[1]),
            },
        ],
        vec![
            OutputNote {
                pub_key: Scalar::from(501u64),
                blinding: Scalar::from(601u64),
                amount: Scalar::from(out_amounts[0]),
            },
            OutputNote {
                pub_key: Scalar::from(502u64),
                blinding: Scalar::from(602u64),
                amount: Scalar::from(out_amounts[1]),
            },
        ],
    );

    // Pool state. `transact` appends its two outputs past this prefix.
    let mut leaves = prepopulated_prefix(
        0xDEAD_BEEFu64,
        &[case.inputs[0].leaf_index, case.inputs[1].leaf_index],
        LEAF_PREFIX,
    );

    let membership_trees = build_membership_trees(&case, |j| 0xFEED_FACEu64 ^ ((j as u64) << 40));
    let keys = case
        .inputs
        .iter()
        .map(|input| NonMembership {
            key_non_inclusion: scalar_to_bigint(derive_public_key(input.priv_key)),
        })
        .collect::<Vec<_>>();

    let witness = prepare_transaction_witness(&case, leaves.clone(), LEVELS)?;
    let public_amount = Scalar::from(u64::try_from(ext_amount).expect("non-negative ext amount"));
    let result = generate_proof(
        &case,
        leaves.clone(),
        public_amount,
        &membership_trees,
        &keys,
        Some(ext_data_hash_bigint),
    )?;
    assert!(result.verified, "Proof should verify locally");

    let roots = sync_contract_state(
        &env,
        &contracts,
        &case,
        &mut leaves,
        &membership_trees,
        &witness,
    );

    let mut input_nullifiers: SorobanVec<U256> = SorobanVec::new(&env);
    for nullifier in &witness.nullifiers {
        input_nullifiers.push_back(scalar_to_u256(&env, *nullifier));
    }

    let proof = Proof {
        proof: wrap_groth16_proof(&env, result),
        root: roots.pool_root,
        input_nullifiers,
        output_commitment0: scalar_to_u256(&env, output_commitment(&case, 0)),
        output_commitment1: scalar_to_u256(&env, output_commitment(&case, 1)),
        public_amount: U256::from_u32(
            &env,
            u32::try_from(ext_amount).expect("non-negative ext amount"),
        ),
        ext_data_hash: ext_data_hash_bytes,
        asp_membership_root: roots.asp_membership_root,
        asp_non_membership_root: roots.asp_non_membership_root,
    };

    Ok(TransactFixture {
        env,
        contracts,
        proof,
        ext_data,
    })
}

/// Commitment of one output note of a case.
fn output_commitment(case: &TxCase, index: usize) -> Scalar {
    commitment(
        case.outputs[index].amount,
        case.outputs[index].pub_key,
        case.outputs[index].blinding,
    )
}

/// Keep only the signals that a circuit with these policy flags declares.
///
/// `policy_tx_2_2` has no ASP proofs, `_A` has the allowlist only and `_B` has
/// the blocklist only. The graph rejects a signal that its circuit does not
/// declare, so the shared input set must be reduced per stem.
fn inputs_for_flags(all: &Inputs, flags: PolicyFlags) -> Inputs {
    let mut out = Inputs::new();
    for (key, value) in all.iter() {
        let keep = if key.starts_with("nonMembership") {
            flags.requires_non_membership_proofs()
        } else if key.starts_with("membership") {
            flags.requires_membership_proofs()
        } else {
            true
        };
        if keep {
            out.set(key.clone(), value.clone());
        }
    }
    out
}

/// A private transfer of 13 units. The public amount stays zero, so no value
/// enters or leaves the pool.
#[test]
#[cfg_attr(miri, ignore)]
fn transact_transfer_succeeds() -> Result<()> {
    let fixture = transact_fixture([0, 13], [13, 0], 0)?;
    assert!(fixture.transact().is_ok(), "transfer should succeed");
    Ok(())
}

/// A deposit moves value into the pool, so `publicAmount` is not zero.
///
/// `transact_transfer_succeeds` keeps `publicAmount` at zero, so this case
/// covers the public amount encoding as well.
#[test]
#[cfg_attr(miri, ignore)]
fn transact_deposit_succeeds() -> Result<()> {
    let fixture = transact_fixture([0, 0], [13, 0], 13)?;
    assert!(fixture.transact().is_ok(), "deposit should succeed");
    Ok(())
}

/// The on-chain verifier must reject a proof whose public inputs were changed.
///
/// The pool checks the root, the nullifiers, the external data hash and the
/// public amount itself. It does not check the output commitments, so a changed
/// commitment goes to the Groth16 verifier contract, where the pairing check
/// fails.
///
/// What the caller gets back is the pool's own `Error::InvalidProof`, not the
/// verifier's `Groth16Error`. The two enums are separate and their codes do not
/// line up — `Groth16Error::InvalidProof` is 0, which is not a pool error code
/// at all — so the pool catches the call and answers for itself.
#[test]
#[cfg_attr(miri, ignore)]
fn transact_rejects_tampered_output_commitment() -> Result<()> {
    let mut fixture = transact_fixture([0, 13], [13, 0], 0)?;

    let tampered = commitment(
        Scalar::from(13u64),
        Scalar::from(501u64),
        Scalar::from(999u64),
    );
    fixture.proof.output_commitment0 = scalar_to_u256(&fixture.env, tampered);

    let outcome = fixture.transact();
    assert!(
        !matches!(outcome, Err(Err(InvokeError::Contract(code))) if code == Groth16Error::InvalidProof as u32),
        "the verifier's raw error code must not cross the pool boundary, got {outcome:?}"
    );
    assert!(
        matches!(outcome, Err(Ok(Error::InvalidProof))),
        "expected the pool's own InvalidProof for a tampered output commitment, got {outcome:?}"
    );
    Ok(())
}

/// Every committed transact graph must prove and verify.
///
/// The verifier contract holds one verification key only, so the other three
/// stems are checked off chain. The test is expensive (four Groth16 proofs), so
/// it stays behind `--ignored` and runs in the release CI job.
#[test]
#[ignore = "expensive: proves all four transact circuits"]
#[cfg_attr(miri, ignore)]
fn all_transact_graphs_prove_and_verify() -> Result<()> {
    let case = TxCase::new(
        vec![
            InputNote {
                leaf_index: 0,
                priv_key: Scalar::from(101u64),
                blinding: Scalar::from(201u64),
                amount: Scalar::from(0u64),
            },
            InputNote {
                leaf_index: 1,
                priv_key: Scalar::from(102u64),
                blinding: Scalar::from(211u64),
                amount: Scalar::from(13u64),
            },
        ],
        vec![
            OutputNote {
                pub_key: Scalar::from(501u64),
                blinding: Scalar::from(601u64),
                amount: Scalar::from(13u64),
            },
            OutputNote {
                pub_key: Scalar::from(502u64),
                blinding: Scalar::from(602u64),
                amount: Scalar::from(0u64),
            },
        ],
    );

    let leaves = prepopulated_prefix(
        0xDEAD_BEEFu64,
        &[case.inputs[0].leaf_index, case.inputs[1].leaf_index],
        LEAF_PREFIX,
    );
    let membership_trees = build_membership_trees(&case, |j| 0xFEED_FACEu64 ^ ((j as u64) << 40));
    let keys = case
        .inputs
        .iter()
        .map(|input| NonMembership {
            key_non_inclusion: scalar_to_bigint(derive_public_key(input.priv_key)),
        })
        .collect::<Vec<_>>();

    let all_inputs = build_policy_inputs(
        &case,
        leaves,
        Scalar::from(0u64),
        &membership_trees,
        &keys,
        None,
    )?;

    for stem in TRANSACT_STEMS {
        let flags = PolicyFlags::from_stem(stem)?;
        let inputs = inputs_for_flags(&all_inputs, flags);
        let result = prove_with_graph(stem, &inputs)?;
        assert!(result.verified, "{stem}: proof should verify locally");
        assert!(
            result.num_public_inputs() > 0,
            "{stem}: proof should commit to public inputs"
        );
    }
    Ok(())
}
