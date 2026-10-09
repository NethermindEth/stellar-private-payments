//! End-to-end tests for the Pool contract with real Groth16 proofs.
//!
//! Every case is 2 inputs and 2 outputs. The witness comes from the committed
//! `*.graph.bin` graph, the proof from `stellar_private_payments::zk::prover`,
//! and the verification from the pool contract. That is the pipeline the CLI,
//! the SDK and the browser use.
use super::utils::{
    DeployedContracts, LEAF_PREFIX, NonMembership, TRANSACT_STEMS, TransactOutcome,
    build_membership_trees, build_policy_inputs, deploy_contracts, prove_transaction,
    prove_with_graph, scalar_to_u256, sync_contract_state, test_env, transact,
};
use anyhow::Result;
use ark_bn254::Fr as Scalar;
use circuits::test::utils::{
    circom_tester::Inputs,
    general::scalar_to_bigint,
    keypair::derive_public_key,
    transaction::{commitment, prepopulated_prefix},
    transaction_case::{InputNote, OutputNote, TxCase},
};
use contract_types::Groth16Error;
use pool::{Error, ExtData, Proof};
use soroban_sdk::{InvokeError, Vec as SorobanVec};
use soroban_utils::constants::bn256_modulus;
use stellar_private_payments::types::PolicyFlags;

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
        transact(&self.env, &self.contracts, &self.proof, &self.ext_data)
    }
}

/// Build a 2-in/2-out pool transaction, prove it from the witness graph, and
/// put the contracts into the state the proof was made against.
///
/// The amounts must balance: `inputs + ext_amount = outputs`. A positive
/// `ext_amount` is a deposit, and zero is a private transfer.
fn transact_fixture(
    in_amounts: [u64; 2],
    out_amounts: [u64; 2],
    ext_amount: i32,
) -> Result<TransactFixture> {
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

    let ext_data = proven.ext_data.clone();
    Ok(TransactFixture {
        proof: proven.into_proof(&env, &roots),
        env,
        contracts,
        ext_data,
    })
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

/// A deposit moves value into the pool, so `publicAmount` is not zero, which
/// covers the public amount encoding that a transfer leaves at zero.
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

/// The pool refuses a settled proof sent again, and with each nullifier `n`
/// sent as `n + r`. The spent check keys on the raw value and misses the alias;
/// the canonical check stops the verifier from reducing it to a spent `n`.
#[test]
#[cfg_attr(miri, ignore)]
fn transact_rejects_a_settled_proof_and_its_field_aliases() -> Result<()> {
    let mut fixture = transact_fixture([0, 13], [13, 0], 0)?;
    assert_eq!(fixture.transact(), Ok(Ok(())), "the first send settles");

    let err = fixture
        .transact()
        .expect_err("a settled proof must not settle again");
    assert_eq!(err, Ok(Error::AlreadySpentNullifier));

    // An unaliased nullifier would answer `AlreadySpentNullifier` first.
    let r = bn256_modulus(&fixture.env);
    fixture.proof.input_nullifiers = SorobanVec::from_iter(
        &fixture.env,
        fixture.proof.input_nullifiers.iter().map(|n| n.add(&r)),
    );
    let err = fixture
        .transact()
        .expect_err("an aliased nullifier must not settle");
    assert_eq!(err, Ok(Error::NonCanonicalPublicInput));
    Ok(())
}

/// Every committed transact graph must prove and verify.
///
/// The verifier contract holds one verification key only, so the other three
/// stems are checked off chain. The test is expensive (four Groth16 proofs), so
/// it stays behind `--ignored` and runs in the release CI job.
#[test]
#[ignore = "expensive: proves all four transact circuits"]
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
