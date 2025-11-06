use super::prove_transaction::{InputNote, OutputNote, TxCase};
use crate::test::utils::circom_tester::{InputValue, prove_and_verify};
use crate::test::utils::general::{poseidon2_hash2, scalar_to_bigint};
use crate::test::utils::keypair::{derive_public_key, sign};
use crate::test::utils::merkle_tree::{merkle_proof, merkle_root};
use crate::test::utils::transaction::{commitment, nullifier, prepopulated_leaves};
use anyhow::{Context, Result, anyhow};
use num_bigint::BigInt;
use std::collections::HashMap;
use std::panic;
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use zkhash::ark_ff::Zero;
use zkhash::fields::bn256::FpBN256 as Scalar;

const LEVELS: usize = 5;

fn run_case(
    wasm: &PathBuf,
    r1cs: &PathBuf,
    case: &TxCase,
    mut leaves: Vec<Scalar>,
    public_amount: Scalar,
) -> Result<()> {
    // === INPUT UTXOs ===
    let in0_pub = derive_public_key(case.in0.priv_key);
    let in1_pub = derive_public_key(case.in1.priv_key);

    let in0_commit = commitment(case.in0.amount, in0_pub, case.in0.blinding);
    let in1_commit = commitment(case.in1.amount, in1_pub, case.in1.blinding);

    leaves[0] = in0_commit;
    leaves[case.real_idx] = in1_commit;

    let root_scalar = merkle_root(leaves.clone());

    // === MERKLE TREE ===
    leaves[0] = in0_commit;
    leaves[case.real_idx] = in1_commit;

    let root_scalar = merkle_root(leaves.clone());
    let (pe0, path_idx0_u64, depth0) = merkle_proof(&leaves, 0);
    let (pe1, path_idx1_u64, depth1) = merkle_proof(&leaves, case.real_idx);

    // Sanity check: both paths must match the circuit depth
    assert_eq!(depth0, LEVELS, "unexpected depth for input 0");
    assert_eq!(depth1, LEVELS, "unexpected depth for input 1");

    // === PATH CONVERSION ===
    let path_elems0: Vec<BigInt> = pe0.into_iter().map(scalar_to_bigint).collect();
    let path_elems1: Vec<BigInt> = pe1.into_iter().map(scalar_to_bigint).collect();
    let path_idx0 = Scalar::from(path_idx0_u64);
    let path_idx1 = Scalar::from(path_idx1_u64);

    // === SIGNATURES & NULLIFIERS ===
    let in0_sig = sign(case.in0.priv_key, in0_commit, path_idx0);
    let in1_sig = sign(case.in1.priv_key, in1_commit, path_idx1);
    let in0_null = nullifier(in0_commit, path_idx0, in0_sig);
    let in1_null = nullifier(in1_commit, path_idx1, in1_sig);

    // === OUTPUTS ===
    let out0_commit = commitment(case.out0.amount, case.out0.pub_key, case.out0.blinding);
    let out1_commit = commitment(case.out1.amount, case.out1.pub_key, case.out1.blinding);

    // === WITNESS MAP ===
    let mut inputs: HashMap<String, InputValue> = HashMap::new();

    // === Public signals ===
    inputs.insert(
        "root".into(),
        InputValue::Single(scalar_to_bigint(root_scalar)),
    );
    inputs.insert(
        "publicAmount".into(),
        InputValue::Single(scalar_to_bigint(public_amount)),
    );
    inputs.insert("extDataHash".into(), InputValue::Single(BigInt::from(0u32)));

    /////////////////////////////////
    let nIns = 2;
    let n_membership_proofs = 1;
    let in_pubs = [in0_pub, in1_pub];
    let mut memb_leafs = vec![];
    let mut mem_proof_leaves = leaves.clone();
    for i in 0..nIns {
        for j in 0..n_membership_proofs {
            let membership_leaf = poseidon2_hash2(in_pubs[i], Scalar::zero());
            memb_leafs.push(membership_leaf);
            inputs.insert(
                format!("membershipProofs[{i}][{j}].leaf"),
                InputValue::Single(scalar_to_bigint(membership_leaf)),
            );
            inputs.insert(
                format!("membershipProofs[{i}][{j}].pk"),
                InputValue::Single(scalar_to_bigint(in_pubs[i])),
            );
            inputs.insert(
                format!("membershipProofs[{i}][{j}].blinding"),
                InputValue::Single(scalar_to_bigint(Scalar::zero())),
            );
        }
    }
    let idxs = [0, case.real_idx];
    mem_proof_leaves[0] = memb_leafs[0];
    mem_proof_leaves[case.real_idx] = memb_leafs[1];
    let mut merkle_roots = vec![];
    for i in 0..nIns {
        for j in 0..n_membership_proofs {
            let (mp, mpath_idx, _) = merkle_proof(&mem_proof_leaves, idxs[i]);
            let mp_elems = mp.into_iter().map(scalar_to_bigint).collect();
            let mp_idx = scalar_to_bigint(Scalar::from(mpath_idx));
            merkle_roots.push(merkle_root(mem_proof_leaves.clone()));
            inputs.insert(
                format!("membershipProofs[{i}][{j}].pathElements"),
                InputValue::Array(mp_elems),
            );
            inputs.insert(
                format!("membershipProofs[{i}][{j}].pathIndices"),
                InputValue::Single(mp_idx),
            );
        }
    }

    inputs.insert(
        "membershipRoots".into(),
        InputValue::Array(vec![
            scalar_to_bigint(merkle_roots[0]),
            scalar_to_bigint(merkle_roots[1]),
        ]),
    );

    /////////////////////////////////////////

    inputs.insert(
        "inputNullifier".into(),
        InputValue::Array(vec![scalar_to_bigint(in0_null), scalar_to_bigint(in1_null)]),
    );

    inputs.insert(
        "inAmount".into(),
        InputValue::Array(vec![
            scalar_to_bigint(case.in0.amount),
            scalar_to_bigint(case.in1.amount),
        ]),
    );

    inputs.insert(
        "inPrivateKey".into(),
        InputValue::Array(vec![
            scalar_to_bigint(case.in0.priv_key),
            scalar_to_bigint(case.in1.priv_key),
        ]),
    );

    inputs.insert(
        "inBlinding".into(),
        InputValue::Array(vec![
            scalar_to_bigint(case.in0.blinding),
            scalar_to_bigint(case.in1.blinding),
        ]),
    );

    inputs.insert(
        "inPathIndices".into(),
        InputValue::Array(vec![
            scalar_to_bigint(path_idx0),
            scalar_to_bigint(path_idx1),
        ]),
    );

    let mut in_path_elements_flat = Vec::with_capacity(path_elems0.len() + path_elems1.len());
    in_path_elements_flat.extend(path_elems0);
    in_path_elements_flat.extend(path_elems1);
    inputs.insert(
        "inPathElements".into(),
        InputValue::Array(in_path_elements_flat),
    );

    inputs.insert(
        "outputCommitment".into(),
        InputValue::Array(vec![
            scalar_to_bigint(out0_commit),
            scalar_to_bigint(out1_commit),
        ]),
    );

    inputs.insert(
        "outAmount".into(),
        InputValue::Array(vec![
            scalar_to_bigint(case.out0.amount),
            scalar_to_bigint(case.out1.amount),
        ]),
    );

    inputs.insert(
        "outPubkey".into(),
        InputValue::Array(vec![
            scalar_to_bigint(case.out0.pub_key),
            scalar_to_bigint(case.out1.pub_key),
        ]),
    );

    inputs.insert(
        "outBlinding".into(),
        InputValue::Array(vec![
            scalar_to_bigint(case.out0.blinding),
            scalar_to_bigint(case.out1.blinding),
        ]),
    );

    println!("inputs: {:?}", inputs);
    // === PROVE & VERIFY ===
    let prove_result =
        panic::catch_unwind(AssertUnwindSafe(|| prove_and_verify(wasm, r1cs, &inputs)));

    match prove_result {
        // Successful call to prove_and_verify
        Ok(Ok(res)) => {
            if res.verified {
                Ok(())
            } else {
                Err(anyhow::anyhow!(
                    "Proof failed to verify (res.verified=false)"
                ))
            }
        }

        // prove_and_verify returned an Err, most likely build failure
        Ok(Err(e)) => Err(anyhow::anyhow!("Prover error: {e:?}")),

        // prove_and_verify panicked (unsatisfied constraint, etc.), Used for test that should fail
        Err(panic_info) => {
            let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_info.downcast_ref::<String>() {
                s.clone()
            } else {
                "Unknown panic".to_string()
            };
            Err(anyhow::anyhow!(
                "Prover panicked (expected on invalid proof): {msg}"
            ))
        }
    }
}

fn load_artifacts() -> Result<(PathBuf, PathBuf)> {
    let out_dir = PathBuf::from(env!("CIRCUIT_OUT_DIR"));
    let wasm = out_dir.join("wasm/compliant_test_js/compliant_test.wasm");
    let r1cs = out_dir.join("compliant_test.r1cs");
    anyhow::ensure!(wasm.exists(), "WASM not found at {}", wasm.display());
    anyhow::ensure!(r1cs.exists(), "R1CS not found at {}", r1cs.display());
    Ok((wasm, r1cs))
}
#[tokio::test]
async fn test_tx_1in_1out() -> Result<()> {
    // One real input (in1), one dummy input (in0.amount = 0).
    // One real output (out0 = in1.amount), one dummy output (out1.amount = 0).

    let (wasm, r1cs) = load_artifacts()?;

    let case = TxCase::new(
        7,
        InputNote {
            priv_key: Scalar::from(101u64),
            blinding: Scalar::from(201u64),
            amount: Scalar::from(0u64),
        }, // dummy
        InputNote {
            priv_key: Scalar::from(101u64),
            blinding: Scalar::from(211u64),
            amount: Scalar::from(13u64),
        }, // real
        OutputNote {
            pub_key: Scalar::from(501u64),
            blinding: Scalar::from(601u64),
            amount: Scalar::from(13u64),
        }, // real
        OutputNote {
            pub_key: Scalar::from(502u64),
            blinding: Scalar::from(602u64),
            amount: Scalar::from(0u64),
        }, // dummy
    );

    let leaves = prepopulated_leaves(LEVELS, 0xDEAD_BEEFu64, &[0, case.real_idx], 24);

    run_case(&wasm, &r1cs, &case, leaves, Scalar::from(0u64))
}

#[tokio::test]
async fn test_tx_2in_2out_split() -> Result<()> {
    // Two real inputs; two outputs splitting the sum.
    let (wasm, r1cs) = load_artifacts()?;

    let a = Scalar::from(15u64);
    let b = Scalar::from(8u64);
    let sum = a + b;

    let out_a = Scalar::from(10u64);
    let out_b = sum - out_a;

    let case = TxCase::new(
        30,
        InputNote {
            priv_key: Scalar::from(401u64),
            blinding: Scalar::from(501u64),
            amount: a,
        },
        InputNote {
            priv_key: Scalar::from(411u64),
            blinding: Scalar::from(511u64),
            amount: b,
        },
        OutputNote {
            pub_key: Scalar::from(1101u64),
            blinding: Scalar::from(1201u64),
            amount: out_a,
        },
        OutputNote {
            pub_key: Scalar::from(1102u64),
            blinding: Scalar::from(1202u64),
            amount: out_b,
        },
    );

    let leaves = prepopulated_leaves(LEVELS, 0xBEEFu64, &[0, case.real_idx], 24);

    run_case(&wasm, &r1cs, &case, leaves, Scalar::from(0u64))
}