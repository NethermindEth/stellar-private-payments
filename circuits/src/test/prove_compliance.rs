use crate::test::utils::circom_tester::{InputValue, Inputs, SignalKey, prove_and_verify};
use crate::test::utils::general::{poseidon2_hash2, scalar_to_bigint};
use crate::test::utils::keypair::{derive_public_key, sign};
use crate::test::utils::merkle_tree::{merkle_proof, merkle_root};
use crate::test::utils::transaction::{commitment, nullifier, prepopulated_leaves};
use anyhow::{Context, Result, anyhow};
use num_bigint::BigInt;
use std::collections::HashMap;
use std::panic;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use ark_circom::Wasm;
use zkhash::ark_ff::Zero;
use zkhash::fields::bn256::FpBN256 as Scalar;

const LEVELS: usize = 5;
const N_INPUTS: usize = 2;
const N_OUTPUTS: usize = 2;
const N_MEM_PROOFS: usize = 1;
const N_NON_PROOFS: usize = 1;

#[derive(Clone, Debug)]
pub struct InputNote {
    pub real_id: usize,
    pub priv_key: Scalar,
    pub blinding: Scalar,
    pub amount: Scalar,
}

#[derive(Clone, Debug)]
pub struct OutputNote {
    pub pub_key: Scalar,
    pub blinding: Scalar,
    pub amount: Scalar,
}

pub struct TxCase {
    pub input: [InputNote; N_INPUTS],
    pub output: [OutputNote; N_OUTPUTS],
}

#[allow(clippy::too_many_arguments)]
impl TxCase {
    pub fn new(
        in0: InputNote,
        in1: InputNote,
        out0: OutputNote,
        out1: OutputNote,
    ) -> Self {
        Self {
            input: [in0, in1],
            output: [out0, out1],
        }
    }
}


fn run_case(wasm: &PathBuf, r1cs: &PathBuf, case: &TxCase, mut leaves: Vec<Scalar>, public_amount: Scalar) -> Result<()> {
    let mut inputs = Inputs::new();
    // === INPUTS ===
    let mut commits = [Scalar::zero(); N_INPUTS];
    let mut pubs    = [Scalar::zero(); N_INPUTS];
    let mut nullifiers    = [Scalar::zero(); N_INPUTS];
    let mut path_indices = [Scalar::zero(); N_INPUTS];
    let mut path_elements_flat: Vec<BigInt> = Vec::with_capacity(N_INPUTS * LEVELS);

    // First pass because we need to modify the leaves
    for (i,input_note) in case.input.iter().enumerate() {
        let pk = derive_public_key(input_note.priv_key);
        pubs[i] = pk;
        let commit = commitment(input_note.amount, pk, input_note.blinding);
        commits[i] = commit;
        leaves[input_note.real_id] = commit;
    }

    let root_scalar = merkle_root(leaves.clone());

    // Second pass after modifying the leaves
    for (i, input_note) in case.input.iter().enumerate() {
        let (siblings, indices, depth) = merkle_proof(&leaves, input_note.real_id);
        assert_eq!(depth, LEVELS, "unexpected depth for input {:?}", input_note);

        for s in siblings { path_elements_flat.push(scalar_to_bigint(s)); }
        let path_id = Scalar::from(indices);
        path_indices[i]  = path_id;

        let sig = sign(input_note.priv_key, commits[i], path_id);
        let nul = nullifier(commits[i], path_id, sig);
        nullifiers[i] = nul;
    }
    
    inputs.set("inPathElements", path_elements_flat);


    // === MEMBERSHIP PROOF ===
    let mut mem_proof_leaves = leaves.clone();
    let mut mem_leaves = [Scalar::zero(); N_INPUTS];

    for (i, input_note) in case.input.iter().enumerate() {
        // THIS NEEDS TO BE THE BINDING
        let leaf = poseidon2_hash2(pubs[i], Scalar::zero());
        mem_leaves[i] = leaf;
        // THIS NEEDS CHANGING
        mem_proof_leaves[input_note.real_id] = leaf;
    }
    let mem_root = merkle_root(mem_proof_leaves.clone());

    let mut membership_roots: Vec<Scalar> =
        Vec::with_capacity(N_INPUTS * N_MEM_PROOFS);

    for i in 0..N_INPUTS {
        for j in 0..N_MEM_PROOFS {
            // SMT proof from the frozen membership tree
            let (siblings, path_idx_u64, depth) = merkle_proof(&mem_proof_leaves, case.input[i].real_id);
            assert_eq!(depth, LEVELS, "unexpected membership depth for input {}", i);

            // Helper to write membershipProofs[i][j].field
            let key = |field: &str| {
                SignalKey::new("membershipProofs")
                    .idx(i)
                    .idx(j)
                    .field(field)
            };

            inputs.set_key(&key("leaf"),     scalar_to_bigint(mem_leaves[i]));
            inputs.set_key(&key("pk"),       scalar_to_bigint(pubs[i]));
            inputs.set_key(&key("blinding"), BigInt::from(0u32)); // leaf = H(pk, 0)

            // If your circuit expects an array for pathElements, we can set it in one go:
            inputs.set_key(
                &key("pathElements"),
                siblings.into_iter().map(scalar_to_bigint).collect::<Vec<BigInt>>(),
            );

            inputs.set_key(
                &key("pathIndices"),
                scalar_to_bigint(Scalar::from(path_idx_u64)),
            );

            // Push root per-proof (matches your earlier contract)
            membership_roots.push(mem_root);
        }
    }

    inputs.set(
        "membershipRoots",
        membership_roots
            .into_iter()
            .map(scalar_to_bigint)
            .collect::<Vec<BigInt>>(),
    );

    // ===OUTPUT===
    let mut output_comms = [Scalar::zero(); N_OUTPUTS];
    for (i,output_note) in case.output.iter().enumerate() {
        let comm = commitment(output_note.amount, output_note.pub_key, output_note.blinding);
        output_comms[i] = comm;
    }

    inputs.set(
        "inAmount",
        (0..N_INPUTS).map(|i| scalar_to_bigint(case.input[i].amount)).collect::<Vec<_>>()
    );
    inputs.set(
        "inPrivateKey",
        (0..N_INPUTS).map(|i| scalar_to_bigint(case.input[i].priv_key)).collect::<Vec<_>>()
    );
    inputs.set(
        "inBlinding",
        (0..N_INPUTS).map(|i| scalar_to_bigint(case.input[i].blinding)).collect::<Vec<_>>()
    );
    inputs.set(
        "inPathIndices",
        (0..N_INPUTS).map(|i| scalar_to_bigint(path_indices[i])).collect::<Vec<_>>()
    );
    inputs.set(
        "inputNullifier",
        (0..N_INPUTS).map(|i| scalar_to_bigint(nullifiers[i])).collect::<Vec<_>>()
    );

    inputs.set(
        "outAmount",
        (0..N_OUTPUTS).map(|i| scalar_to_bigint(case.output[i].amount)).collect::<Vec<_>>()
    );
    inputs.set(
        "outPubkey",
        (0..N_OUTPUTS).map(|i| scalar_to_bigint(case.output[i].pub_key)).collect::<Vec<_>>()
    );
    inputs.set(
        "outBlinding",
        (0..N_OUTPUTS).map(|i| scalar_to_bigint(case.output[i].blinding)).collect::<Vec<_>>()
    );
    inputs.set(
        "outputCommitment",
        (0..N_OUTPUTS).map(|i| scalar_to_bigint(output_comms[i])).collect::<Vec<_>>()
    );

    inputs.set("root", scalar_to_bigint(root_scalar));
    inputs.set("publicAmount", scalar_to_bigint(public_amount));
    inputs.set("extDataHash", BigInt::from(0u32));

    // === PROVE & VERIFY ===
    let prove_result = panic::catch_unwind(AssertUnwindSafe(|| {
        prove_and_verify(wasm, r1cs, &inputs.into_map())
    }));
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
        InputNote {
            real_id: 0,
            priv_key: Scalar::from(101u64),
            blinding: Scalar::from(201u64),
            amount: Scalar::from(0u64),
        }, // dummy
        InputNote {
            real_id: 7,
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

    let leaves = prepopulated_leaves(LEVELS, 0xDEAD_BEEFu64, &[case.input[0].real_id, case.input[1].real_id], 24);

    run_case(&wasm, &r1cs, &case, leaves, Scalar::from(0u64))
}
