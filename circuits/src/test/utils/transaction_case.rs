use super::{
    circom_tester::prove_and_verify,
    general::scalar_to_bigint,
    keypair::{derive_public_key, sign},
    merkle_tree::{merkle_proof, merkle_root},
    transaction::{commitment, nullifier},
};
use crate::test::utils::circom_tester::Inputs;
use anyhow::{Result, ensure};
use num_bigint::BigInt;
use std::{
    panic::{self, AssertUnwindSafe},
    path::PathBuf,
};
use zkhash::fields::bn256::FpBN256 as Scalar;

#[derive(Clone, Debug)]
pub struct InputNote {
    pub leaf_index: usize,
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

#[derive(Clone, Debug)]
pub struct TxCase {
    pub inputs: Vec<InputNote>,
    pub outputs: Vec<OutputNote>,
}

impl TxCase {
    pub fn new(inputs: Vec<InputNote>, outputs: Vec<OutputNote>) -> Self {
        Self { inputs, outputs }
    }
}

pub struct TransactionWitness {
    pub root: Scalar,
    pub public_keys: Vec<Scalar>,
    pub nullifiers: Vec<Scalar>,
    pub path_indices: Vec<Scalar>,
    pub path_elements_flat: Vec<BigInt>,
}

pub fn prepare_transaction_witness(
    case: &TxCase,
    mut leaves: Vec<Scalar>,
    expected_levels: usize,
) -> Result<TransactionWitness> {
    let mut commitments = Vec::with_capacity(case.inputs.len());
    let mut public_keys = Vec::with_capacity(case.inputs.len());

    for note in &case.inputs {
        let pk = derive_public_key(note.priv_key);
        let cm = commitment(note.amount, pk, note.blinding);
        public_keys.push(pk);
        commitments.push(cm);
        leaves[note.leaf_index] = cm;
    }

    let root = merkle_root(leaves.clone());
    let mut path_indices = Vec::with_capacity(case.inputs.len());
    let mut path_elements_flat =
        Vec::with_capacity(expected_levels.saturating_mul(case.inputs.len()));
    let mut nullifiers = Vec::with_capacity(case.inputs.len());

    for (i, note) in case.inputs.iter().enumerate() {
        let (siblings, path_idx_u64, depth) = merkle_proof(&leaves, note.leaf_index);
        ensure!(
            depth == expected_levels,
            "unexpected depth for input {i}, expected {expected_levels}, got {depth}"
        );

        path_elements_flat.extend(siblings.into_iter().map(scalar_to_bigint));

        let path_idx = Scalar::from(path_idx_u64);
        path_indices.push(path_idx);

        let sig = sign(note.priv_key, commitments[i], path_idx);
        let nul = nullifier(commitments[i], path_idx, sig);
        nullifiers.push(nul);
    }

    Ok(TransactionWitness {
        root,
        public_keys,
        nullifiers,
        path_indices,
        path_elements_flat,
    })
}

pub fn build_base_inputs(
    case: &TxCase,
    witness: &TransactionWitness,
    public_amount: Scalar,
) -> Inputs {
    let mut inputs = Inputs::new();

    inputs.set("root", scalar_to_bigint(witness.root));
    inputs.set("publicAmount", scalar_to_bigint(public_amount));
    inputs.set("extDataHash", BigInt::from(0u32));

    inputs.set("inputNullifier", witness.nullifiers.clone());
    inputs.set(
        "inAmount",
        case.inputs
            .iter()
            .map(|n| n.amount)
            .collect::<Vec<Scalar>>(),
    );
    inputs.set(
        "inPrivateKey",
        case.inputs
            .iter()
            .map(|n| n.priv_key)
            .collect::<Vec<Scalar>>(),
    );
    inputs.set(
        "inBlinding",
        case.inputs
            .iter()
            .map(|n| n.blinding)
            .collect::<Vec<Scalar>>(),
    );
    inputs.set("inPathIndices", witness.path_indices.clone());
    inputs.set("inPathElements", witness.path_elements_flat.clone());

    let output_commitments: Vec<BigInt> = case
        .outputs
        .iter()
        .map(|out| scalar_to_bigint(commitment(out.amount, out.pub_key, out.blinding)))
        .collect();
    inputs.set("outputCommitment", output_commitments);

    inputs.set(
        "outAmount",
        case.outputs
            .iter()
            .map(|n| n.amount)
            .collect::<Vec<Scalar>>(),
    );
    inputs.set(
        "outPubkey",
        case.outputs
            .iter()
            .map(|n| n.pub_key)
            .collect::<Vec<Scalar>>(),
    );
    inputs.set(
        "outBlinding",
        case.outputs
            .iter()
            .map(|n| n.blinding)
            .collect::<Vec<Scalar>>(),
    );

    inputs
}

pub fn prove_transaction_case(
    wasm: &PathBuf,
    r1cs: &PathBuf,
    case: &TxCase,
    leaves: Vec<Scalar>,
    public_amount: Scalar,
    expected_levels: usize,
) -> Result<()> {
    let witness = prepare_transaction_witness(case, leaves, expected_levels)?;
    let inputs = build_base_inputs(case, &witness, public_amount);

    let prove_result =
        panic::catch_unwind(AssertUnwindSafe(|| prove_and_verify(wasm, r1cs, &inputs)));

    match prove_result {
        Ok(Ok(res)) if res.verified => Ok(()),
        Ok(Ok(_)) => Err(anyhow::anyhow!(
            "Proof failed to verify (res.verified=false)"
        )),
        Ok(Err(e)) => Err(anyhow::anyhow!("Prover error: {e:?}")),
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
