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
/// Description of a note spent by the tested transaction.
pub struct InputNote {
    pub leaf_index: usize, /* We need to place the note in the tree, and hold the index to know
                            * where it is */
    pub priv_key: Scalar, // Used to derive its public key and to sign nullifiers for spends.
    pub blinding: Scalar, // Keeps the commitment hiding so tests match the production circuit.
    pub amount: Scalar,   // Amount being spent; required for balance and commitment inputs.
}

#[derive(Clone, Debug)]
/// Description of a note created by the tested transaction.
pub struct OutputNote {
    pub pub_key: Scalar,
    pub blinding: Scalar,
    pub amount: Scalar,
}

#[derive(Clone, Debug)]
/// Convenience container holding a single test transaction scenario.
/// We use `Vec` because we usually have more than one input and output. The
/// test defines how many
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

/// Builds the witnesses needed to exercise a `TxCase`
///
/// Populates commitment leaves in the Merkle tree, derives Merkle proofs for
/// each input note, and computes nullifiers. This prepares all the witness data
/// required for proving a transaction.
///
/// # Arguments
///
/// * `case` - Transaction case containing input and output notes
/// * `leaves` - Initial leaves vector (will be modified with commitments)
/// * `expected_levels` - Expected number of levels in the Merkle tree
///
/// # Returns
///
/// Returns `Ok(TransactionWitness)` containing the root, public keys,
/// nullifiers, path indices, and flattened path elements, or an error if the
/// tree depth doesn't match expectations.
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

        // Flatten sibling nodes into the format the Circom tester expects.
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

/// Populates Circom tester inputs for policy-enabled and regular transactions
///
/// Builds the input structure required by the Circom circuit tester from a
/// transaction case and its witness data. Includes all public and private
/// inputs needed for proving.
///
/// # Arguments
///
/// * `case` - Transaction case containing input and output notes
/// * `witness` - Transaction witness containing Merkle proofs and nullifiers
/// * `public_amount` - Public amount scalar value (net public input/output)
///
/// # Returns
///
/// Returns an `Inputs` structure populated with all circuit inputs.
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

/// Runs a Circom proof/verify cycle for a transaction test case
///
/// Prepares the transaction witness, builds circuit inputs, and executes
/// a proof generation and verification cycle.
///
/// # Arguments
///
/// * `wasm` - Path to the compiled WASM file
/// * `r1cs` - Path to the R1CS constraint system file
/// * `case` - Transaction case to prove
/// * `leaves` - Initial leaves vector for the Merkle tree
/// * `public_amount` - Public amount scalar value
/// * `expected_levels` - Expected number of levels in the Merkle tree
///
/// # Returns
///
/// Returns `Ok(())` if the proof is generated and verified successfully,
/// or an error if witness preparation, proving, or verification fails.
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
            // Tests expect panics for invalid proofs; convert any panic into a typed error.
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
