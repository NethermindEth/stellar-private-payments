use super::{
    circom_tester::{InputValue, prove_and_verify},
    keypair::{derive_public_key, sign},
    merkle_tree::{merkle_proof, merkle_root},
    transaction::{commitment, nullifier},
};
use crate::test::utils::general::scalar_to_bigint;

use anyhow::{Context, Result};
use num_bigint::BigInt;
use std::{collections::HashMap, env, path::PathBuf};
use zkhash::fields::bn256::FpBN256 as Scalar;

struct TxCase {
    real_idx: usize,

    in0_priv: Scalar,
    in0_blind: Scalar,

    in1_amount: Scalar,
    in1_priv: Scalar,
    in1_blind: Scalar,

    out0_amount: Scalar,
    out0_pub: Scalar,
    out0_blind: Scalar,
    out1_pub: Scalar,
    out1_blind: Scalar,
}

#[allow(clippy::too_many_arguments)]
impl TxCase {
    fn new(
        real_idx: usize,
        in0_priv: Scalar,
        in0_blind: Scalar,
        in1_amount: Scalar,
        in1_priv: Scalar,
        in1_blind: Scalar,
        out0_amount: Scalar,
        out0_pub: Scalar,
        out0_blind: Scalar,
        out1_pub: Scalar,
        out1_blind: Scalar,
    ) -> Self {
        Self {
            real_idx,
            in0_priv: (in0_priv),
            in0_blind: (in0_blind),
            in1_amount: (in1_amount),
            in1_priv: (in1_priv),
            in1_blind: (in1_blind),
            out0_amount: (out0_amount),
            out0_pub: (out0_pub),
            out0_blind: (out0_blind),
            out1_pub: (out1_pub),
            out1_blind: (out1_blind),
        }
    }
}

/// Runs one Transaction(5,2,2) case:
/// - input 0 is dummy (amount=0) -> disables merkle root check
/// - input 1 is real and must prove membership at `real_idx`
/// - publicAmount = 0, so outputs sum == inputs sum
#[allow(clippy::arithmetic_side_effects)]
fn run_case(wasm: &PathBuf, r1cs: &PathBuf, case: &TxCase) -> Result<()> {
    // === TREE SETUP ===
    const LEVELS: usize = 5;
    const N: usize = 1 << LEVELS;

    // === INPUT UTXOs ===
    let in0_amount = Scalar::from(0u64); // dummy (disables root check in circuit logic)
    let in0_pub = derive_public_key(case.in0_priv);
    let in1_pub = derive_public_key(case.in1_priv);

    let in0_commit = commitment(in0_amount, in0_pub, case.in0_blind);
    let in1_commit = commitment(case.in1_amount, in1_pub, case.in1_blind);

    // === MERKLE TREE ===
    let mut leaves = vec![Scalar::from(0u64); N];
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
    // signature = Poseidon2(3)(privKey, commitment, pathIndices)
    let in0_sig = sign(case.in0_priv, in0_commit, path_idx0);
    let in1_sig = sign(case.in1_priv, in1_commit, path_idx1);
    let in0_null = nullifier(in0_commit, path_idx0, in0_sig);
    let in1_null = nullifier(in1_commit, path_idx1, in1_sig);

    // === OUTPUTS ===
    let public_amount = Scalar::from(0u64);
    let mut out1_amount = case.in1_amount; // since in0_amount=0 and public=0, sumOuts = in1_amount
    // sinccec we allow arithmetic side effects, lets manually do the check
    anyhow::ensure!(
        case.out0_amount <= case.in1_amount,
        "out0_amount must be ≤ in1_amount"
    );
    out1_amount -= case.out0_amount;

    let out0_commit = commitment(case.out0_amount, case.out0_pub, case.out0_blind);
    let out1_commit = commitment(out1_amount, case.out1_pub, case.out1_blind);

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

    // === Input UTXO fields ===
    inputs.insert(
        "inputNullifier".into(),
        InputValue::Array(vec![scalar_to_bigint(in0_null), scalar_to_bigint(in1_null)]),
    );
    inputs.insert(
        "inAmount".into(),
        InputValue::Array(vec![
            scalar_to_bigint(in0_amount),
            scalar_to_bigint(case.in1_amount),
        ]),
    );
    inputs.insert(
        "inPrivateKey".into(),
        InputValue::Array(vec![
            scalar_to_bigint(case.in0_priv),
            scalar_to_bigint(case.in1_priv),
        ]),
    );
    inputs.insert(
        "inBlinding".into(),
        InputValue::Array(vec![
            scalar_to_bigint(case.in0_blind),
            scalar_to_bigint(case.in1_blind),
        ]),
    );
    inputs.insert(
        "inPathIndices".into(),
        InputValue::Array(vec![
            scalar_to_bigint(path_idx0),
            scalar_to_bigint(path_idx1),
        ]),
    );

    // === Flattened path elements ===
    #[allow(clippy::arithmetic_side_effects)]
    let mut in_path_elements_flat = Vec::with_capacity(path_elems0.len() + path_elems1.len());
    in_path_elements_flat.extend(path_elems0);
    in_path_elements_flat.extend(path_elems1);
    inputs.insert(
        "inPathElements".into(),
        InputValue::Array(in_path_elements_flat),
    );

    // === Output UTXO fields ===
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
            scalar_to_bigint(case.out0_amount),
            scalar_to_bigint(out1_amount),
        ]),
    );
    inputs.insert(
        "outPubkey".into(),
        InputValue::Array(vec![
            scalar_to_bigint(case.out0_pub),
            scalar_to_bigint(case.out1_pub),
        ]),
    );
    inputs.insert(
        "outBlinding".into(),
        InputValue::Array(vec![
            scalar_to_bigint(case.out0_blind),
            scalar_to_bigint(case.out1_blind),
        ]),
    );

    // === PROVE & VERIFY ===
    let res =
        prove_and_verify(wasm, r1cs, &inputs).context("Failed to prove and verify transaction2")?;
    anyhow::ensure!(res.verified, "Transaction2 proof did not verify");

    Ok(())
}

#[tokio::test]
async fn test_transaction2_edge_indices() -> anyhow::Result<()> {
    // === PATH SETUP ===
    let out_dir = PathBuf::from(env!("CIRCUIT_OUT_DIR"));
    let wasm = out_dir.join("wasm/transaction2_js/transaction2.wasm");
    let r1cs = out_dir.join("transaction2.r1cs");

    if !wasm.exists() {
        return Err(anyhow::anyhow!("WASM file not found at {}", wasm.display()));
    }
    if !r1cs.exists() {
        return Err(anyhow::anyhow!("R1CS file not found at {}", r1cs.display()));
    }

    // === TEST MATRIX ===
    // Hit the far left/right edges
    const LEVELS: usize = 5;
    const N: usize = 1 << LEVELS;
    let indices = [1usize, N - 2, N - 1];

    for &real_idx in &indices {
        // === INPUT PARAMETERS ===
        let in0_priv = Scalar::from(9u64);
        let in0_blind = Scalar::from(10u64);

        let in1_amount = Scalar::from(21u64);
        let in1_priv = Scalar::from(22u64);
        let in1_blind = Scalar::from(23u64);

        // === OUTPUT SPLIT ===
        let out0_amount = Scalar::from(5u64); // out1 = 16
        let out0_pub = Scalar::from(1111u64);
        let out0_blind = Scalar::from(2222u64);

        let out1_pub = Scalar::from(3333u64);
        let out1_blind = Scalar::from(4444u64);

        let case = TxCase::new(
            real_idx,
            in0_priv,
            in0_blind,
            in1_amount,
            in1_priv,
            in1_blind,
            out0_amount,
            out0_pub,
            out0_blind,
            out1_pub,
            out1_blind,
        );

        run_case(&wasm, &r1cs, &case)
            .with_context(|| format!("edge-indices failed at real_idx={real_idx}"))?;
    }

    Ok(())
}

#[tokio::test]
async fn test_transaction2_output_sweep() -> anyhow::Result<()> {
    // === PATH SETUP ===
    let out_dir = PathBuf::from(env!("CIRCUIT_OUT_DIR"));
    let wasm = out_dir.join("wasm/transaction2_js/transaction2.wasm");
    let r1cs = out_dir.join("transaction2.r1cs");

    if !wasm.exists() {
        return Err(anyhow::anyhow!("WASM file not found at {}", wasm.display()));
    }
    if !r1cs.exists() {
        return Err(anyhow::anyhow!("R1CS file not found at {}", r1cs.display()));
    }

    // === FIXED POSITION ===
    let real_idx = 7usize;

    // === FIXED INPUTS ===
    let in0_priv = Scalar::from(31u64);
    let in0_blind = Scalar::from(41u64);

    let in1_amount = Scalar::from(20u64);
    let in1_priv = Scalar::from(59u64);
    let in1_blind = Scalar::from(26u64);

    // === PUBKEYS/BLINDS ===
    let out0_pub = Scalar::from(777u64);
    let out0_blind = Scalar::from(888u64);
    let out1_pub = Scalar::from(999u64);
    let out1_blind = Scalar::from(1110u64);

    // === SWEEP out0_amount from 0..=in1_amount ===
    for a0 in 0u64..=20u64 {
        let out0_amount = Scalar::from(a0);

        let case = TxCase::new(
            real_idx,
            in0_priv,
            in0_blind,
            in1_amount,
            in1_priv,
            in1_blind,
            out0_amount,
            out0_pub,
            out0_blind,
            out1_pub,
            out1_blind,
        );

        run_case(&wasm, &r1cs, &case)
            .with_context(|| format!("output-sweep failed for out0_amount={a0}"))?;
    }

    Ok(())
}

#[tokio::test]
async fn test_transaction2_blinding_variations() -> anyhow::Result<()> {
    // === PATH SETUP ===
    let out_dir = PathBuf::from(env!("CIRCUIT_OUT_DIR"));
    let wasm = out_dir.join("wasm/transaction2_js/transaction2.wasm");
    let r1cs = out_dir.join("transaction2.r1cs");

    if !wasm.exists() {
        return Err(anyhow::anyhow!("WASM file not found at {}", wasm.display()));
    }
    if !r1cs.exists() {
        return Err(anyhow::anyhow!("R1CS file not found at {}", r1cs.display()));
    }

    // === TEST MATRIX ===
    let real_idx_cases = [3usize, 11, 19, 27];

    // Use a spread of blinding choices (0, 1, medium, large)
    let blinding_cases = [
        (0u64, 0u64, 0u64, 0u64),
        (1, 1, 1, 1),
        (12345, 67890, 22222, 33333),
        (u64::MAX - 1, u64::MAX - 2, u64::MAX - 3, u64::MAX - 4),
    ];

    for &real_idx in &real_idx_cases {
        for &(in0_b, in1_b, out0_b, out1_b) in &blinding_cases {
            // === INPUTS ===
            let in0_priv = Scalar::from(5u64);
            let in0_blind = Scalar::from(in0_b);

            let in1_amount = Scalar::from(37u64);
            let in1_priv = Scalar::from(11u64);
            let in1_blind = Scalar::from(in1_b);

            // === OUTPUTS ===
            let out0_amount = Scalar::from(17u64); // out1 = 20
            let out0_pub = Scalar::from(2024u64);
            let out0_blind = Scalar::from(out0_b);

            let out1_pub = Scalar::from(2025u64);
            let out1_blind = Scalar::from(out1_b);

            let case = TxCase::new(
                real_idx,
                in0_priv,
                in0_blind,
                in1_amount,
                in1_priv,
                in1_blind,
                out0_amount,
                out0_pub,
                out0_blind,
                out1_pub,
                out1_blind,
            );

            run_case(
                &wasm, &r1cs, &case
            )
                .with_context(|| format!(
                    "blinding-variations failed at real_idx={real_idx} with blinds=({in0_b},{in1_b},{out0_b},{out1_b})"
                ))?;
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_transaction2_randomized_lcg() -> anyhow::Result<()> {
    // === PATH SETUP ===
    let out_dir = PathBuf::from(env!("CIRCUIT_OUT_DIR"));
    let wasm = out_dir.join("wasm/transaction2_js/transaction2.wasm");
    let r1cs = out_dir.join("transaction2.r1cs");

    if !wasm.exists() {
        return Err(anyhow::anyhow!("WASM file not found at {}", wasm.display()));
    }
    if !r1cs.exists() {
        return Err(anyhow::anyhow!("R1CS file not found at {}", r1cs.display()));
    }

    // === LCG SEED ===
    let mut x: u64 = 0xA5A5_A5A5_DEAD_BEEF;
    const LEVELS: usize = 5;
    const N: usize = 1 << LEVELS;

    // === RUN 20 DETERMINISTIC "RANDOM" CASES ===
    for case_idx in 0..20 {
        // LCG step
        x = x.wrapping_mul(2862933555777941757).wrapping_add(3037000493);

        // real_idx in [1..N-1] (avoid 0: reserved for dummy)
        let real_idx: usize = (usize::try_from(x).unwrap_or(0) % (N - 1)).saturating_add(1);

        // Derive inputs from the same x to keep it deterministic and varied
        let in0_priv = Scalar::from(x ^ 0x1111);
        let in0_blind = Scalar::from(x.rotate_left(7));

        let in1_amount = Scalar::from((x >> 3) % 64); // keep smallish to vary output sums
        let in1_priv = Scalar::from(x ^ 0x2222);
        let in1_blind = Scalar::from(x.rotate_left(13));

        // Split out0 randomly but <= in1_amount
        let out0_raw = (x >> 17) % 65;
        let out0_amount = Scalar::from(std::cmp::min(out0_raw, (x >> 3) % 64));

        let out0_pub = Scalar::from(x ^ 0x3333);
        let out0_blind = Scalar::from(x.rotate_left(29));

        let out1_pub = Scalar::from(x ^ 0x4444);
        let out1_blind = Scalar::from(x.rotate_left(41));

        let case = TxCase::new(
            real_idx,
            in0_priv,
            in0_blind,
            in1_amount,
            in1_priv,
            in1_blind,
            out0_amount,
            out0_pub,
            out0_blind,
            out1_pub,
            out1_blind,
        );

        run_case(&wasm, &r1cs, &case).with_context(|| {
            format!("randomized-lcg failed at case_idx={case_idx}, real_idx={real_idx}")
        })?;
    }

    Ok(())
}

#[tokio::test]
async fn test_transaction2_many_indices_small_amounts() -> anyhow::Result<()> {
    // === PATH SETUP ===
    let out_dir = PathBuf::from(env!("CIRCUIT_OUT_DIR"));
    let wasm = out_dir.join("wasm/transaction2_js/transaction2.wasm");
    let r1cs = out_dir.join("transaction2.r1cs");

    if !wasm.exists() {
        return Err(anyhow::anyhow!("WASM file not found at {}", wasm.display()));
    }
    if !r1cs.exists() {
        return Err(anyhow::anyhow!("R1CS file not found at {}", r1cs.display()));
    }

    // === TRY MANY INDICES WITH TINY AMOUNTS (CORNER-ISH) ===
    let indices: [usize; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16, 23, 27, 31];

    for &real_idx in &indices {
        let in0_priv = Scalar::from(2u64);
        let in0_blind = Scalar::from(3u64);

        let in1_amount = Scalar::from(1u64); // super small amount
        let in1_priv = Scalar::from(5u64);
        let in1_blind = Scalar::from(7u64);

        // Split: either 0/1 or 1/0 depending on index parity
        let out0_amount = if real_idx % 2 == 0 {
            Scalar::from(0u64)
        } else {
            Scalar::from(1u64)
        };
        let out0_pub = Scalar::from(100u64 + real_idx as u64);
        let out0_blind = Scalar::from(200u64 + real_idx as u64);

        let out1_pub = Scalar::from(300u64 + real_idx as u64);
        let out1_blind = Scalar::from(400u64 + real_idx as u64);

        let case = TxCase::new(
            real_idx,
            in0_priv,
            in0_blind,
            in1_amount,
            in1_priv,
            in1_blind,
            out0_amount,
            out0_pub,
            out0_blind,
            out1_pub,
            out1_blind,
        );

        run_case(&wasm, &r1cs, &case)
            .with_context(|| format!("many-indices-small-amounts failed at real_idx={real_idx}"))?;
    }

    Ok(())
}
