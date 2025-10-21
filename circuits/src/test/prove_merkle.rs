//! Temp Comment
use super::{
    circom_tester::{InputValue, prove_and_verify},
    merkle_tree::{merkle_proof, merkle_root},
};

use anyhow::{Context, Result};
use num_bigint::{BigInt, BigUint};
use std::{collections::HashMap, env, path::PathBuf};
use zkhash::{
    ark_ff::{BigInteger, PrimeField},
    fields::bn256::FpBN256 as Scalar,
};

fn scalar_to_bigint(s: Scalar) -> BigInt {
    let bi = s.into_bigint();
    let bytes_le = bi.to_bytes_le();
    let u = BigUint::from_bytes_le(&bytes_le);
    BigInt::from(u)
}

fn run_case(
    wasm: &PathBuf,
    r1cs: &PathBuf,
    leaves: Vec<Scalar>,
    leaf_index: usize,
    expected_levels: usize,
) -> Result<()> {
    // Compute root and proof in Rust
    let root_scalar = merkle_root(leaves.clone());
    let leaf_scalar = leaves[leaf_index];
    let (path_elements_scalar, path_indices_u64, levels) = merkle_proof(&leaves, leaf_index);

    // Ensure proof depth matches the circuit’s expected depth
    assert_eq!(
        levels, expected_levels,
        "This executable expects a {expected_levels}-level circuit"
    );

    // Convert to BigInt for Circom witness
    let leaf_val = scalar_to_bigint(leaf_scalar);
    let root_val = scalar_to_bigint(root_scalar);
    let path_elems: Vec<BigInt> = path_elements_scalar
        .into_iter()
        .map(scalar_to_bigint)
        .collect();
    let path_idx = BigInt::from(path_indices_u64);

    let mut inputs: HashMap<String, InputValue> = HashMap::new();
    inputs.insert("leaf".into(), InputValue::Single(leaf_val));
    inputs.insert("root".into(), InputValue::Single(root_val.clone())); // public
    inputs.insert("pathElements".into(), InputValue::Array(path_elems));
    inputs.insert("pathIndices".into(), InputValue::Single(path_idx));

    // Prove and verify
    let res =
        prove_and_verify(wasm, r1cs, &inputs).context("Failed to prove and verify circuit")?;

    if !res.verified {
        anyhow::bail!("Proof did not verify");
    }

    // Compare public root
    let circom_root_dec = res
        .public_inputs
        .first()
        .expect("missing public root from circuit")
        .to_string();

    let rust_root_dec = root_val.to_string();
    assert_eq!(circom_root_dec, rust_root_dec, "Circom root != Rust root");

    Ok(())
}

#[tokio::test]
async fn test_merkle_5_levels_matrix() -> anyhow::Result<()> {
    // === PATH SETUP ===
    let out_dir = PathBuf::from(env!("CIRCUIT_OUT_DIR"));
    // If your build outputs differently, tweak these two lines:
    let wasm = out_dir.join("wasm/merkleProof_5_js/merkleProof_5.wasm");
    let r1cs = out_dir.join("merkleProof_5.r1cs");

    if !wasm.exists() {
        return Err(anyhow::anyhow!("WASM file not found at {}", wasm.display()));
    }
    if !r1cs.exists() {
        return Err(anyhow::anyhow!("R1CS file not found at {}", r1cs.display()));
    }

    // === TEST MATRIX (5 levels => 32 leaves) ===
    const LEVELS: usize = 5;
    const N: usize = 1 << LEVELS;

    // Case A: sequential 0..N
    let leaves_a: Vec<Scalar> = (0u64..N as u64).map(Scalar::from).collect();

    // Case B: affine progression to mix values a bit
    let leaves_b: Vec<Scalar> = (0u64..N as u64)
        .map(|i| Scalar::from(i.wrapping_mul(7).wrapping_add(3)))
        .collect();

    // Case C: reversed 0..N-1
    let leaves_c: Vec<Scalar> = (0u64..N as u64).rev().map(Scalar::from).collect();

    // Case D: simple LCG-style mix (deterministic, no extra deps)
    let leaves_d: Vec<Scalar> = {
        let mut x: u64 = 0xDEADBEEFCAFEBABE;
        (0..N)
            .map(|_| {
                // x = x * 2862933555777941757 + 3037000493  (64-bit LCG-ish)
                x = x.wrapping_mul(2862933555777941757).wrapping_add(3037000493);
                Scalar::from(x)
            })
            .collect()
    };

    // Indices to try (cover left/right edges and middle)
    let indices = [0usize, 1, 7, 8, 15, 16, 23, 31];

    // Run cases
    for &idx in &indices {
        run_case(&wasm, &r1cs, leaves_a.clone(), idx, LEVELS)
            .with_context(|| format!("Case A failed at index {idx}"))?;
        run_case(&wasm, &r1cs, leaves_b.clone(), idx, LEVELS)
            .with_context(|| format!("Case B failed at index {idx}"))?;
        run_case(&wasm, &r1cs, leaves_c.clone(), idx, LEVELS)
            .with_context(|| format!("Case C failed at index {idx}"))?;
        run_case(&wasm, &r1cs, leaves_d.clone(), idx, LEVELS)
            .with_context(|| format!("Case D failed at index {idx}"))?;
    }

    println!("All test cases passed for {LEVELS} levels ({N} leaves).");
    Ok(())
}
