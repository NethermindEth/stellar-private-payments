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

/// Convert a `Scalar` (BN254 field element) into a signed `BigInt`
/// suitable for ark-circom input.
///
/// Circom JSON expects decimal strings for field elements, and
/// `ark_circom::CircomBuilder::push_input` accepts `BigInt`.
/// We obtain the canonical big integer representation (little-endian bytes),
/// convert to an unsigned `BigUint`, then to a signed `BigInt`.
fn scalar_to_bigint(s: Scalar) -> BigInt {
    // Field -> canonical big integer (arkworks `BigInteger`)
    let bi = s.into_bigint();
    // Convert to little-endian bytes so we can feed it to BigUint
    let bytes_le = bi.to_bytes_le();
    let u = BigUint::from_bytes_le(&bytes_le);
    // Finally convert to signed BigInt (non-negative in our use)
    BigInt::from(u)
}

/// Run one end-to-end case: build inputs, compute Rust Merkle root & proof,
/// pass them to the Circom verifier (Groth16), and assert the public output matches.
///
/// # Arguments
/// - `wasm`, `r1cs`: paths to the compiled circom artifacts
/// - `leaves`: the full leaf set (length must be 2^levels for this circuit)
/// - `leaf_index`: the index of the leaf we’ll prove membership for
/// - `expected_levels`: the depth that the circuit was compiled with (e.g. 5)
fn run_case(
    wasm: &PathBuf,
    r1cs: &PathBuf,
    leaves: Vec<Scalar>,
    leaf_index: usize,
    expected_levels: usize,
) -> Result<()> {
    // === Compute the reference values in Rust ===
    // Root of the whole tree from the supplied leaves
    let root_scalar = merkle_root(leaves.clone());
    // The target leaf
    let leaf_scalar = leaves[leaf_index];
    // Merkle path elements (siblings), path index bitfield, and depth
    let (path_elements_scalar, path_indices_u64, levels) = merkle_proof(&leaves, leaf_index);

    // Ensure the runtime proof depth matches the circuit depth.
    // This avoids mismatched arities (e.g., feeding a 4-level proof to a 5-level circuit).
    assert_eq!(
        levels, expected_levels,
        "This executable expects a {expected_levels}-level circuit"
    );

    // === Convert inputs to the format ark-circom expects (BigInt) ===
    let leaf_val = scalar_to_bigint(leaf_scalar);
    let root_val = scalar_to_bigint(root_scalar);
    let path_elems: Vec<BigInt> = path_elements_scalar
        .into_iter()
        .map(scalar_to_bigint)
        .collect();
    // Many Circom templates take pathIndices as a packed integer bitfield:
    // bit i indicates whether the node was on the right (1) or left (0) at level i.
    let path_idx = BigInt::from(path_indices_u64);

    // === Prepare Circom inputs ===
    // - `leaf` and `pathElements` are usually private
    // - `root` is typically declared `signal public` in the circuit
    // - `pathIndices` is private unless your circuit exposes it
    let mut inputs: HashMap<String, InputValue> = HashMap::new();
    inputs.insert("leaf".into(), InputValue::Single(leaf_val));
    inputs.insert("root".into(), InputValue::Single(root_val.clone())); // public
    inputs.insert("pathElements".into(), InputValue::Array(path_elems));
    inputs.insert("pathIndices".into(), InputValue::Single(path_idx));

    // === Prove and verify with ark-groth16 via ark-circom ===
    // Returns: verification status, public inputs, proof object, and VK.
    let res =
        prove_and_verify(wasm, r1cs, &inputs).context("Failed to prove and verify circuit")?;

    // Safety net: verification must succeed
    if !res.verified {
        anyhow::bail!("Proof did not verify");
    }

    // === Cross-check the circuit's public output against the Rust root ===
    // Convention: public_inputs[0] is the root. If your Circom template changes,
    // this index may need to be updated.
    let circom_root_dec = res
        .public_inputs
        .first()
        .expect("missing public root from circuit")
        .to_string();

    // Compare decimal strings to avoid endianness/byte-level mismatches
    let rust_root_dec = root_val.to_string();
    assert_eq!(circom_root_dec, rust_root_dec, "Circom root != Rust root");

    Ok(())
}

/// End-to-end test for a 5-level (32-leaf) Merkle membership circuit.
/// Builds several deterministic leaf patterns and checks a variety of indices
/// across the tree edges and middle to stress both left/right branches.
#[tokio::test]
async fn test_merkle_5_levels_matrix() -> anyhow::Result<()> {
    // === PATH SETUP ===
    // `CIRCUIT_OUT_DIR` is expected to be defined via build.rs or environment.
    let out_dir = PathBuf::from(env!("CIRCUIT_OUT_DIR"));
    // If your build outputs differently, tweak these two lines:
    let wasm = out_dir.join("wasm/merkleProof_5_js/merkleProof_5.wasm");
    let r1cs = out_dir.join("merkleProof_5.r1cs");

    // Fail fast with helpful diagnostics if artifacts are missing
    if !wasm.exists() {
        return Err(anyhow::anyhow!("WASM file not found at {}", wasm.display()));
    }
    if !r1cs.exists() {
        return Err(anyhow::anyhow!("R1CS file not found at {}", r1cs.display()));
    }

    // === TEST MATRIX (5 levels => 32 leaves) ===
    const LEVELS: usize = 5;
    const N: usize = 1 << LEVELS; // 2^LEVELS leaves

    // Case A: sequential 0..N-1
    let leaves_a: Vec<Scalar> = (0u64..N as u64).map(Scalar::from).collect();

    // Case B: affine progression to mix values (still deterministic)
    let leaves_b: Vec<Scalar> = (0u64..N as u64)
        .map(|i| Scalar::from(i.wrapping_mul(7).wrapping_add(3)))
        .collect();

    // Case C: reversed order
    let leaves_c: Vec<Scalar> = (0u64..N as u64).rev().map(Scalar::from).collect();

    // Case D: simple LCG-style generator (deterministic, no external RNG needed)
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

    // === Run all combinations ===
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
