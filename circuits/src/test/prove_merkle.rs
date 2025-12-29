#[cfg(test)]
mod tests {
    use crate::test::utils::{
        circom_tester::generate_keys,
        general::{load_artifacts, scalar_to_bigint},
        merkle_tree::{merkle_proof, merkle_root},
    };

    use crate::test::utils::circom_tester::{CircuitKeys, Inputs, prove_and_verify_with_keys};
    use anyhow::{Context, Result};
    use num_bigint::BigInt;
    use std::path::PathBuf;
    use zkhash::fields::bn256::FpBN256 as Scalar;

    /// Run a Merkle proof test case
    ///
    /// Tests the Merkle proof circuit by computing a Merkle root and proof in
    /// Rust, then verifying the circuit produces matching results. Uses
    /// precomputed keys for efficiency when running multiple test cases.
    ///
    /// # Arguments
    ///
    /// * `wasm` - Path to the compiled WASM file
    /// * `r1cs` - Path to the R1CS constraint system file
    /// * `leaves` - Vector of leaf scalar values
    /// * `leaf_index` - Index of the leaf to generate a proof for
    /// * `expected_levels` - Expected number of levels in the tree
    /// * `keys` - Precomputed circuit keys for efficient proving
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the proof verifies and the computed root matches the
    /// circuit output, or an error if verification fails or roots don't
    /// match.
    fn run_case(
        wasm: &PathBuf,
        r1cs: &PathBuf,
        leaves: Vec<Scalar>,
        leaf_index: usize,
        expected_levels: usize,
        keys: &CircuitKeys,
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

        let mut inputs = Inputs::new();
        inputs.set("leaf", leaf_val);
        inputs.set("root", &root_val);
        inputs.set("pathElements", path_elems);
        inputs.set("pathIndices", path_idx);

        // Prove and verify
        let res = prove_and_verify_with_keys(wasm, r1cs, &inputs, keys)
            .context("Failed to prove and verify circuit")?;

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

    #[test]
    #[ignore]
    fn test_merkle_5_levels_matrix() -> anyhow::Result<()> {
        // === PATH SETUP ===
        let (wasm, r1cs) = load_artifacts("merkleProof_5")?;

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

        let keys = generate_keys(&wasm, &r1cs)?;

        // Run cases
        for &idx in &indices {
            run_case(&wasm, &r1cs, leaves_a.clone(), idx, LEVELS, &keys)
                .with_context(|| format!("Case A failed at index {idx}"))?;
            run_case(&wasm, &r1cs, leaves_b.clone(), idx, LEVELS, &keys)
                .with_context(|| format!("Case B failed at index {idx}"))?;
            run_case(&wasm, &r1cs, leaves_c.clone(), idx, LEVELS, &keys)
                .with_context(|| format!("Case C failed at index {idx}"))?;
            run_case(&wasm, &r1cs, leaves_d.clone(), idx, LEVELS, &keys)
                .with_context(|| format!("Case D failed at index {idx}"))?;
        }

        Ok(())
    }
}
