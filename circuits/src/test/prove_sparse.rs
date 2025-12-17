use super::circom_tester::prove_and_verify;
use crate::test::utils::{circom_tester::Inputs, sparse_merkle_tree::prepare_smt_proof};
use anyhow::{Context, Result};
use num_bigint::BigInt;
use std::path::PathBuf;

/// Run a sparse Merkle tree test case
///
/// Tests the sparse Merkle tree circuit by preparing an SMT proof (either inclusion
/// or non-inclusion) and verifying the circuit correctly validates the proof.
///
/// # Arguments
///
/// * `wasm` - Path to the compiled WASM file
/// * `r1cs` - Path to the R1CS constraint system file
/// * `queried_key` - Key to query in the sparse Merkle tree
/// * `max_levels` - Maximum number of levels in the tree
///
/// # Returns
///
/// Returns `Ok(())` if the proof verifies successfully, or an error otherwise.
fn run_case(wasm: &PathBuf, r1cs: &PathBuf, queried_key: BigInt, max_levels: usize) -> Result<()> {
    let smt_proof = prepare_smt_proof(&queried_key, max_levels);

    // Map SMT proof to circuit inputs
    let enabled = BigInt::from(1u32);
    let root = smt_proof.root.clone();

    // The function to use for the SMT (0 = inclusion, 1 = non-inclusion)
    let fnc = if smt_proof.found {
        BigInt::from(0u32)
    } else {
        BigInt::from(1u32)
    };

    // Compute (oldKey, oldValue, isOld0, key, value) according to what smtverifier.circom expects
    let (old_key, old_value, is_old0, key_for_circuit, value_for_circuit) = if smt_proof.found {
        // Inclusion proof
        (
            queried_key.clone(),
            smt_proof.found_value.clone(),
            BigInt::from(0u32),
            queried_key.clone(),
            smt_proof.found_value.clone(),
        )
    } else if smt_proof.is_old0 {
        // Non-inclusion: empty path
        (
            queried_key.clone(),
            BigInt::from(0u32),
            BigInt::from(1u32),
            queried_key.clone(),
            BigInt::from(0u32),
        )
    } else {
        // Non-inclusion: collision with existing leaf
        (
            smt_proof.not_found_key.clone(),
            smt_proof.not_found_value.clone(),
            BigInt::from(0u32),
            queried_key.clone(),
            BigInt::from(0u32),
        )
    };

    let mut inputs = Inputs::new();
    inputs.set("enabled", enabled);
    inputs.set("root", root);
    inputs.set("siblings", smt_proof.siblings.clone());
    inputs.set("oldKey", old_key);
    inputs.set("oldValue", old_value);
    inputs.set("isOld0", is_old0);
    inputs.set("key", key_for_circuit);
    inputs.set("value", value_for_circuit);
    inputs.set("fnc", fnc);

    let res =
        prove_and_verify(wasm, r1cs, &inputs).context("Failed to prove and verify circuit")?;

    assert!(res.verified, "Proof did not verify for key {queried_key}");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::utils::general::load_artifacts;

    #[test]
    #[ignore]
    fn test_sparse_merkle_tree_membership_matrix() -> anyhow::Result<()> {
        // === PATH SETUP ===
        let (wasm, r1cs) = load_artifacts("sparse_merkle_tree")?;

        // === TEST MATRIX ===
        const MAX_LEVELS: usize = 254;

        // Inclusion cases
        let inclusion_keys = [0u32, 1, 50, 99];
        for k in inclusion_keys {
            run_case(&wasm, &r1cs, BigInt::from(k), MAX_LEVELS)
                .with_context(|| format!("Inclusion case failed for key {k}"))?;
        }

        // Non-inclusion cases
        let non_inclusion_keys = [100u32, 200, 123_456];
        for k in non_inclusion_keys {
            run_case(&wasm, &r1cs, BigInt::from(k), MAX_LEVELS)
                .with_context(|| format!("Non-inclusion case failed for key {k}"))?;
        }

        Ok(())
    }
}
