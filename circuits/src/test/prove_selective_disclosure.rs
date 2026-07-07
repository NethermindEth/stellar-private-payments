#[cfg(test)]
mod tests {
    use crate::test::utils::{
        circom_tester::{CircuitKeys, Inputs, generate_keys, prove_and_verify_with_keys},
        general::{load_artifacts, scalar_to_bigint},
        keypair::{derive_public_key, sign},
        merkle_tree::{merkle_proof, merkle_root},
        transaction::{commitment, nullifier, prepopulated_leaves},
    };
    use anyhow::{Context, Result};
    use num_bigint::BigInt;
    use std::{
        panic::{self, AssertUnwindSafe},
        path::Path,
    };
    use zkhash::fields::bn256::FpBN256 as Scalar;

    /// Returns `true` when the prover produced a verifying proof for the given
    /// inputs. Any other outcome (a returned `Err`, a `verified == false`
    /// result, or a panic from the WASM witness calculator) counts as a
    /// rejection and yields `false`, so negative tests can assert on this
    /// uniformly regardless of which layer trips first.
    /// This is needed because `arkworks` and `wasmer` might panic or return
    /// depending on in which layer the error is found.
    fn proof_verifies(
        wasm: impl AsRef<Path>,
        r1cs: impl AsRef<Path>,
        inputs: &Inputs,
        keys: &CircuitKeys,
    ) -> bool {
        let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
            prove_and_verify_with_keys(wasm.as_ref(), r1cs.as_ref(), inputs, keys)
        }));
        matches!(outcome, Ok(Ok(ref res)) if res.verified)
    }

    const LEVELS: usize = 10;
    const EXT_CONTEXT_HASH: u64 = 0xC0FFEE_u64;

    /// Note material for a single selective-disclosure proof.
    #[derive(Clone)]
    struct DisclosureNote {
        leaf_index: usize,
        priv_key: Scalar,
        blinding: Scalar,
        amount: Scalar,
    }

    fn build_inputs(
        notes: &[DisclosureNote],
        leaves: &mut [Scalar],
        ext_context_hash: Scalar,
    ) -> Result<Inputs> {
        let mut roots = Vec::with_capacity(notes.len());
        let mut note_commitments = Vec::with_capacity(notes.len());
        let mut output_nullifiers = Vec::with_capacity(notes.len());
        let mut in_amount = Vec::with_capacity(notes.len());
        let mut in_private_key = Vec::with_capacity(notes.len());
        let mut in_blinding = Vec::with_capacity(notes.len());
        let mut in_path_indices = Vec::with_capacity(notes.len());
        let mut in_path_elements = Vec::new();

        for note in notes {
            let pub_key = derive_public_key(note.priv_key);
            let note_commitment = commitment(note.amount, pub_key, note.blinding);

            leaves[note.leaf_index] = note_commitment;

            let root = merkle_root(leaves.to_vec());
            let (siblings, path_idx_u64, depth) = merkle_proof(leaves, note.leaf_index);
            assert_eq!(
                depth, LEVELS,
                "unexpected Merkle depth: expected {LEVELS}, got {depth}"
            );

            let path_indices = Scalar::from(path_idx_u64);
            let sig = sign(note.priv_key, note_commitment, path_indices);
            let note_nullifier = nullifier(note_commitment, path_indices, sig);

            roots.push(scalar_to_bigint(root));
            note_commitments.push(scalar_to_bigint(note_commitment));
            output_nullifiers.push(scalar_to_bigint(note_nullifier));
            in_amount.push(note.amount);
            in_private_key.push(note.priv_key);
            in_blinding.push(note.blinding);
            in_path_indices.push(path_indices);
            in_path_elements.extend(siblings.into_iter().map(scalar_to_bigint));
        }

        let mut inputs = Inputs::new();
        inputs.set("roots", roots);
        inputs.set("noteCommitments", note_commitments);
        inputs.set("extContextHash", ext_context_hash);
        inputs.set("expectedNullifier", output_nullifiers);
        inputs.set("inAmount", in_amount);
        inputs.set("inPrivateKey", in_private_key);
        inputs.set("inBlinding", in_blinding);
        inputs.set("inPathIndices", in_path_indices);
        inputs.set("inPathElements", in_path_elements);
        Ok(inputs)
    }

    fn sample_note(leaf_index: usize, priv_key: u64, blinding: u64, amount: u64) -> DisclosureNote {
        DisclosureNote {
            leaf_index,
            priv_key: Scalar::from(priv_key),
            blinding: Scalar::from(blinding),
            amount: Scalar::from(amount),
        }
    }

    fn sample_leaves(notes: &[DisclosureNote]) -> Vec<Scalar> {
        let indices: Vec<usize> = notes.iter().map(|n| n.leaf_index).collect();
        prepopulated_leaves(LEVELS, 0xD15C_105E_u64, &indices, 24)
    }

    #[allow(clippy::arithmetic_side_effects)]
    fn run_valid_note_test(n_notes: usize) -> Result<()> {
        let circuit = format!("selectiveDisclosure_{n_notes}");
        let (wasm, r1cs) = load_artifacts(&circuit).expect("Cannot find {circuit} artifacts");
        let keys = generate_keys(&wasm, &r1cs).expect("Groth16 key generation failed");

        let notes: Vec<DisclosureNote> = (0..n_notes)
            .map(|i| sample_note(7 + i * 5, 4242 + i as u64, 5151 + i as u64, 17 + i as u64))
            .collect();
        let mut leaves = sample_leaves(&notes);
        let inputs = build_inputs(&notes, &mut leaves, Scalar::from(EXT_CONTEXT_HASH))?;
        let res = prove_and_verify_with_keys(&wasm, &r1cs, &inputs, &keys)
            .context("prove_and_verify failed")?;
        assert!(res.verified, "selective disclosure proof did not verify");
        Ok(())
    }

    #[test]
    #[ignore]
    fn test_selective_disclosure_valid_1_note() -> Result<()> {
        run_valid_note_test(1)
    }

    #[test]
    #[ignore]
    fn test_selective_disclosure_valid_2_notes() -> Result<()> {
        run_valid_note_test(2)
    }

    #[test]
    #[ignore]
    fn test_selective_disclosure_valid_3_notes() -> Result<()> {
        run_valid_note_test(3)
    }

    #[test]
    #[ignore]
    fn test_selective_disclosure_valid_4_notes() -> Result<()> {
        run_valid_note_test(4)
    }

    #[test]
    #[ignore]
    fn test_selective_disclosure_1_wrong_private_key_fails() {
        let (wasm, r1cs) = load_artifacts("selectiveDisclosure_1")
            .expect("Cannot find selectiveDisclosure_1 artifacts");
        let keys = generate_keys(&wasm, &r1cs).expect("Groth16 key generation failed");

        let note = sample_note(14, 4242, 5151, 17);
        let mut leaves = sample_leaves(std::slice::from_ref(&note));
        let mut inputs = build_inputs(
            std::slice::from_ref(&note),
            &mut leaves,
            Scalar::from(EXT_CONTEXT_HASH),
        )
        .expect("witness inputs");
        inputs.set("inPrivateKey", vec![Scalar::from(9999u64)]);

        assert!(
            !proof_verifies(&wasm, &r1cs, &inputs, &keys),
            "Wrong private key case unexpectedly verified; expected rejection"
        );
    }

    #[test]
    #[ignore]
    fn test_selective_disclosure_1_wrong_amount_fails() {
        let (wasm, r1cs) = load_artifacts("selectiveDisclosure_1")
            .expect("Cannot find selectiveDisclosure_1 artifacts");
        let keys = generate_keys(&wasm, &r1cs).expect("Groth16 key generation failed");

        let note = sample_note(18, 4242, 5151, 17);
        let mut leaves = sample_leaves(std::slice::from_ref(&note));
        let mut inputs = build_inputs(
            std::slice::from_ref(&note),
            &mut leaves,
            Scalar::from(EXT_CONTEXT_HASH),
        )
        .expect("witness inputs");
        inputs.set("inAmount", vec![Scalar::from(9999u64)]);

        assert!(
            !proof_verifies(&wasm, &r1cs, &inputs, &keys),
            "Wrong amount case unexpectedly verified; expected rejection"
        );
    }

    #[test]
    #[ignore]
    fn test_selective_disclosure_1_wrong_blinding_fails() {
        let (wasm, r1cs) = load_artifacts("selectiveDisclosure_1")
            .expect("Cannot find selectiveDisclosure_1 artifacts");
        let keys = generate_keys(&wasm, &r1cs).expect("Groth16 key generation failed");

        let note = sample_note(25, 4242, 5151, 17);
        let mut leaves = sample_leaves(std::slice::from_ref(&note));
        let mut inputs = build_inputs(
            std::slice::from_ref(&note),
            &mut leaves,
            Scalar::from(EXT_CONTEXT_HASH),
        )
        .expect("witness inputs");
        inputs.set("inBlinding", vec![Scalar::from(8888u64)]);

        assert!(
            !proof_verifies(&wasm, &r1cs, &inputs, &keys),
            "Wrong blinding case unexpectedly verified; expected rejection"
        );
    }

    #[test]
    #[ignore]
    fn test_selective_disclosure_1_wrong_path_fails() {
        let (wasm, r1cs) = load_artifacts("selectiveDisclosure_1")
            .expect("Cannot find selectiveDisclosure_1 artifacts");
        let keys = generate_keys(&wasm, &r1cs).expect("Groth16 key generation failed");

        let note = sample_note(21, 4242, 5151, 17);
        let mut leaves = sample_leaves(std::slice::from_ref(&note));
        let mut inputs = build_inputs(
            std::slice::from_ref(&note),
            &mut leaves,
            Scalar::from(EXT_CONTEXT_HASH),
        )
        .expect("witness inputs");
        let zeros: Vec<BigInt> = (0..LEVELS).map(|_| BigInt::from(0u32)).collect();
        inputs.set("inPathElements", zeros);

        assert!(
            !proof_verifies(&wasm, &r1cs, &inputs, &keys),
            "Wrong Merkle path case unexpectedly verified; expected rejection"
        );
    }

    #[test]
    #[ignore]
    fn test_selective_disclosure_1_wrong_root_fails() {
        let (wasm, r1cs) = load_artifacts("selectiveDisclosure_1")
            .expect("Cannot find selectiveDisclosure_1 artifacts");
        let keys = generate_keys(&wasm, &r1cs).expect("Groth16 key generation failed");

        let note = sample_note(28, 4242, 5151, 17);
        let mut leaves = sample_leaves(std::slice::from_ref(&note));
        let mut inputs = build_inputs(
            std::slice::from_ref(&note),
            &mut leaves,
            Scalar::from(EXT_CONTEXT_HASH),
        )
        .expect("witness inputs");
        inputs.set("roots", vec![scalar_to_bigint(Scalar::from(12345u64))]);

        assert!(
            !proof_verifies(&wasm, &r1cs, &inputs, &keys),
            "Wrong root case unexpectedly verified; expected rejection"
        );
    }

    #[test]
    #[ignore]
    fn test_selective_disclosure_1_wrong_note_commitment_fails() {
        let (wasm, r1cs) = load_artifacts("selectiveDisclosure_1")
            .expect("Cannot find selectiveDisclosure_1 artifacts");
        let keys = generate_keys(&wasm, &r1cs).expect("Groth16 key generation failed");

        let note = sample_note(35, 4242, 5151, 17);
        let mut leaves = sample_leaves(std::slice::from_ref(&note));
        let mut inputs = build_inputs(
            std::slice::from_ref(&note),
            &mut leaves,
            Scalar::from(EXT_CONTEXT_HASH),
        )
        .expect("witness inputs");
        inputs.set(
            "noteCommitments",
            vec![scalar_to_bigint(Scalar::from(99999u64))],
        );

        assert!(
            !proof_verifies(&wasm, &r1cs, &inputs, &keys),
            "Wrong note commitment case unexpectedly verified; expected rejection"
        );
    }
}
