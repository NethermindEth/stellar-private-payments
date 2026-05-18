#[cfg(test)]
mod tests {
    use crate::test::utils::{
        circom_tester::{CircuitKeys, Inputs, generate_keys, prove_and_verify_with_keys},
        general::{load_artifacts, scalar_to_bigint},
        keypair::derive_public_key,
        merkle_tree::{merkle_proof, merkle_root},
        transaction::{commitment, prepopulated_leaves},
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
    struct DisclosureNote {
        leaf_index: usize,
        priv_key: Scalar,
        blinding: Scalar,
        amount: Scalar,
    }

    fn build_inputs(
        note: &DisclosureNote,
        leaves: &[Scalar],
        ext_context_hash: Scalar,
    ) -> Result<Inputs> {
        let pub_key = derive_public_key(note.priv_key);
        let note_commitment = commitment(note.amount, pub_key, note.blinding);

        let mut frozen = leaves.to_vec();
        frozen[note.leaf_index] = note_commitment;

        let root = merkle_root(frozen.clone());
        let (siblings, path_idx_u64, depth) = merkle_proof(&frozen, note.leaf_index);
        assert_eq!(
            depth, LEVELS,
            "unexpected Merkle depth: expected {LEVELS}, got {depth}"
        );

        let path_elements: Vec<BigInt> = siblings.into_iter().map(scalar_to_bigint).collect();

        let mut inputs = Inputs::new();
        inputs.set("roots", vec![scalar_to_bigint(root)]);
        inputs.set("noteCommitments", vec![scalar_to_bigint(note_commitment)]);
        inputs.set("extContextHash", ext_context_hash);
        inputs.set("inAmount", vec![note.amount]);
        inputs.set("inPrivateKey", vec![note.priv_key]);
        inputs.set("inBlinding", vec![note.blinding]);
        inputs.set("inPathIndices", vec![Scalar::from(path_idx_u64)]);
        inputs.set("inPathElements", path_elements);
        Ok(inputs)
    }

    fn sample_note(leaf_index: usize) -> DisclosureNote {
        DisclosureNote {
            leaf_index,
            priv_key: Scalar::from(4242u64),
            blinding: Scalar::from(5151u64),
            amount: Scalar::from(17u64),
        }
    }

    fn sample_leaves(note: &DisclosureNote) -> Vec<Scalar> {
        prepopulated_leaves(LEVELS, 0xD15C_105E_u64, &[note.leaf_index], 24)
    }

    #[test]
    #[ignore]
    fn test_selective_disclosure_valid_note() -> Result<()> {
        let (wasm, r1cs) = load_artifacts("selectiveDisclosure_1")
            .expect("Cannot find selectiveDisclosure_1 artifacts");
        let keys = generate_keys(&wasm, &r1cs).expect("Groth16 key generation failed");

        let note = sample_note(7);
        let leaves = sample_leaves(&note);
        let inputs = build_inputs(&note, &leaves, Scalar::from(EXT_CONTEXT_HASH))?;
        let res = prove_and_verify_with_keys(&wasm, &r1cs, &inputs, &keys)
            .context("prove_and_verify failed")?;
        assert!(res.verified, "selective disclosure proof did not verify");
        Ok(())
    }

    #[test]
    #[ignore]
    fn test_selective_disclosure_wrong_private_key_fails() {
        let (wasm, r1cs) = load_artifacts("selectiveDisclosure_1")
            .expect("Cannot find selectiveDisclosure_1 artifacts");
        let keys = generate_keys(&wasm, &r1cs).expect("Groth16 key generation failed");

        let note = sample_note(14);
        let leaves = sample_leaves(&note);
        let mut inputs =
            build_inputs(&note, &leaves, Scalar::from(EXT_CONTEXT_HASH)).expect("witness inputs");
        inputs.set("inPrivateKey", vec![Scalar::from(9999u64)]);

        assert!(
            !proof_verifies(&wasm, &r1cs, &inputs, &keys),
            "Wrong private key case unexpectedly verified; expected rejection"
        );
    }

    #[test]
    #[ignore]
    fn test_selective_disclosure_wrong_amount_fails() {
        let (wasm, r1cs) = load_artifacts("selectiveDisclosure_1")
            .expect("Cannot find selectiveDisclosure_1 artifacts");
        let keys = generate_keys(&wasm, &r1cs).expect("Groth16 key generation failed");

        let note = sample_note(18);
        let leaves = sample_leaves(&note);
        let mut inputs =
            build_inputs(&note, &leaves, Scalar::from(EXT_CONTEXT_HASH)).expect("witness inputs");
        inputs.set("inAmount", vec![Scalar::from(9999u64)]);

        assert!(
            !proof_verifies(&wasm, &r1cs, &inputs, &keys),
            "Wrong amount case unexpectedly verified; expected rejection"
        );
    }

    #[test]
    #[ignore]
    fn test_selective_disclosure_wrong_blinding_fails() {
        let (wasm, r1cs) = load_artifacts("selectiveDisclosure_1")
            .expect("Cannot find selectiveDisclosure_1 artifacts");
        let keys = generate_keys(&wasm, &r1cs).expect("Groth16 key generation failed");

        let note = sample_note(25);
        let leaves = sample_leaves(&note);
        let mut inputs =
            build_inputs(&note, &leaves, Scalar::from(EXT_CONTEXT_HASH)).expect("witness inputs");
        inputs.set("inBlinding", vec![Scalar::from(8888u64)]);

        assert!(
            !proof_verifies(&wasm, &r1cs, &inputs, &keys),
            "Wrong blinding case unexpectedly verified; expected rejection"
        );
    }

    #[test]
    #[ignore]
    fn test_selective_disclosure_wrong_path_fails() {
        let (wasm, r1cs) = load_artifacts("selectiveDisclosure_1")
            .expect("Cannot find selectiveDisclosure_1 artifacts");
        let keys = generate_keys(&wasm, &r1cs).expect("Groth16 key generation failed");

        let note = sample_note(21);
        let leaves = sample_leaves(&note);
        let mut inputs =
            build_inputs(&note, &leaves, Scalar::from(EXT_CONTEXT_HASH)).expect("witness inputs");
        let zeros: Vec<BigInt> = (0..LEVELS).map(|_| BigInt::from(0u32)).collect();
        inputs.set("inPathElements", zeros);

        assert!(
            !proof_verifies(&wasm, &r1cs, &inputs, &keys),
            "Wrong Merkle path case unexpectedly verified; expected rejection"
        );
    }

    #[test]
    #[ignore]
    fn test_selective_disclosure_wrong_root_fails() {
        let (wasm, r1cs) = load_artifacts("selectiveDisclosure_1")
            .expect("Cannot find selectiveDisclosure_1 artifacts");
        let keys = generate_keys(&wasm, &r1cs).expect("Groth16 key generation failed");

        let note = sample_note(28);
        let leaves = sample_leaves(&note);
        let mut inputs =
            build_inputs(&note, &leaves, Scalar::from(EXT_CONTEXT_HASH)).expect("witness inputs");
        inputs.set("roots", vec![scalar_to_bigint(Scalar::from(12345u64))]);

        assert!(
            !proof_verifies(&wasm, &r1cs, &inputs, &keys),
            "Wrong root case unexpectedly verified; expected rejection"
        );
    }

    #[test]
    #[ignore]
    fn test_selective_disclosure_wrong_note_commitment_fails() {
        let (wasm, r1cs) = load_artifacts("selectiveDisclosure_1")
            .expect("Cannot find selectiveDisclosure_1 artifacts");
        let keys = generate_keys(&wasm, &r1cs).expect("Groth16 key generation failed");

        let note = sample_note(35);
        let leaves = sample_leaves(&note);
        let mut inputs =
            build_inputs(&note, &leaves, Scalar::from(EXT_CONTEXT_HASH)).expect("witness inputs");
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
