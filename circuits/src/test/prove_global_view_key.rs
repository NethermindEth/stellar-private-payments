#[cfg(test)]
mod tests {
    use crate::test::utils::{
        circom_tester::{
            CircuitKeys, Inputs, generate_keys, prove_and_verify, prove_and_verify_with_keys,
        },
        general::load_artifacts,
        global_view_key::{Note, admin_public_key, decrypt_note, encrypt_note},
    };
    use anyhow::Result;
    use ark_bn254::Fr;
    use ark_ff::{BigInteger, PrimeField};
    use core::str::FromStr;
    use std::{
        panic::{self, AssertUnwindSafe},
        path::Path,
    };
    use zkhash::fields::bn256::FpBN256 as Scalar;

    /// `p - 1`, the `y`-coordinate of the Baby JubJub order-2 point `(0, -1)`.
    const NEG_ONE: &str =
        "21888242871839275222246405745257275088548364400416034343698204186575808495616";

    fn sample_note() -> Note {
        Note {
            pk: Scalar::from(0xABCDu64),
            amount: Scalar::from(1_000_000u64),
            blinding: Scalar::from(0xDEAD_BEEFu64),
        }
    }

    /// Distinct sample notes so multi-note circuits exercise different plaintext.
    #[allow(clippy::arithmetic_side_effects)]
    fn sample_notes(n: usize) -> Vec<Note> {
        (0..n)
            .map(|i| {
                let i = u64::try_from(i).expect("small note index");
                Note {
                    pk: Scalar::from(100u64 + i),
                    amount: Scalar::from(1_000u64 + i),
                    blinding: Scalar::from(7u64 + i),
                }
            })
            .collect()
    }

    /// Build the circuit inputs for `GlobalViewKey(n)`: shared `D`/`nonce` and a
    /// per-note plaintext vector. The circuit assigns `idx = 0..n-1` internally.
    fn gvk_inputs(notes: &[Note], d: (Scalar, Scalar), nonce: Scalar) -> Inputs {
        let mut inputs = Inputs::new();
        inputs.set("D", vec![d.0, d.1]);
        inputs.set("nonce", nonce);
        inputs.set("pk", notes.iter().map(|n| n.pk).collect::<Vec<_>>());
        inputs.set("amount", notes.iter().map(|n| n.amount).collect::<Vec<_>>());
        inputs.set(
            "blinding",
            notes.iter().map(|n| n.blinding).collect::<Vec<_>>(),
        );
        inputs
    }

    fn fr_to_scalar(fr: Fr) -> Scalar {
        Scalar::from_le_bytes_mod_order(&fr.into_bigint().to_bytes_le())
    }

    /// Returns `true` when the prover produced a verifying proof. Any other
    /// outcome (an `Err`, `verified == false`, or a panic in the WASM witness
    /// calculator when a constraint is violated) counts as a rejection, so
    /// negative tests can assert uniformly.
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

    // === Fast pure-Rust reference checks (no proving) ===

    /// The admin recovers the plaintext from the ciphertext using only the
    /// authority private scalar.
    #[test]
    fn known_answer_roundtrip_pure_rust() {
        let d_priv = Scalar::from(987_654_321u64);
        let d = admin_public_key(d_priv);
        let note = sample_note();
        let ct = encrypt_note(&note, d, Scalar::from(42u64), Scalar::from(0u64));
        assert_eq!(
            decrypt_note(&ct, d_priv),
            note,
            "decryption must recover the note"
        );
    }

    /// Notes sharing `D`/`nonce` but differing in `idx` must produce different
    /// keystreams — even for identical plaintext — so keystreams are never
    /// reused across the notes of one transaction.
    #[test]
    fn keystream_no_reuse_across_idx() {
        let d = admin_public_key(Scalar::from(11u64));
        let nonce = Scalar::from(99u64);
        let note = sample_note();
        let ct0 = encrypt_note(&note, d, nonce, Scalar::from(0u64));
        let ct1 = encrypt_note(&note, d, nonce, Scalar::from(1u64));
        assert_ne!(
            ct0.r, ct1.r,
            "different idx must yield a different ephemeral key"
        );
        assert_ne!(
            ct0.c1, ct1.c1,
            "different idx must yield a different keystream"
        );
    }

    /// A different nonce yields a different ciphertext for the same note, which
    /// is why the nonce must be unique per transaction (a reused nonce makes
    /// identical notes publicly linkable).
    #[test]
    fn distinct_nonce_changes_ciphertext() {
        let d = admin_public_key(Scalar::from(11u64));
        let note = sample_note();
        let a = encrypt_note(&note, d, Scalar::from(1u64), Scalar::from(0u64));
        let b = encrypt_note(&note, d, Scalar::from(2u64), Scalar::from(0u64));
        assert_ne!(a.r, b.r);
        assert_ne!(a.c1, b.c1);
    }

    /// A tampered ciphertext does not decrypt back to the original note.
    #[test]
    fn tampered_ciphertext_not_recovered() {
        let d_priv = Scalar::from(7u64);
        let d = admin_public_key(d_priv);
        let note = sample_note();
        let mut ct = encrypt_note(&note, d, Scalar::from(5u64), Scalar::from(0u64));
        ct.c1 = Scalar::from(0x1234_5678u64); // overwrite with an unrelated value
        assert_ne!(
            decrypt_note(&ct, d_priv),
            note,
            "tampered ciphertext must not decrypt to the original note",
        );
    }

    // === Circuit known-answer (single note) ===

    /// The `globalViewKey_test` circuit asserts `R/c1/c2/c3` equal the
    /// Rust-computed values, so a verifying proof means the in-circuit math
    /// matches the reference implementation.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn known_answer_matches_circuit() -> Result<()> {
        let (wasm, r1cs) = load_artifacts("globalViewKey_test")?;

        let d_priv = Scalar::from(987_654_321u64);
        let d = admin_public_key(d_priv);
        let note = sample_note();
        let nonce = Scalar::from(42u64);
        let idx = Scalar::from(0u64);
        let ct = encrypt_note(&note, d, nonce, idx);

        let mut inputs = Inputs::new();
        inputs.set("D", vec![d.0, d.1]);
        inputs.set("nonce", nonce);
        inputs.set("idx", idx);
        inputs.set("pk", note.pk);
        inputs.set("amount", note.amount);
        inputs.set("blinding", note.blinding);
        inputs.set("expectedR", vec![ct.r.0, ct.r.1]);
        inputs.set("expectedC1", ct.c1);
        inputs.set("expectedC2", ct.c2);
        inputs.set("expectedC3", ct.c3);

        let res = prove_and_verify(&wasm, &r1cs, &inputs)?;
        assert!(res.verified, "GVK known-answer proof did not verify");
        Ok(())
    }

    // === Full entry-point proofs (expensive) ===

    /// Prove `globalViewKey_{n}`, verify, and confirm the public signals equal
    /// the reference ciphertext (order-independent multiset match), then check
    /// the admin decrypts each note back from those ciphertexts.
    fn run_gvk_roundtrip(n: usize) -> Result<()> {
        let circuit = format!("globalViewKey_{n}");
        let (wasm, r1cs) = load_artifacts(&circuit)?;
        let keys = generate_keys(&wasm, &r1cs)?;

        let d_priv = Scalar::from(0x5EEDu64);
        let d = admin_public_key(d_priv);
        let nonce = Scalar::from(0xABCD_1234u64);
        let notes = sample_notes(n);

        let res = prove_and_verify_with_keys(&wasm, &r1cs, &gvk_inputs(&notes, d, nonce), &keys)?;
        assert!(res.verified, "{circuit} proof did not verify");

        let mut expected: Vec<Scalar> = Vec::new();
        for (i, note) in notes.iter().enumerate() {
            let idx = Scalar::from(u64::try_from(i).expect("small note index"));
            let ct = encrypt_note(note, d, nonce, idx);
            assert_eq!(
                decrypt_note(&ct, d_priv),
                *note,
                "admin must recover note {i}"
            );
            expected.extend([ct.r.0, ct.r.1, ct.c1, ct.c2, ct.c3]);
        }
        expected.extend([d.0, d.1, nonce]);

        let mut actual: Vec<Scalar> = res
            .public_inputs
            .iter()
            .map(|fr| fr_to_scalar(*fr))
            .collect();
        expected.sort();
        actual.sort();
        assert_eq!(
            actual, expected,
            "circuit public signals must equal the reference ciphertext",
        );
        Ok(())
    }

    #[test]
    #[ignore]
    fn gvk_2_view_only_proves_and_roundtrips() -> Result<()> {
        run_gvk_roundtrip(2)
    }

    #[test]
    #[ignore]
    fn gvk_4_traceable_proves_and_roundtrips() -> Result<()> {
        run_gvk_roundtrip(4)
    }

    #[test]
    #[ignore]
    fn gvk_2_off_curve_d_rejected() {
        let (wasm, r1cs) = load_artifacts("globalViewKey_2").expect("globalViewKey_2 artifacts");
        let keys = generate_keys(&wasm, &r1cs).expect("Groth16 key generation failed");

        // (1, 1) does not satisfy the Baby JubJub curve equation, so BabyCheck fails.
        let bad_d = (Scalar::from(1u64), Scalar::from(1u64));
        let inputs = gvk_inputs(&sample_notes(2), bad_d, Scalar::from(3u64));

        assert!(
            !proof_verifies(&wasm, &r1cs, &inputs, &keys),
            "off-curve D unexpectedly verified; expected rejection",
        );
    }

    #[test]
    #[ignore]
    fn gvk_2_low_order_d_rejected() {
        let (wasm, r1cs) = load_artifacts("globalViewKey_2").expect("globalViewKey_2 artifacts");
        let keys = generate_keys(&wasm, &r1cs).expect("Groth16 key generation failed");

        // (0, -1) is on-curve but has order 2, so 8*D is the identity and the
        // low-order guard (x(8*D) != 0) rejects it.
        let neg_one = Scalar::from_str(NEG_ONE).expect("valid p-1 constant");
        let bad_d = (Scalar::from(0u64), neg_one);
        let inputs = gvk_inputs(&sample_notes(2), bad_d, Scalar::from(3u64));

        assert!(
            !proof_verifies(&wasm, &r1cs, &inputs, &keys),
            "low-order D unexpectedly verified; expected rejection",
        );
    }
}
