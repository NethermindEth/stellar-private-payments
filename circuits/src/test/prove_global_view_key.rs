#[cfg(test)]
mod tests {
    use crate::test::utils::{
        circom_tester::{Inputs, prove_and_verify},
        general::load_artifacts,
        global_view_key::{Note, admin_public_key, decrypt_note, encrypt_note},
    };
    use anyhow::Result;
    use zkhash::fields::bn256::FpBN256 as Scalar;

    fn sample_note() -> Note {
        Note {
            pk: Scalar::from(0xABCDu64),
            amount: Scalar::from(1_000_000u64),
            blinding: Scalar::from(0xDEAD_BEEFu64),
        }
    }

    /// Pure-Rust sanity check: the admin recovers the plaintext from the
    /// ciphertext using only the authority private scalar. Fast, no circuit.
    #[test]
    fn known_answer_roundtrip_pure_rust() {
        let d_priv = Scalar::from(987_654_321u64);
        let d = admin_public_key(d_priv);
        let note = sample_note();
        let nonce = Scalar::from(42u64);
        let idx = Scalar::from(0u64);

        let ct = encrypt_note(&note, d, nonce, idx);
        let recovered = decrypt_note(&ct, d_priv);

        assert_eq!(recovered, note, "admin decryption must recover the note");
    }

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
}
