#[cfg(test)]
mod tests {
    use crate::test::utils::circom_tester::{Inputs, prove_and_verify};
    use crate::test::utils::general::load_artifacts;
    use crate::test::utils::keypair::{derive_public_key, sign};
    use anyhow::Context;
    use anyhow::Result;
    use std::path::PathBuf;
    use zkhash::fields::bn256::FpBN256 as Scalar;

    /// Run a keypair test case
    ///
    /// Tests the keypair circuit by deriving a public key from a private key
    /// and verifying the circuit produces the expected result.
    ///
    /// # Arguments
    ///
    /// * `wasm` - Path to the compiled WASM file
    /// * `r1cs` - Path to the R1CS constraint system file
    /// * `private_key` - Private key scalar value to test
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the proof verifies successfully, or an error otherwise.
    fn run_keypair_case(wasm: &PathBuf, r1cs: &PathBuf, private_key: Scalar) -> Result<()> {
        // compute expected in Rust
        let expected_pk = derive_public_key(private_key);

        let mut inputs = Inputs::new();
        inputs.set("privateKey", private_key);
        inputs.set("expectedPublicKey", expected_pk);

        let res = prove_and_verify(wasm, r1cs, &inputs)?;
        assert!(res.verified, "Keypair proof did not verify");
        Ok(())
    }

    /// Run a signature test case
    ///
    /// Tests the signature circuit by generating a signature from a private key,
    /// commitment, and merkle path, then verifying the circuit produces the expected result.
    ///
    /// # Arguments
    ///
    /// * `wasm` - Path to the compiled WASM file
    /// * `r1cs` - Path to the R1CS constraint system file
    /// * `private_key` - Private key scalar value
    /// * `commitment` - Commitment scalar value
    /// * `merkle_path` - Merkle path scalar value
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the proof verifies successfully, or an error otherwise.
    fn run_signature_case(
        wasm: &PathBuf,
        r1cs: &PathBuf,
        private_key: Scalar,
        commitment: Scalar,
        merkle_path: Scalar,
    ) -> Result<()> {
        // compute expected in Rust
        let expected_sig = sign(private_key, commitment, merkle_path);

        let mut inputs = Inputs::new();
        inputs.set("privateKey", private_key);
        inputs.set("commitment", commitment);
        inputs.set("merklePath", merkle_path);
        inputs.set("expectedSig", expected_sig);

        let res = prove_and_verify(wasm, r1cs, &inputs)?;
        anyhow::ensure!(res.verified, "Signature proof did not verify");
        Ok(())
    }

    #[test]
    fn test_keypair_test_matrix() -> anyhow::Result<()> {
        // === PATH SETUP ===
        let (wasm, r1cs) = load_artifacts("keypair_test")?;

        // Simple test set
        let cases: [u64; 8] = [0, 1, 2, 7, 8, 15, 16, 23];

        for &x in &cases {
            let sk = Scalar::from(x);
            run_keypair_case(&wasm, &r1cs, sk)
                .with_context(|| format!("Keypair case failed for sk={x}"))?;
        }

        Ok(())
    }

    #[test]
    #[ignore]
    fn test_signature_test_matrix() -> anyhow::Result<()> {
        // === PATH SETUP ===
        let (wasm, r1cs) = load_artifacts("signature_test")?;

        let triples: [(u64, u64, u64); 8] = [
            (0, 0, 0),
            (1, 2, 3),
            (7, 8, 9),
            (15, 16, 17),
            (23, 24, 25),
            (31, 1, 2),
            (127, 255, 511),
            (0xDEAD, 0xBEEF, 0xCAFE),
        ];

        for &(sk_u, cm_u, mp_u) in &triples {
            let sk = Scalar::from(sk_u);
            let cm = Scalar::from(cm_u);
            let mp = Scalar::from(mp_u);

            run_signature_case(&wasm, &r1cs, sk, cm, mp).with_context(|| {
                format!("Signature case failed for (sk,cm,mp)=({sk_u},{cm_u},{mp_u})")
            })?;
        }

        Ok(())
    }
}
