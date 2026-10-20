#[cfg(test)]
mod tests {
    use crate::test::utils::{
        circom_tester::{CircuitKeys, Inputs, generate_keys, prove_and_verify_with_keys},
        general::load_artifacts,
        keypair::derive_public_key,
    };
    use anyhow::{Result, anyhow};
    use ark_bn254::{Bn254, Fr as Scalar};
    use ark_circom::CircomReduction;
    use ark_groth16::Groth16;
    use ark_snark::SNARK;
    use std::{
        panic::{self, AssertUnwindSafe},
        path::Path,
    };

    const CIRCUIT: &str = "keyOwnership";

    fn inputs(private_key: Scalar, public_key: Scalar, registration_hash: Scalar) -> Inputs {
        let mut inputs = Inputs::new();
        inputs.set("publicKey", public_key);
        inputs.set("registrationHash", registration_hash);
        inputs.set("privateKey", private_key);
        inputs
    }

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

    #[test]
    #[ignore]
    fn test_key_ownership_valid() -> Result<()> {
        let (wasm, r1cs) = load_artifacts(CIRCUIT)?;
        let keys = generate_keys(&wasm, &r1cs)?;

        for (sk, hash) in [(1u64, 0u64), (7, 0xC0FFEE), (123_456_789, u64::MAX)] {
            let sk = Scalar::from(sk);
            let pk = derive_public_key(sk);
            let hash = Scalar::from(hash);

            let res = prove_and_verify_with_keys(&wasm, &r1cs, &inputs(sk, pk, hash), &keys)?;
            assert!(res.verified, "key ownership proof did not verify");
            assert_eq!(res.public_inputs, vec![pk, hash]);
        }
        Ok(())
    }

    #[test]
    #[ignore]
    fn test_key_ownership_wrong_private_key_fails() -> Result<()> {
        let (wasm, r1cs) = load_artifacts(CIRCUIT)?;
        let keys = generate_keys(&wasm, &r1cs)?;

        let pk = derive_public_key(Scalar::from(7u64));
        assert!(!proof_verifies(
            &wasm,
            &r1cs,
            &inputs(Scalar::from(8u64), pk, Scalar::from(1u64)),
            &keys,
        ));
        Ok(())
    }

    #[test]
    #[ignore]
    fn test_key_ownership_proof_bound_to_public_inputs() -> Result<()> {
        let (wasm, r1cs) = load_artifacts(CIRCUIT)?;
        let keys = generate_keys(&wasm, &r1cs)?;

        let sk = Scalar::from(7u64);
        let pk = derive_public_key(sk);
        let hash = Scalar::from(1u64);
        let res = prove_and_verify_with_keys(&wasm, &r1cs, &inputs(sk, pk, hash), &keys)?;
        assert!(res.verified);

        let other_pk = derive_public_key(Scalar::from(8u64));
        for (public_inputs, what) in [
            ([pk, Scalar::from(2u64)], "registration hash"),
            ([other_pk, hash], "public key"),
        ] {
            let replayed = Groth16::<Bn254, CircomReduction>::verify_with_processed_vk(
                &keys.pvk,
                &public_inputs,
                &res.proof,
            )
            .map_err(|e| anyhow!("verify_with_processed_vk failed: {e}"))?;
            assert!(!replayed, "proof verified under another {what}");
        }
        Ok(())
    }
}
