#[cfg(test)]
mod tests {
    use crate::test::utils::{
        circom_tester::{
            Inputs, build_circuit, generate_keys, prove_and_verify_with_keys, r1cs_satisfied,
        },
        general::load_artifacts,
        keypair::derive_public_key,
    };
    use anyhow::{Result, anyhow};
    use ark_bn254::{Bn254, Fr as Scalar};
    use ark_circom::CircomReduction;
    use ark_groth16::Groth16;
    use ark_snark::SNARK;

    const CIRCUIT: &str = "keyOwnership";

    // Circom wire layout: constant one, outputs, public inputs, private inputs.
    const PUBLIC_KEY_WIRE: usize = 1;
    const REGISTRATION_HASH_WIRE: usize = 2;
    const PRIVATE_KEY_WIRE: usize = 3;

    fn inputs(private_key: Scalar, public_key: Scalar, registration_hash: Scalar) -> Inputs {
        let mut inputs = Inputs::new();
        inputs.set("publicKey", public_key);
        inputs.set("registrationHash", registration_hash);
        inputs.set("privateKey", private_key);
        inputs
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

        let real_pk = derive_public_key(Scalar::from(7u64));
        let wrong_sk = Scalar::from(8u64);
        let wrong_pk = derive_public_key(wrong_sk);
        let hash = Scalar::from(1u64);

        // Compute an honest witness for the wrong key and swap in the real
        // public key afterwards.
        let mut circuit = build_circuit(&wasm, &r1cs, &inputs(wrong_sk, wrong_pk, hash))?;
        assert!(r1cs_satisfied(circuit.clone())?);

        let witness = circuit
            .witness
            .as_mut()
            .ok_or_else(|| anyhow!("missing witness"))?;
        assert_eq!(witness[PRIVATE_KEY_WIRE], wrong_sk);
        assert_eq!(witness[PUBLIC_KEY_WIRE], wrong_pk);
        witness[PUBLIC_KEY_WIRE] = real_pk;

        assert_eq!(circuit.get_public_inputs(), Some(vec![real_pk, hash]));
        assert!(
            !r1cs_satisfied(circuit)?,
            "R1CS accepted a private key that does not derive the public key"
        );
        Ok(())
    }

    #[test]
    #[ignore]
    fn test_key_ownership_registration_hash_constrained() -> Result<()> {
        let (wasm, r1cs) = load_artifacts(CIRCUIT)?;

        let sk = Scalar::from(7u64);
        let pk = derive_public_key(sk);
        let hash = Scalar::from(1u64);
        let other_hash = Scalar::from(2u64);

        let mut circuit = build_circuit(&wasm, &r1cs, &inputs(sk, pk, hash))?;
        assert!(r1cs_satisfied(circuit.clone())?);

        let witness = circuit
            .witness
            .as_mut()
            .ok_or_else(|| anyhow!("missing witness"))?;
        assert_eq!(witness[REGISTRATION_HASH_WIRE], hash);
        witness[REGISTRATION_HASH_WIRE] = other_hash;

        assert_eq!(circuit.get_public_inputs(), Some(vec![pk, other_hash]));
        assert!(
            !r1cs_satisfied(circuit)?,
            "registrationHash is not in any constraint"
        );
        Ok(())
    }

    // The verifying key rejects any changed public input, constrained or not.
    #[test]
    #[ignore]
    fn test_key_ownership_proof_fails_under_other_public_inputs() -> Result<()> {
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
