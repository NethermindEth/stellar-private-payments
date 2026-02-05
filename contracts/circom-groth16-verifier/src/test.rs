use super::*;
use ark_bn254::{Bn254, Fr as ArkFr};
use ark_ff::{BigInteger, Field, PrimeField};
use ark_groth16::{Groth16, Proof};
use ark_relations::{
    gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable},
    lc,
};
use ark_std::rand::{SeedableRng, rngs::StdRng};
use contract_types::PROOF_SIZE;
use soroban_sdk::{Bytes, BytesN, Env, Vec};
use soroban_utils::{g1_bytes_from_ark, g2_bytes_from_ark, vk_bytes_from_ark};

/// Simple circuit that exposes eleven public inputs (as many as a tx circuit).
///
/// The circuit ties the first public input to a witness to keep the proving
/// key minimal while still exercising the fixed `ic` array length expected by
/// the contract (11 public inputs + 1 constant term).
#[derive(Clone)]
struct ElevenInputCircuit<F: Field> {
    inputs: [F; 11],
}

impl<F: Field> ConstraintSynthesizer<F> for ElevenInputCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Register all public inputs
        let mut input_vars = alloc::vec::Vec::with_capacity(self.inputs.len());
        for value in self.inputs {
            input_vars.push(cs.new_input_variable(|| Ok(value))?);
        }

        // Constrain a witness to equal the first public input: w * 1 = input_0
        let witness = cs.new_witness_variable(|| Ok(self.inputs[0]))?;
        cs.enforce_r1cs_constraint(
            || lc!() + witness,
            || lc!() + Variable::One,
            || lc!() + input_vars[0],
        )?;
        Ok(())
    }
}

fn seeded_rng() -> StdRng {
    StdRng::seed_from_u64(7)
}

fn fr_from_ark(env: &Env, value: ArkFr) -> Fr {
    let bytes = value.into_bigint().to_bytes_be();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&bytes);
    Fr::from_bytes(BytesN::from_array(env, &buf))
}

fn groth16_proof_from_ark(env: &Env, proof: &Proof<Bn254>) -> Groth16Proof {
    Groth16Proof {
        a: G1Affine::from_array(env, &g1_bytes_from_ark(proof.a)),
        b: G2Affine::from_array(env, &g2_bytes_from_ark(proof.b)),
        c: G1Affine::from_array(env, &g1_bytes_from_ark(proof.c)),
    }
}

fn serialize_proof(env: &Env, proof: &Groth16Proof) -> Bytes {
    let mut data = Bytes::new(env);
    data.append(&Bytes::from(proof.a.to_bytes()));
    data.append(&Bytes::from(proof.b.to_bytes()));
    data.append(&Bytes::from(proof.c.to_bytes()));
    data
}

fn build_test(env: &Env) -> (VerificationKeyBytes, Groth16Proof, Vec<Fr>, [ArkFr; 11]) {
    let mut rng = seeded_rng();
    let inputs = [ArkFr::from(33u64); 11];
    let circuit = ElevenInputCircuit { inputs };
    let params =
        Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit.clone(), &mut rng)
            .expect("params failed to generate");
    let proof = Groth16::<Bn254>::create_random_proof_with_reduction(circuit, &params, &mut rng)
        .expect("proof failed");

    let mut public_inputs: Vec<Fr> = Vec::new(env);
    for value in inputs {
        public_inputs.push_back(fr_from_ark(env, value));
    }

    let vk_bytes_ext = vk_bytes_from_ark(env, &params.vk);
    let vk_bytes = VerificationKeyBytes {
        alpha: vk_bytes_ext.alpha,
        beta: vk_bytes_ext.beta,
        gamma: vk_bytes_ext.gamma,
        delta: vk_bytes_ext.delta,
        ic: vk_bytes_ext.ic,
    };

    (
        vk_bytes,
        groth16_proof_from_ark(env, &proof),
        public_inputs,
        inputs,
    )
}


/// Create a test environment that disables snapshot writing under Miri.
/// Miri's isolation mode blocks filesystem operations, which the Soroban SDK
/// uses for test snapshots.
fn test_env() -> Env {
    #[cfg(miri)]
    {
        use soroban_sdk::testutils::EnvTestConfig;
        Env::new_with_config(EnvTestConfig {
            capture_snapshot_at_drop: false,
        })
    }
    #[cfg(not(miri))]
    {
        Env::default()
    }
}

#[test]
fn verifies_valid_proof() {
    let env = test_env();
    let (vk_bytes, proof, public_inputs, _) = build_test(&env);
    let contract_id = env.register(CircomGroth16Verifier, (vk_bytes.clone(),));
    let client = CircomGroth16VerifierClient::new(&env, &contract_id);

    let result = client.try_verify(&proof, &public_inputs);

    assert_eq!(result, Ok(Ok(true)));
}

#[test]
fn rejects_wrong_public_input_length() {
    let env = test_env();
    let (vk_bytes, proof, _public_inputs, inputs) = build_test(&env);
    let contract_id = env.register(CircomGroth16Verifier, (vk_bytes.clone(),));
    let client = CircomGroth16VerifierClient::new(&env, &contract_id);

    // Provide too few public inputs (length 5 instead of 11)
    let mut short_inputs: Vec<Fr> = Vec::new(&env);
    for value in inputs.iter().take(5) {
        short_inputs.push_back(fr_from_ark(&env, *value));
    }

    let result = client.try_verify(&proof, &short_inputs);
    assert!(matches!(
        result,
        Err(Ok(Groth16Error::MalformedPublicInputs))
    ));
}

#[test]
fn groth16_proof_parsing_checks_size() {
    let env = test_env();
    let (_vk_bytes, proof, _public_inputs, _) = build_test(&env);

    let encoded = serialize_proof(&env, &proof);
    assert_eq!(encoded.len(), PROOF_SIZE);
    assert!(Groth16Proof::try_from(encoded.clone()).is_ok());

    let truncated = encoded.slice(0..(PROOF_SIZE - 1));
    assert!(matches!(
        Groth16Proof::try_from(truncated),
        Err(Groth16Error::MalformedProof)
    ));
}
