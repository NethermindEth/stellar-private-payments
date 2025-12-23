#![no_std]

//! Groth16 verifier contract for Circom proofs on Soroban using the native
//! BN254 precompile.

// Use Soroban's allocator for heap allocations
extern crate alloc;

pub use contract_types::{Groth16Error, Groth16Proof, VerificationKeyBytes};
use soroban_sdk::{
    Env, Vec, contract, contractimpl, contracttype,
    crypto::bn254::{Bn254G1Affine as G1Affine, Bn254G2Affine as G2Affine, Fr},
    vec,
};

/// Groth16 verification key for BN254 curve.
#[derive(Clone)]
pub struct VerificationKey {
    pub alpha: G1Affine,
    pub beta: G2Affine,
    pub gamma: G2Affine,
    pub delta: G2Affine,
    pub ic: Vec<G1Affine>,
}

fn verification_key_from_bytes(env: &Env, vk_bytes: &VerificationKeyBytes) -> VerificationKey {
    let mut ic_vec: Vec<G1Affine> = Vec::new(env);
    for i in 0..vk_bytes.ic.len() {
        let bytes = vk_bytes.ic.get(i).unwrap();
        ic_vec.push_back(G1Affine::from_bytes(bytes));
    }

    VerificationKey {
        alpha: G1Affine::from_bytes(vk_bytes.alpha.clone()),
        beta: G2Affine::from_bytes(vk_bytes.beta.clone()),
        gamma: G2Affine::from_bytes(vk_bytes.gamma.clone()),
        delta: G2Affine::from_bytes(vk_bytes.delta.clone()),
        ic: ic_vec,
    }
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    VerificationKey,
}

/// Groth16 verifier for BN254/Circom proofs.
#[contract]
pub struct CircomGroth16Verifier;

#[contractimpl]
impl CircomGroth16Verifier {
    /// Constructor: initialize the contract with a verification key.
    pub fn __constructor(env: Env, vk: VerificationKeyBytes) -> Result<(), Groth16Error> {
        let storage = env.storage().persistent();
        storage.set(&DataKey::VerificationKey, &vk);
        Ok(())
    }

    /// Verify a Groth16 proof using the stored verification key.
    pub fn verify(
        env: Env,
        proof: Groth16Proof,
        public_inputs: Vec<Fr>,
    ) -> Result<bool, Groth16Error> {
        let vk_bytes: VerificationKeyBytes = env
            .storage()
            .persistent()
            .get(&DataKey::VerificationKey)
            .ok_or(Groth16Error::NotInitialized)?;
        let vk = verification_key_from_bytes(&env, &vk_bytes);
        Self::verify_with_vk(&env, &vk, proof, public_inputs)
    }

    fn verify_with_vk(
        env: &Env,
        vk: &VerificationKey,
        proof: Groth16Proof,
        pub_inputs: Vec<Fr>,
    ) -> Result<bool, Groth16Error> {
        let bn = env.crypto().bn254();

        if pub_inputs.len() + 1 != vk.ic.len() {
            return Err(Groth16Error::MalformedPublicInputs);
        }

        let mut vk_x = vk.ic.get(0).ok_or(Groth16Error::MalformedPublicInputs)?;

        for i in 0..pub_inputs.len() {
            let s = pub_inputs.get(i).unwrap();
            let v = vk.ic.get(i + 1).unwrap();
            let prod = bn.g1_mul(&v, &s);
            vk_x = bn.g1_add(&vk_x, &prod);
        }

        // Compute the pairing check:
        // e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1
        let neg_a = -proof.a;

        let g1_points = vec![env, neg_a, vk.alpha.clone(), vk_x, proof.c];
        let g2_points = vec![
            env,
            proof.b,
            vk.beta.clone(),
            vk.gamma.clone(),
            vk.delta.clone(),
        ];
        if bn.pairing_check(g1_points, g2_points) {
            Ok(true)
        } else {
            Err(Groth16Error::InvalidProof)
        }
    }
}

#[cfg(test)]
mod test;
