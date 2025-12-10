#![no_std]

//! Groth16 verifier contract for Circom proofs on Soroban using the native
//! BN254 precompile.

extern crate alloc;

use core::array;

use soroban_sdk::{
    Bytes, BytesN, Env, Vec, contract, contracterror, contractimpl, contracttype,
    crypto::bn254::{Fr, G1Affine, G2Affine},
    vec,
};

/// Errors that can occur during Groth16 proof verification.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Groth16Error {
    /// The pairing product did not equal identity.
    InvalidProof = 0,
    /// The public inputs length does not match the verification key.
    MalformedPublicInputs = 1,
    /// The proof bytes are malformed.
    MalformedProof = 2,

}

/// Groth16 verification key for BN254 curve.
#[derive(Clone)]
pub struct VerificationKey {
    pub alpha: G1Affine,
    pub beta: G2Affine,
    pub gamma: G2Affine,
    pub delta: G2Affine,
    pub ic: [G1Affine; 6],
}

/// Byte-oriented verification key generated at build time.
#[contracttype]
pub struct VerificationKeyBytes {
    pub alpha: BytesN<64>,
    pub beta: BytesN<128>,
    pub gamma: BytesN<128>,
    pub delta: BytesN<128>,
    pub ic: Vec<BytesN<64>>,
}

impl VerificationKeyBytes {
    pub fn verification_key(&self, _env: &Env) -> VerificationKey {
        let ic_vec = &self.ic;
        let ic_array: [G1Affine; 6] = array::from_fn(|i| {
            let bytes = ic_vec.get(i as u32).unwrap();
            G1Affine::from_bytes(bytes.clone())
        });

        VerificationKey {
            alpha: G1Affine::from_bytes(self.alpha.clone()),
            beta: G2Affine::from_bytes(self.beta.clone()),
            gamma: G2Affine::from_bytes(self.gamma.clone()),
            delta: G2Affine::from_bytes(self.delta.clone()),
            ic: ic_array,
        }
    }
}

/// Groth16 proof composed of points A, B, and C.
#[derive(Clone)]
#[contracttype]
pub struct Groth16Proof {
    pub a: G1Affine,
    pub b: G2Affine,
    pub c: G1Affine,
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
    /// Initialize the contract with a verification key.
    pub fn init(env: Env, vk: VerificationKeyBytes) {
        env.storage().persistent().set(&DataKey::VerificationKey, &vk);
    }

    /// Verify a Groth16 proof using the stored verification key.
    pub fn verify(env: Env, proof_bytes: Bytes, public_inputs: Vec<Fr>) -> bool {
        let vk_bytes: VerificationKeyBytes =
            match env.storage().persistent().get(&DataKey::VerificationKey) {
                Some(vk) => vk,
                None => return false,
            };
        let vk = vk_bytes.verification_key(&env);

        let proof = match Groth16Proof::try_from(proof_bytes) {
            Ok(p) => p,
            Err(_) => return false,
        };

        Self::verify_with_vk(&env, &vk, proof, public_inputs).unwrap_or(false)
    }

    fn verify_with_vk(
        env: &Env,
        vk: &VerificationKey,
        proof: Groth16Proof,
        pub_inputs: Vec<Fr>,
    ) -> Result<bool, Groth16Error> {
        let bn = env.crypto().bn254();

        if pub_inputs.len() + 1 != vk.ic.len() as u32 {
            return Err(Groth16Error::MalformedPublicInputs);
        }

        let mut vk_x = vk.ic.first().cloned().unwrap();
        for (s, v) in pub_inputs.iter().zip(vk.ic.iter().skip(1)) {
            let prod = bn.g1_mul(v, &s);
            vk_x = bn.g1_add(&vk_x, &prod);
        }

        // Compute the pairing check:
        // e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1
        let neg_a = -proof.a;

        let g1_points = vec![env, neg_a, vk.alpha.clone(), vk_x, proof.c];
        let g2_points = vec![env, proof.b, vk.beta.clone(), vk.gamma.clone(), vk.delta.clone()];

        Ok(bn.pairing_check(g1_points, g2_points))
    }
}

// === Proof parsing from bytes ===

// Layout: a.x | a.y | b.x_0 | b.x_1 | b.y_0 | b.y_1 | c.x | c.y (all 32-byte big-endian)
const FIELD_ELEMENT_SIZE: u32 = 32;
const G1_SIZE: u32 = FIELD_ELEMENT_SIZE * 2;
const G2_SIZE: u32 = FIELD_ELEMENT_SIZE * 4;
const PROOF_SIZE: u32 = G1_SIZE + G2_SIZE + G1_SIZE;


impl TryFrom<Bytes> for Groth16Proof {
    type Error = Groth16Error;

    fn try_from(value: Bytes) -> Result<Self, Self::Error> {
        if value.len() != PROOF_SIZE {
            return Err(Groth16Error::MalformedProof);
        }

        let a = G1Affine::from_bytes(
            value
                .slice(0..G1_SIZE)
                .try_into()
                .map_err(|_| Groth16Error::MalformedProof)?,
        );
        let b = G2Affine::from_bytes(
            value
                .slice(G1_SIZE..G1_SIZE + G2_SIZE)
                .try_into()
                .map_err(|_| Groth16Error::MalformedProof)?,
        );
        let c = G1Affine::from_bytes(
            value
                .slice(G1_SIZE + G2_SIZE..)
                .try_into()
                .map_err(|_| Groth16Error::MalformedProof)?,
        );

        Ok(Self { a, b, c })
    }
}
