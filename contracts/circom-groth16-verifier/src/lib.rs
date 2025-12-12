#![no_std]

//! Groth16 verifier contract for Circom proofs on Soroban using the native
//! BN254 precompile.

// Use Soroban's allocator for heap allocations
extern crate alloc;

use alloc::vec::Vec as StdVec;

use soroban_sdk::{
    Bytes, Env, Vec, contract, contracterror, contractimpl, contracttype,
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
    pub ic: StdVec<G1Affine>,
}

/// Byte-oriented version of the verification key generated at build time.
///
/// Soroban's BN254 affine types are not `const` constructible, so we emit the
/// key as raw byte arrays in `build.rs` and reconstruct the affine points at
/// runtime inside the contract via [`verification_key`]. This keeps the key
/// embeddable with `include!` while still avoiding any serialization support on
/// the `VerificationKey` itself.
pub struct VerificationKeyBytes {
    pub alpha: [u8; G1_SIZE as usize],
    pub beta: [u8; G2_SIZE as usize],
    pub gamma: [u8; G2_SIZE as usize],
    pub delta: [u8; G2_SIZE as usize],
    pub ic: &'static [[u8; G1_SIZE as usize]],
}

impl VerificationKeyBytes {
    pub fn verification_key(&self, env: &Env) -> VerificationKey {
        VerificationKey {
            alpha: G1Affine::from_array(env, &self.alpha),
            beta: G2Affine::from_array(env, &self.beta),
            gamma: G2Affine::from_array(env, &self.gamma),
            delta: G2Affine::from_array(env, &self.delta),
            ic: self
                .ic
                .iter()
                .map(|coords| G1Affine::from_array(env, coords))
                .collect(),
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

/// Groth16 verifier for BN254/Circom proofs.
#[contract]
pub struct CircomGroth16Verifier;

#[contractimpl]
impl CircomGroth16Verifier {

    /// Groth16 verification key generated from the Circom `vk.json`.
    ///
    /// The bytes are emitted in `build.rs` from `circuits/vk.json` at compile time.
    const VERIFICATION_KEY: VerificationKeyBytes =
        include!(concat!(env!("OUT_DIR"), "/verification_key.rs"));

    /// Verify a Groth16 proof using the stored verification key.
    ///
    /// Returns `Ok(())` on success or a [`Groth16Error`] describing the failure.
    pub fn verify(env: Env, proof_bytes: Bytes, public_inputs: Vec<Fr>) -> Result<(), Groth16Error> {
        let vk = Self::VERIFICATION_KEY.verification_key(&env);

        let proof = Groth16Proof::try_from(proof_bytes)?;

        Self::verify_with_vk(&env, &vk, proof, public_inputs)
    }

    fn verify_with_vk(
        env: &Env,
        vk: &VerificationKey,
        proof: Groth16Proof,
        pub_inputs: Vec<Fr>,
    ) -> Result<(), Groth16Error> {
        let bn = env.crypto().bn254();

        if pub_inputs.len() + 1 != vk.ic.len() as u32 {
            return Err(Groth16Error::MalformedPublicInputs);
        }

        let mut vk_x = vk
            .ic
            .first()
            .cloned()
            .ok_or(Groth16Error::MalformedPublicInputs)?;
        for (s, v) in pub_inputs.iter().zip(vk.ic.iter().skip(1)) {
            let prod = bn.g1_mul(v, &s);
            vk_x = bn.g1_add(&vk_x, &prod);
        }

        // Compute the pairing check:
        // e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1
        let neg_a = -proof.a;

        let g1_points = vec![env, neg_a, vk.alpha.clone(), vk_x, proof.c];
        let g2_points = vec![env, proof.b, vk.beta.clone(), vk.gamma.clone(), vk.delta.clone()];

        if bn.pairing_check(g1_points, g2_points) {
            Ok(())
        } else {
            Err(Groth16Error::InvalidProof)
        }
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
