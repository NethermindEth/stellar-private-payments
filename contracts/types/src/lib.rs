#![no_std]

use soroban_sdk::{
    Bytes, BytesN, Vec, contracterror, contracttype,
    crypto::bn254::{Bn254G1Affine, Bn254G2Affine},
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
    /// The contract was not initialized
    NotInitialized = 3,
}

/// Groth16 verification key for BN254 curve (byte-oriented).
/// All G2 points use Soroban's c1||c0 (imaginary||real) ordering.
#[contracttype]
#[derive(Clone)]
pub struct VerificationKeyBytes {
    pub alpha: BytesN<64>,
    pub beta: BytesN<128>,
    pub gamma: BytesN<128>,
    pub delta: BytesN<128>,
    pub ic: Vec<BytesN<64>>,
}

/// Groth16 proof composed of points A, B, and C.
/// G2 point B uses Soroban's c1||c0 (imaginary||real) ordering.
#[derive(Clone)]
#[contracttype]
pub struct Groth16Proof {
    pub a: Bn254G1Affine,
    pub b: Bn254G2Affine,
    pub c: Bn254G1Affine,
}

impl Groth16Proof {
    /// Returns true if any of the embedded points is empty.
    pub fn is_empty(&self) -> bool {
        self.a.to_bytes().is_empty() || self.b.to_bytes().is_empty() || self.c.to_bytes().is_empty()
    }
}

/// Size of a single BN254 field element in bytes.
pub const FIELD_ELEMENT_SIZE: u32 = 32;

/// Size of a G1 point (x || y, each 32 bytes).
pub const G1_SIZE: u32 = FIELD_ELEMENT_SIZE * 2;

/// Size of a G2 point (x.c1 || x.c0 || y.c1 || y.c0, each 32 bytes).
pub const G2_SIZE: u32 = FIELD_ELEMENT_SIZE * 4;

/// Total proof size: A (G1) || B (G2) || C (G1) = 64 + 128 + 64 = 256 bytes.
pub const PROOF_SIZE: u32 = G1_SIZE + G2_SIZE + G1_SIZE;

impl TryFrom<Bytes> for Groth16Proof {
    type Error = Groth16Error;

    fn try_from(value: Bytes) -> Result<Self, Self::Error> {
        if value.len() != PROOF_SIZE {
            return Err(Groth16Error::MalformedProof);
        }

        let a = Bn254G1Affine::from_bytes(
            value
                .slice(0..G1_SIZE)
                .try_into()
                .map_err(|_| Groth16Error::MalformedProof)?,
        );
        let b = Bn254G2Affine::from_bytes(
            value
                .slice(G1_SIZE..G1_SIZE + G2_SIZE)
                .try_into()
                .map_err(|_| Groth16Error::MalformedProof)?,
        );
        let c = Bn254G1Affine::from_bytes(
            value
                .slice(G1_SIZE + G2_SIZE..)
                .try_into()
                .map_err(|_| Groth16Error::MalformedProof)?,
        );

        Ok(Self { a, b, c })
    }
}
