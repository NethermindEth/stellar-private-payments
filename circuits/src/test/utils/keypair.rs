use zkhash::ark_ff::Zero;
use zkhash::fields::bn256::FpBN256 as Scalar;

use super::general::{poseidon2_hash2, poseidon2_hash3};

/// publicKey = Poseidon2(privatekey, 0)
pub fn derive_public_key(private_key: Scalar) -> Scalar {
    poseidon2_hash2(private_key, Scalar::zero(), Some(Scalar::from(3))) // We use 3 as domain separation for Keypair
}

/// signature = Poseidon2(privateKey, commitment, merklePath)
pub fn sign(private_key: Scalar, commitment: Scalar, merkle_path: Scalar) -> Scalar {
    poseidon2_hash3(private_key, commitment, merkle_path, Some(Scalar::from(4))) // We use 4 as domain separation for Signature
}
