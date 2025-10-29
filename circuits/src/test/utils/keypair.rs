use zkhash::{
    fields::bn256::FpBN256 as Scalar,
    poseidon2::{poseidon2::Poseidon2, poseidon2_instance_bn256::POSEIDON2_BN256_PARAMS_2,poseidon2_instance_bn256::POSEIDON2_BN256_PARAMS_3},
};
use zkhash::ark_ff::Zero;

/// Poseidon2 hash of two field elements (t = 2), returning the first lane
/// (state[0]).
pub fn poseidon2_hash2(left: Scalar, right: Scalar) -> Scalar {
    let h = Poseidon2::new(&POSEIDON2_BN256_PARAMS_2);
    let out = h.permutation(&[left, right]);
    out[0]
}

/// Poseidon2 hash of three field elements (t = 3), returning the first lane
/// (state[0]).
pub fn poseidon2_hash3(a: Scalar, b: Scalar, c: Scalar) -> Scalar {
    let h = Poseidon2::new(&POSEIDON2_BN256_PARAMS_3);
    let out = h.permutation(&[a, b, c]);
    out[0]
}

/// publicKey = Poseidon2(privatekey, 0)
pub fn derive_public_key(private_key: Scalar) -> Scalar {
    poseidon2_hash2(private_key, Scalar::zero())
}

/// signature = Poseidon2(privateKey, commitment, merklePath)
pub fn sign(private_key: Scalar, commitment: Scalar, merkle_path: Scalar) -> Scalar {
    poseidon2_hash3(private_key, commitment, merkle_path)
}