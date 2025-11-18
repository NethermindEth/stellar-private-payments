use num_bigint::{BigInt, BigUint};
use std::path::PathBuf;
use zkhash::poseidon2::poseidon2::Poseidon2;
use zkhash::poseidon2::poseidon2_instance_bn256::{
    POSEIDON2_BN256_PARAMS_2, POSEIDON2_BN256_PARAMS_3,
};

use zkhash::ark_ff::{BigInteger, PrimeField};
use zkhash::fields::bn256::FpBN256 as Scalar;

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

pub fn scalar_to_bigint(s: Scalar) -> BigInt {
    let bi = s.into_bigint();
    let bytes_le = bi.to_bytes_le();
    let u = BigUint::from_bytes_le(&bytes_le);
    BigInt::from(u)
}

pub fn load_artifacts(name: &str) -> anyhow::Result<(PathBuf, PathBuf)> {
    let out_dir = PathBuf::from(env!("CIRCUIT_OUT_DIR"));
    let wasm = out_dir.join(format!("wasm/{name}_js/{name}.wasm"));
    let r1cs = out_dir.join(format!("{name}.r1cs"));
    anyhow::ensure!(wasm.exists(), "WASM file not found at {}", wasm.display());
    anyhow::ensure!(r1cs.exists(), "R1CS file not found at {}", r1cs.display());
    Ok((wasm, r1cs))
}
