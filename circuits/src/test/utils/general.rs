use num_bigint::{BigInt, BigUint};
use std::ops::AddAssign;
use std::path::PathBuf;
use zkhash::poseidon2::poseidon2::Poseidon2;
use zkhash::poseidon2::poseidon2_instance_bn256::{
    POSEIDON2_BN256_PARAMS_2, POSEIDON2_BN256_PARAMS_3, POSEIDON2_BN256_PARAMS_4,
};

use zkhash::ark_ff::{BigInteger, PrimeField};
use zkhash::fields::bn256::FpBN256 as Scalar;

/// Poseidon2 hash of two field elements. Optimized compression mode.
pub fn poseidon2_compression(left: Scalar, right: Scalar) -> Scalar {
    let h = Poseidon2::new(&POSEIDON2_BN256_PARAMS_2);
    let mut perm = h.permutation(&[left, right]);
    perm[0].add_assign(&left);
    perm[1].add_assign(&right);
    perm[0] // By default, we truncate to one element
}

/// Poseidon2 hash of 2 field elements (t = 3, r=2, c=1), returning the first lane
/// (state[0]).
pub fn poseidon2_hash2(a: Scalar, b: Scalar, dom_sep: Option<Scalar>) -> Scalar {
    let h = Poseidon2::new(&POSEIDON2_BN256_PARAMS_3);
    let perm: Vec<Scalar>;
    if let Some(dom_sep) = dom_sep {
        perm = h.permutation(&[a, b, dom_sep]);
    } else {
        perm = h.permutation(&[a, b, Scalar::from(0)]);
    }
    perm[0]
}

/// Poseidon2 hash of 3 field elements (t = 4, r=3, c=1), returning the first lane
/// (state[0]).
pub fn poseidon2_hash3(a: Scalar, b: Scalar, c: Scalar, dom_sep: Option<Scalar>) -> Scalar {
    let h = Poseidon2::new(&POSEIDON2_BN256_PARAMS_4);
    let perm: Vec<Scalar>;
    if let Some(dom_sep) = dom_sep {
        perm = h.permutation(&[a, b, c, dom_sep]);
    } else {
        perm = h.permutation(&[a, b, c, Scalar::from(0)]);
    }
    perm[0]
}

/// Convert a field `Scalar` into a signed `BigInt`.
/// This goes through little-endian bytes because `Scalar::into_bigint`
/// returns an internal representation not directly compatible with `BigInt`.
pub fn scalar_to_bigint(s: Scalar) -> BigInt {
    let bi = s.into_bigint();
    let bytes_le = bi.to_bytes_le();
    let u = BigUint::from_bytes_le(&bytes_le);
    BigInt::from(u)
}

/// Load the compiled WASM and R1CS artifacts for a circuit by name.
/// This expects files to be located under the `CIRCUIT_OUT_DIR` tree
/// as produced by the build system.
pub fn load_artifacts(name: &str) -> anyhow::Result<(PathBuf, PathBuf)> {
    let out_dir = PathBuf::from(env!("CIRCUIT_OUT_DIR"));
    let wasm = out_dir.join(format!("wasm/{name}_js/{name}.wasm"));
    let r1cs = out_dir.join(format!("{name}.r1cs"));
    anyhow::ensure!(wasm.exists(), "WASM file not found at {}", wasm.display());
    anyhow::ensure!(r1cs.exists(), "R1CS file not found at {}", r1cs.display());
    Ok((wasm, r1cs))
}
