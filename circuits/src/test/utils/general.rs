use num_bigint::{BigInt, BigUint};
use std::{ops::AddAssign, path::PathBuf};
use zkhash::poseidon2::{
    poseidon2::Poseidon2,
    poseidon2_instance_bn256::{
        POSEIDON2_BN256_PARAMS_2, POSEIDON2_BN256_PARAMS_3, POSEIDON2_BN256_PARAMS_4,
    },
};

use zkhash::{
    ark_ff::{BigInteger, PrimeField},
    fields::bn256::FpBN256 as Scalar,
};

/// Poseidon2 hash of two field elements using optimized compression mode
///
/// # Arguments
///
/// * `left` - First field element to hash
/// * `right` - Second field element to hash
///
/// # Returns
///
/// Returns the first element of the permutation result after adding the inputs.
pub fn poseidon2_compression(left: Scalar, right: Scalar) -> Scalar {
    let h = Poseidon2::new(&POSEIDON2_BN256_PARAMS_2);
    let mut perm = h.permutation(&[left, right]);
    perm[0].add_assign(&left);
    perm[1].add_assign(&right);
    perm[0] // By default, we truncate to one element
}

/// Poseidon2 hash of 2 field elements (t = 3, r=2, c=1)
///
/// Performs a Poseidon2 permutation on two field elements with an optional
/// domain separator, returning the first element (state\[0\]).
///
/// # Arguments
///
/// * `a` - First field element to hash
/// * `b` - Second field element to hash
/// * `dom_sep` - Optional domain separator (uses 0 if None)
///
/// # Returns
///
/// Returns the first lane (state\[0\]) of the permutation result.
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

/// Poseidon2 hash of 3 field elements (t = 4, r=3, c=1)
///
/// Performs a Poseidon2 permutation on three field elements with an optional
/// domain separator, returning the first element (state\[0\]).
///
/// # Arguments
///
/// * `a` - First field element to hash
/// * `b` - Second field element to hash
/// * `c` - Third field element to hash
/// * `dom_sep` - Optional domain separator (uses 0 if None)
///
/// # Returns
///
/// Returns the first element (state\[0\]) of the permutation result.
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

/// Convert a field `Scalar` into a signed `BigInt`
///  
/// # Arguments
///
/// * `s` - Field element scalar to convert
///
/// # Returns
///
/// Returns the scalar as a signed `BigInt` value.
pub fn scalar_to_bigint(s: Scalar) -> BigInt {
    let bi = s.into_bigint();
    let bytes_le = bi.to_bytes_le();
    let u = BigUint::from_bytes_le(&bytes_le);
    BigInt::from(u)
}

/// Load the compiled WASM and R1CS artifacts for a circuit by name from
/// `target/circuits-artifacts/` (`make circuits`).
pub fn load_artifacts(name: &str) -> anyhow::Result<(PathBuf, PathBuf)> {
    let publish = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/circuits-artifacts");

    let wasm = publish.join(format!("{name}.wasm"));
    let r1cs = publish.join(format!("{name}.r1cs"));
    if wasm.is_file() && r1cs.is_file() {
        return Ok((wasm, r1cs));
    }

    artifacts_in_out_dir(&publish.join("out"), name).ok_or_else(|| {
        anyhow::anyhow!(
            "artifacts for `{name}` not found; run \
                 `make circuits TESTS=1`"
        )
    })
}

fn artifacts_in_out_dir(out_dir: &std::path::Path, name: &str) -> Option<(PathBuf, PathBuf)> {
    let wasm = out_dir.join(format!("wasm/{name}_js/{name}.wasm"));
    let r1cs = out_dir.join(format!("{name}.r1cs"));
    (wasm.is_file() && r1cs.is_file()).then_some((wasm, r1cs))
}
