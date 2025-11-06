use num_bigint::{BigInt, BigUint};
use std::ops::AddAssign;
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

pub fn scalar_to_bigint(s: Scalar) -> BigInt {
    let bi = s.into_bigint();
    let bytes_le = bi.to_bytes_le();
    let u = BigUint::from_bytes_le(&bytes_le);
    BigInt::from(u)
}
