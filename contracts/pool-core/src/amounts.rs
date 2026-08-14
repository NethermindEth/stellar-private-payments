//! Pure numeric helpers shared by `pool` and `pool-gvk`.
//!
//! These take no `DataKey`/error type, so each contract calls them directly
//! and maps the result to its own `Error` enum.

use soroban_sdk::{BytesN, Env, I256, U256};
use soroban_utils::constants::bn256_modulus;

/// Convert a U256 into a 32-byte big-endian field element.
pub fn u256_to_bytes(env: &Env, v: &U256) -> BytesN<32> {
    let mut buf = [0u8; 32];
    v.to_be_bytes().copy_into_slice(&mut buf);
    BytesN::from_array(env, &buf)
}

/// Maximum absolute external amount allowed (2^248).
pub fn max_ext_amount(env: &Env) -> U256 {
    U256::from_parts(env, 0x0100_0000_0000_0000, 0, 0, 0)
}

/// Convert a non-negative I256 to i128 with bounds checking.
pub fn i256_to_i128_nonneg(env: &Env, v: &I256) -> Option<i128> {
    if *v < I256::from_i32(env, 0) {
        return None;
    }
    v.to_i128()
}

/// Convert I256 to its absolute value as U256.
pub fn i256_abs_to_u256(env: &Env, v: &I256) -> U256 {
    let zero = I256::from_i32(env, 0);
    let abs = if *v >= zero { v.clone() } else { zero.sub(v) };
    U256::from_be_bytes(env, &abs.to_be_bytes())
}

/// Calculate the public amount from external amount:
/// `public_amount = ext_amount` in the BN256 field, wrapping negative values
/// to `FIELD_SIZE - |ext_amount|`. Returns `None` if `|ext_amount|` exceeds
/// the 2^248 bound.
pub fn calculate_public_amount(env: &Env, ext_amount: I256) -> Option<U256> {
    let abs_ext = i256_abs_to_u256(env, &ext_amount);
    if abs_ext >= max_ext_amount(env) {
        return None;
    }

    let zero = I256::from_i32(env, 0);

    if ext_amount >= zero {
        let pa_bytes = ext_amount.to_be_bytes();
        Some(U256::from_be_bytes(env, &pa_bytes))
    } else {
        let neg = zero.sub(&ext_amount);
        let neg_bytes = neg.to_be_bytes();
        let neg_u256 = U256::from_be_bytes(env, &neg_bytes);

        let field = bn256_modulus(env);
        Some(field.sub(&neg_u256))
    }
}

/// Whether a value is within the canonical BN254 scalar-field range.
pub fn is_canonical_bn256_public_input(value: &U256, modulus: &U256) -> bool {
    value < modulus
}
