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

/// Convert a non-negative I256 to i128 with bounds checking.
pub fn i256_to_i128_nonneg(env: &Env, v: &I256) -> Option<i128> {
    if *v < I256::from_i32(env, 0) {
        return None;
    }
    v.to_i128()
}

/// Calculate the public amount from external amount:
/// `public_amount = ext_amount` in the BN256 field, wrapping negative values
/// to `FIELD_SIZE - |ext_amount|`. Returns `None` unless
/// `-2^248 < ext_amount < 2^248`.
pub fn calculate_public_amount(env: &Env, ext_amount: I256) -> Option<U256> {
    let zero = I256::from_i32(env, 0);
    let max = I256::from_parts(env, 0x0100_0000_0000_0000, 0, 0, 0);
    if ext_amount >= max || ext_amount <= zero.sub(&max) {
        return None;
    }

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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn calculate_public_amount_accepts_values_inside_the_bound() {
        let env = Env::default();
        let r = bn256_modulus(&env);
        let largest = U256::from_parts(&env, 0x00FF_FFFF_FFFF_FFFF, u64::MAX, u64::MAX, u64::MAX);

        assert_eq!(
            calculate_public_amount(
                &env,
                I256::from_parts(&env, 0x00FF_FFFF_FFFF_FFFF, u64::MAX, u64::MAX, u64::MAX)
            ),
            Some(largest.clone())
        );
        assert_eq!(
            calculate_public_amount(
                &env,
                I256::from_parts(&env, -0x0100_0000_0000_0000, 0, 0, 1)
            ),
            Some(r.sub(&largest))
        );
        assert_eq!(
            calculate_public_amount(&env, I256::from_i32(&env, 0)),
            Some(U256::from_u32(&env, 0))
        );
        assert_eq!(
            calculate_public_amount(&env, I256::from_i32(&env, -1)),
            Some(r.sub(&U256::from_u32(&env, 1)))
        );
    }

    #[test]
    fn calculate_public_amount_refuses_the_bound_in_either_sign() {
        let env = Env::default();
        assert_eq!(
            calculate_public_amount(&env, I256::from_parts(&env, 0x0100_0000_0000_0000, 0, 0, 0)),
            None
        );
        assert_eq!(
            calculate_public_amount(
                &env,
                I256::from_parts(&env, -0x0100_0000_0000_0000, 0, 0, 0)
            ),
            None
        );
        assert_eq!(
            calculate_public_amount(
                &env,
                I256::from_parts(&env, i64::MAX, u64::MAX, u64::MAX, u64::MAX)
            ),
            None
        );
    }

    #[test]
    fn calculate_public_amount_refuses_i256_min() {
        let env = Env::default();
        assert_eq!(
            calculate_public_amount(&env, I256::from_parts(&env, i64::MIN, 0, 0, 0)),
            None
        );
    }

    #[test]
    fn i256_to_i128_nonneg_refuses_negative_and_oversized_values() {
        let env = Env::default();
        let max = I256::from_i128(&env, i128::MAX);
        assert_eq!(i256_to_i128_nonneg(&env, &I256::from_i32(&env, -1)), None);
        assert_eq!(
            i256_to_i128_nonneg(&env, &max.add(&I256::from_i32(&env, 1))),
            None
        );
        assert_eq!(i256_to_i128_nonneg(&env, &max), Some(i128::MAX));
    }
}
