//! Pure numeric helpers shared by `pool` and `pool-gvk`.
//!
//! These take no `DataKey`/error type, so each contract calls them directly
//! and maps the result to its own `Error` enum.

use soroban_sdk::{BytesN, Env, I256, U256, Vec};
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

/// Whether every public input shared by `pool` and `pool-gvk` is below the
/// BN254 scalar-field modulus.
///
/// The verifier converts these values with `Bn254Fr::from_bytes`, which
/// expects field elements, so they must be checked first. The ASP membership
/// and non-membership roots are checked only when `policy_flags` requires the
/// matching proof. `ext_data_hash` and contract-specific inputs are left to
/// the caller.
#[allow(clippy::too_many_arguments)]
pub fn is_canonical_common_bn256_public_inputs(
    root: &U256,
    public_amount: &U256,
    input_nullifiers: &Vec<U256>,
    output_commitment0: &U256,
    output_commitment1: &U256,
    asp_membership_root: &U256,
    asp_non_membership_root: &U256,
    policy_flags: u32,
    modulus: &U256,
) -> bool {
    if !is_canonical_bn256_public_input(root, modulus) {
        return false;
    }
    if !is_canonical_bn256_public_input(public_amount, modulus) {
        return false;
    }
    for nullifier in input_nullifiers.iter() {
        if !is_canonical_bn256_public_input(&nullifier, modulus) {
            return false;
        }
    }
    if !is_canonical_bn256_public_input(output_commitment0, modulus) {
        return false;
    }
    if !is_canonical_bn256_public_input(output_commitment1, modulus) {
        return false;
    }
    if crate::policy::requires_membership_proofs(policy_flags)
        && !is_canonical_bn256_public_input(asp_membership_root, modulus)
    {
        return false;
    }
    if crate::policy::requires_non_membership_proofs(policy_flags)
        && !is_canonical_bn256_public_input(asp_non_membership_root, modulus)
    {
        return false;
    }
    true
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::policy::{ALLOWLIST_BIT, BLOCKLIST_BIT};
    use soroban_sdk::vec;

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

    #[test]
    fn is_canonical_bn256_public_input_bounds() {
        let env = Env::default();
        let modulus = bn256_modulus(&env);
        let one = U256::from_u32(&env, 1);
        let zero = U256::from_u32(&env, 0);

        // Values below modulus
        assert!(is_canonical_bn256_public_input(&zero, &modulus));
        let below = modulus.sub(&one);
        assert!(is_canonical_bn256_public_input(&below, &modulus));

        // Value equal to modulus
        assert!(!is_canonical_bn256_public_input(&modulus, &modulus));

        // Value greater than modulus
        let above = modulus.add(&one);
        assert!(!is_canonical_bn256_public_input(&above, &modulus));
    }

    #[test]
    fn is_canonical_common_bn256_public_inputs_valid() {
        let env = Env::default();
        let modulus = bn256_modulus(&env);
        let one = U256::from_u32(&env, 1);
        let val = modulus.sub(&one);
        let nullifiers = vec![&env, val.clone(), val.clone()];

        // All flags off
        assert!(is_canonical_common_bn256_public_inputs(
            &val,
            &val,
            &nullifiers,
            &val,
            &val,
            &val,
            &val,
            0,
            &modulus
        ));

        // Both policy flags active
        assert!(is_canonical_common_bn256_public_inputs(
            &val,
            &val,
            &nullifiers,
            &val,
            &val,
            &val,
            &val,
            ALLOWLIST_BIT | BLOCKLIST_BIT,
            &modulus
        ));
    }

    #[test]
    fn is_canonical_common_bn256_public_inputs_rejects_non_canonical() {
        let env = Env::default();
        let modulus = bn256_modulus(&env);
        let one = U256::from_u32(&env, 1);
        let valid = modulus.sub(&one);
        let equal = modulus.clone();
        let above = modulus.add(&one);
        let valid_nullifiers = vec![&env, valid.clone(), valid.clone()];

        for bad in [&equal, &above] {
            // Bad root
            assert!(!is_canonical_common_bn256_public_inputs(
                bad,
                &valid,
                &valid_nullifiers,
                &valid,
                &valid,
                &valid,
                &valid,
                0,
                &modulus
            ));

            // Bad public_amount
            assert!(!is_canonical_common_bn256_public_inputs(
                &valid,
                bad,
                &valid_nullifiers,
                &valid,
                &valid,
                &valid,
                &valid,
                0,
                &modulus
            ));

            // Bad nullifier
            let bad_nullifiers = vec![&env, valid.clone(), bad.clone()];
            assert!(!is_canonical_common_bn256_public_inputs(
                &valid,
                &valid,
                &bad_nullifiers,
                &valid,
                &valid,
                &valid,
                &valid,
                0,
                &modulus
            ));

            // Bad output_commitment0
            assert!(!is_canonical_common_bn256_public_inputs(
                &valid,
                &valid,
                &valid_nullifiers,
                bad,
                &valid,
                &valid,
                &valid,
                0,
                &modulus
            ));

            // Bad output_commitment1
            assert!(!is_canonical_common_bn256_public_inputs(
                &valid,
                &valid,
                &valid_nullifiers,
                &valid,
                bad,
                &valid,
                &valid,
                0,
                &modulus
            ));
        }
    }

    #[test]
    fn is_canonical_common_bn256_public_inputs_asp_policy_gating() {
        let env = Env::default();
        let modulus = bn256_modulus(&env);
        let one = U256::from_u32(&env, 1);
        let valid = modulus.sub(&one);
        let equal = modulus.clone();
        let above = modulus.add(&one);
        let valid_nullifiers = vec![&env, valid.clone()];

        for bad in [&equal, &above] {
            // When membership is required, bad asp_membership_root is rejected
            assert!(!is_canonical_common_bn256_public_inputs(
                &valid,
                &valid,
                &valid_nullifiers,
                &valid,
                &valid,
                bad,
                &valid,
                ALLOWLIST_BIT,
                &modulus
            ));

            // When membership is NOT required, bad asp_membership_root is
            // ignored
            assert!(is_canonical_common_bn256_public_inputs(
                &valid,
                &valid,
                &valid_nullifiers,
                &valid,
                &valid,
                bad,
                &valid,
                0,
                &modulus
            ));

            // When non-membership is required, bad asp_non_membership_root is
            // rejected
            assert!(!is_canonical_common_bn256_public_inputs(
                &valid,
                &valid,
                &valid_nullifiers,
                &valid,
                &valid,
                &valid,
                bad,
                BLOCKLIST_BIT,
                &modulus
            ));

            // When non-membership is NOT required, bad asp_non_membership_root
            // is ignored
            assert!(is_canonical_common_bn256_public_inputs(
                &valid,
                &valid,
                &valid_nullifiers,
                &valid,
                &valid,
                &valid,
                bad,
                0,
                &modulus
            ));
        }
    }
}
