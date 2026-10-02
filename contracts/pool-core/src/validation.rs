//! Transaction validation shared by `pool` and `pool-gvk`.
//!
//! Holds the validation logic common to both contract flavors:
//! - Merkle root verification in recent history
//! - Input nullifier unspent checks
//! - External data hash binding
//! - Public amount calculation and equivalence
//! - ASP policy membership and non-membership root checks
//! - Deposit bounds and conversion checking
//! - Canonical field-range checking for BN254 scalar public inputs

use crate::{
    ASPMembershipClient, ASPNonMembershipClient, ExtData, amounts, hash_ext_data,
    merkle_with_history::{Error as MerkleError, MerkleTreeWithHistory},
    policy,
};
use soroban_sdk::{Address, BytesN, Env, I256, U256, Vec};

/// Validation error types matching the pool contract error variants.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    WrongExtAmount,
    InvalidProof,
    UnknownRoot,
    AlreadySpentNullifier,
    WrongExtHash,
    NotInitialized,
    NonCanonicalPublicInput,
}

impl From<MerkleError> for Error {
    fn from(e: MerkleError) -> Self {
        match e {
            MerkleError::NotInitialized => Error::NotInitialized,
            _ => Error::UnknownRoot,
        }
    }
}

/// Validate deposit amount: if positive, ensure it does not exceed maximum
/// deposit and fits within non-negative i128. Returns `Ok(Some(amount))` for
/// deposits, or `Ok(None)` for non-deposit transactions.
pub fn validate_deposit_amount(
    env: &Env,
    ext_amount: &I256,
    max_deposit: &U256,
) -> Result<Option<i128>, Error> {
    let zero = I256::from_i32(env, 0);
    if *ext_amount > zero {
        let deposit_u = U256::from_be_bytes(env, &ext_amount.to_be_bytes());
        if deposit_u > *max_deposit {
            return Err(Error::WrongExtAmount);
        }
        let amount = amounts::i256_to_i128_nonneg(env, ext_amount).ok_or(Error::WrongExtAmount)?;
        Ok(Some(amount))
    } else {
        Ok(None)
    }
}

/// Check that the Merkle root is in the recent history of the pool's tree.
pub fn validate_root(env: &Env, root: &U256) -> Result<(), Error> {
    if !MerkleTreeWithHistory::is_known_root(env, root)? {
        return Err(Error::UnknownRoot);
    }
    Ok(())
}

/// Check that none of the transaction's input nullifiers have already been
/// spent.
pub fn validate_nullifiers<E, F>(nullifiers: &Vec<U256>, mut is_spent: F) -> Result<(), E>
where
    F: FnMut(&U256) -> Result<bool, E>,
    E: From<Error>,
{
    for n in nullifiers.iter() {
        if is_spent(&n)? {
            return Err(Error::AlreadySpentNullifier.into());
        }
    }
    Ok(())
}

/// Verify that the transaction's external data hash matches the Keccak256
/// hash of the provided external data bound to this pool's address and token.
pub fn validate_ext_data_hash(
    env: &Env,
    ext_data: &ExtData,
    token: &Address,
    proof_hash: &BytesN<32>,
) -> Result<(), Error> {
    let ext_hash = hash_ext_data(env, ext_data, token);
    if &ext_hash != proof_hash {
        return Err(Error::WrongExtHash);
    }
    Ok(())
}

/// Verify that the proof's public amount matches the expected amount
/// calculated from the external amount in the BN256 field.
pub fn validate_public_amount(
    env: &Env,
    ext_amount: &I256,
    proof_public_amount: &U256,
) -> Result<(), Error> {
    let expected =
        amounts::calculate_public_amount(env, ext_amount.clone()).ok_or(Error::WrongExtAmount)?;
    if proof_public_amount != &expected {
        return Err(Error::WrongExtAmount);
    }
    Ok(())
}

/// Validate membership and non-membership ASP roots against their respective
/// contracts according to the configured policy flags.
pub fn validate_asp_roots(
    env: &Env,
    policy_flags: u32,
    asp_membership: &Address,
    asp_non_membership: &Address,
    proof_membership_root: &U256,
    proof_non_membership_root: &U256,
) -> Result<(), Error> {
    if policy::requires_non_membership_proofs(policy_flags) {
        let client = ASPNonMembershipClient::new(env, asp_non_membership);
        if client.get_root() != *proof_non_membership_root {
            return Err(Error::InvalidProof);
        }
    }
    if policy::requires_membership_proofs(policy_flags) {
        let client = ASPMembershipClient::new(env, asp_membership);
        if !client.is_known_root(proof_membership_root) {
            return Err(Error::InvalidProof);
        }
    }
    Ok(())
}

/// Reject values outside the canonical BN254 scalar-field range.
pub fn validate_bn256_public_input(value: &U256, modulus: &U256) -> Result<(), Error> {
    if amounts::is_canonical_bn256_public_input(value, modulus) {
        Ok(())
    } else {
        Err(Error::NonCanonicalPublicInput)
    }
}

/// Validate canonical range for all standard public input fields shared by
/// privacy pools.
pub fn validate_base_bn256_public_inputs(
    root: &U256,
    public_amount: &U256,
    input_nullifiers: &Vec<U256>,
    output_commitment0: &U256,
    output_commitment1: &U256,
    asp_membership_root: &U256,
    asp_non_membership_root: &U256,
    policy_flags: u32,
    modulus: &U256,
) -> Result<(), Error> {
    validate_bn256_public_input(root, modulus)?;
    validate_bn256_public_input(public_amount, modulus)?;
    for nullifier in input_nullifiers.iter() {
        validate_bn256_public_input(&nullifier, modulus)?;
    }
    validate_bn256_public_input(output_commitment0, modulus)?;
    validate_bn256_public_input(output_commitment1, modulus)?;
    if policy::requires_membership_proofs(policy_flags) {
        validate_bn256_public_input(asp_membership_root, modulus)?;
    }
    if policy::requires_non_membership_proofs(policy_flags) {
        validate_bn256_public_input(asp_non_membership_root, modulus)?;
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::vec;
    use soroban_utils::constants::bn256_modulus;

    #[test]
    fn test_validate_deposit_amount() {
        let env = Env::default();
        let max_deposit = U256::from_u32(&env, 1000);

        // Positive deposit within limit
        let ext_amount = I256::from_i32(&env, 500);
        let res = validate_deposit_amount(&env, &ext_amount, &max_deposit);
        assert_eq!(res, Ok(Some(500)));

        // Positive deposit exceeding limit
        let ext_amount = I256::from_i32(&env, 1500);
        let res = validate_deposit_amount(&env, &ext_amount, &max_deposit);
        assert_eq!(res, Err(Error::WrongExtAmount));

        // Negative ext_amount (withdrawal) returns Ok(None)
        let ext_amount = I256::from_i32(&env, -500);
        let res = validate_deposit_amount(&env, &ext_amount, &max_deposit);
        assert_eq!(res, Ok(None));

        // Zero ext_amount returns Ok(None)
        let ext_amount = I256::from_i32(&env, 0);
        let res = validate_deposit_amount(&env, &ext_amount, &max_deposit);
        assert_eq!(res, Ok(None));
    }

    #[test]
    fn test_validate_bn256_public_input() {
        let env = Env::default();
        let modulus = bn256_modulus(&env);
        let valid = U256::from_u32(&env, 12345);
        assert_eq!(validate_bn256_public_input(&valid, &modulus), Ok(()));

        assert_eq!(
            validate_bn256_public_input(&modulus, &modulus),
            Err(Error::NonCanonicalPublicInput)
        );
    }

    #[test]
    fn test_validate_nullifiers() {
        let env = Env::default();
        let n1 = U256::from_u32(&env, 1);
        let n2 = U256::from_u32(&env, 2);
        let nullifiers = vec![&env, n1.clone(), n2.clone()];

        // None spent
        let res = validate_nullifiers::<Error, _>(&nullifiers, |_| Ok(false));
        assert_eq!(res, Ok(()));

        // One spent
        let res = validate_nullifiers::<Error, _>(&nullifiers, |n| Ok(*n == n2));
        assert_eq!(res, Err(Error::AlreadySpentNullifier));
    }

    #[test]
    fn test_validate_public_amount() {
        let env = Env::default();
        let ext_amount = I256::from_i32(&env, 100);
        let valid_pa = U256::from_u32(&env, 100);
        let wrong_pa = U256::from_u32(&env, 99);

        assert_eq!(validate_public_amount(&env, &ext_amount, &valid_pa), Ok(()));
        assert_eq!(
            validate_public_amount(&env, &ext_amount, &wrong_pa),
            Err(Error::WrongExtAmount)
        );
    }
}
