//! External transaction data and its hash.
//!
//! `ExtData` carries the public parameters a proof is bound to. It is hashed
//! together with the calling pool's own identity and the calling pool's own
//! token, and checked against the proof's `ext_data_hash` rather than
//! verified by the SNARK directly.

use soroban_sdk::{Address, Bytes, BytesN, Env, I256, U256, contracttype, xdr::ToXdr};
use soroban_utils::constants::bn256_modulus;

/// External data for a transaction
///
/// Contains public information about the transaction that is hashed and
/// included in the zero-knowledge proof to bind the proof to specific
/// transaction parameters (e.g. recipient address).
#[contracttype]
#[derive(Clone)]
pub struct ExtData {
    /// Recipient address for withdrawals
    pub recipient: Address,
    /// External amount: positive for deposits, negative for withdrawals
    pub ext_amount: I256,
    /// Encrypted data for the first output UTXO
    pub encrypted_output0: Bytes,
    /// Encrypted data for the second output UTXO
    pub encrypted_output1: Bytes,
}

/// `ExtData` plus the deployment domain it is bound to.
///
/// Never constructed from caller input: `pool` and `token` are read by
/// `hash_ext_data` from `env.current_contract_address()` and the caller's own
/// canonical token configuration, never from `ExtData` or any other
/// caller-supplied value. This is what makes the resulting hash, and so the
/// proof, specific to one pool contract and one token.
#[contracttype]
#[derive(Clone)]
struct ExtDataDomain {
    pool: Address,
    token: Address,
    recipient: Address,
    ext_amount: I256,
    encrypted_output0: Bytes,
    encrypted_output1: Bytes,
}

/// Hash external data using Keccak256, bound to the calling pool and its token
///
/// Serializes `ext` together with the currently executing contract's own
/// address (`env.current_contract_address()`) and the given token address to
/// XDR, hashes the result with Keccak256, and reduces it modulo the BN256
/// field size. Two pools that share a verifier/VK but differ in contract
/// address or token produce different hashes for otherwise identical `ext`,
/// so a proof built for one is not `ext_data_hash`-valid for the other.
///
/// # Arguments
///
/// * `env` - The Soroban environment
/// * `ext` - The external data to hash
/// * `token` - The calling pool's own configured token address (from that
///   pool's own persistent storage, never from caller input)
///
/// # Returns
///
/// Returns the 32-byte hash of the external data, bound to this pool and this
/// token
pub fn hash_ext_data(env: &Env, ext: &ExtData, token: &Address) -> BytesN<32> {
    let domain = ExtDataDomain {
        pool: env.current_contract_address(),
        token: token.clone(),
        recipient: ext.recipient.clone(),
        ext_amount: ext.ext_amount.clone(),
        encrypted_output0: ext.encrypted_output0.clone(),
        encrypted_output1: ext.encrypted_output1.clone(),
    };
    let payload = domain.to_xdr(env);
    let digest: BytesN<32> = env.crypto().keccak256(&payload).into();
    let digest_u256 = U256::from_be_bytes(env, &Bytes::from(digest));
    let reduced = digest_u256.rem_euclid(&bn256_modulus(env));
    let mut buf = [0u8; 32];
    reduced.to_be_bytes().copy_into_slice(&mut buf);
    BytesN::from_array(env, &buf)
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::{contract, contractimpl, testutils::Address as _};

    // A trivial local contract, not `soroban_utils::utils::MockToken`: this
    // crate must never itself contain `#[contractimpl]` in non-test code
    // (see the module comment on why), but a `#[cfg(test)]`-only one never
    // reaches `pool-core`'s compiled lib, so it carries none of that risk.
    // It exists only so `env.as_contract` has a genuinely registered address
    // to run `hash_ext_data` as.
    #[contract]
    struct DummyContract;

    #[contractimpl]
    impl DummyContract {
        pub fn noop() {}
    }

    fn register_dummy(env: &Env) -> Address {
        env.register(DummyContract, ())
    }

    fn sample_ext(env: &Env) -> ExtData {
        ExtData {
            recipient: Address::generate(env),
            ext_amount: I256::from_i32(env, 7),
            encrypted_output0: Bytes::from_slice(env, &[1, 2, 3]),
            encrypted_output1: Bytes::from_slice(env, &[4, 5]),
        }
    }

    #[test]
    fn hash_ext_data_is_deterministic() {
        let env = Env::default();
        let pool = register_dummy(&env);
        let token = Address::generate(&env);
        let ext = sample_ext(&env);

        let first = env.as_contract(&pool, || hash_ext_data(&env, &ext, &token));
        let second = env.as_contract(&pool, || hash_ext_data(&env, &ext, &token));

        assert_eq!(
            first, second,
            "identical pool, token, and ExtData must hash identically every time"
        );
    }

    #[test]
    fn hash_ext_data_changes_with_pool_address() {
        let env = Env::default();
        let pool_a = register_dummy(&env);
        let pool_b = register_dummy(&env);
        let token = Address::generate(&env);
        let ext = sample_ext(&env);

        let hash_a = env.as_contract(&pool_a, || hash_ext_data(&env, &ext, &token));
        let hash_b = env.as_contract(&pool_b, || hash_ext_data(&env, &ext, &token));

        assert_ne!(
            hash_a, hash_b,
            "identical ExtData and token must hash differently under a different pool address"
        );
    }

    #[test]
    fn hash_ext_data_changes_with_token_address() {
        let env = Env::default();
        let pool = register_dummy(&env);
        let token_a = Address::generate(&env);
        let token_b = Address::generate(&env);
        let ext = sample_ext(&env);

        let hash_a = env.as_contract(&pool, || hash_ext_data(&env, &ext, &token_a));
        let hash_b = env.as_contract(&pool, || hash_ext_data(&env, &ext, &token_b));

        assert_ne!(
            hash_a, hash_b,
            "identical ExtData and pool must hash differently under a different token address"
        );
    }
}
