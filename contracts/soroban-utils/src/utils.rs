use ark_bn254::{G1Affine as ArkG1Affine, G1Projective, G2Affine as ArkG2Affine, G2Projective};
use ark_ec::PrimeGroup;
use ark_ff::BigInteger;
use ark_ff::fields::PrimeField;
use circom_groth16_verifier::VerificationKeyBytes;
use soroban_sdk::{Address, BytesN, Env, IntoVal, TryFromVal, Val, Vec, contract, contractimpl, U256, Bytes, contracttype, I256};
use soroban_sdk::xdr::ToXdr;
use crate::bn256_modulus;

/// Update the contract administrator
///
/// Changes the admin address to a new address. Only the current admin
/// can call this function.
///
/// # Arguments
/// * `env` - The Soroban environment
/// * `admin_key` - Storage key for the admin address (e.g., `DataKey::Admin`)
/// * `new_admin` - Address of the new administrator
///
/// # Panics
/// Panics if the caller is not the current admin
pub fn update_admin<K>(env: &Env, admin_key: &K, new_admin: &Address)
where
    K: IntoVal<Env, Val> + TryFromVal<Env, Val> + Clone,
{
    let store = env.storage().persistent();
    let admin: Address = store.get(admin_key).unwrap();
    admin.require_auth();

    // Update admin address
    store.set(admin_key, new_admin);
}

/// Mock token contract for testing purposes
#[contract]
pub struct MockToken;

#[contractimpl]
impl MockToken {
    pub fn balance(_env: Env, _id: Address) -> i128 {
        0
    }
    pub fn transfer(_env: Env, _from: Address, _to: Address, _amount: i128) {}
    pub fn transfer_from(_env: Env, _from: Address, _to: Address, _amount: i128) {}
    pub fn approve(_env: Env, _from: Address, _spender: Address, _amount: i128) {}
    pub fn allowance(_env: Env, _from: Address, _spender: Address) -> i128 {
        0
    }
}

pub fn g1_bytes_from_ark(p: ArkG1Affine) -> [u8; 64] {
    let mut out = [0u8; 64];
    let x_bytes: [u8; 32] = p.x.into_bigint().to_bytes_be().try_into().unwrap();
    let y_bytes: [u8; 32] = p.y.into_bigint().to_bytes_be().try_into().unwrap();
    out[..32].copy_from_slice(&x_bytes);
    out[32..].copy_from_slice(&y_bytes);
    out
}

pub fn g2_bytes_from_ark(p: ArkG2Affine) -> [u8; 128] {
    let mut out = [0u8; 128];
    let x0: [u8; 32] = p.x.c0.into_bigint().to_bytes_be().try_into().unwrap();
    let x1: [u8; 32] = p.x.c1.into_bigint().to_bytes_be().try_into().unwrap();
    let y0: [u8; 32] = p.y.c0.into_bigint().to_bytes_be().try_into().unwrap();
    let y1: [u8; 32] = p.y.c1.into_bigint().to_bytes_be().try_into().unwrap();

    // Real component first, imaginary component second
    // According to Soroban G2Affine documentation
    out[..32].copy_from_slice(&x1); // x.c1 (imaginary)
    out[32..64].copy_from_slice(&x0); // x.c0 (real)
    out[64..96].copy_from_slice(&y1); // y.c1 (imaginary)
    out[96..].copy_from_slice(&y0); // y.c0 (real)
    out
}

pub fn dummy_vk_bytes(env: &Env) -> VerificationKeyBytes {
    let g1 = ArkG1Affine::from(G1Projective::generator());
    let g2 = ArkG2Affine::from(G2Projective::generator());

    let g1_bytes = g1_bytes_from_ark(g1);
    let g2_bytes = g2_bytes_from_ark(g2);

    let g1_bn = BytesN::from_array(env, &g1_bytes);
    let g2_bn = BytesN::from_array(env, &g2_bytes);

    let mut ic = Vec::new(env);
    for _ in 0..6 {
        ic.push_back(g1_bn.clone());
    }

    VerificationKeyBytes {
        alpha: g1_bn,
        beta: g2_bn.clone(),
        gamma: g2_bn.clone(),
        delta: g2_bn,
        ic,
    }
}

/// Convert an ark-groth16 VerifyingKey to Soroban VerificationKeyBytes
///
/// # Arguments
/// * `env` - The Soroban environment
/// * `vk` - The ark-groth16 VerifyingKey<Bn254>
///
/// # Returns
/// A VerificationKeyBytes struct suitable for use with the CircomGroth16Verifier contract
pub fn vk_bytes_from_ark(
    env: &Env,
    vk: &ark_groth16::VerifyingKey<ark_bn254::Bn254>,
) -> VerificationKeyBytes {
    let alpha_bytes = g1_bytes_from_ark(vk.alpha_g1);
    let beta_bytes = g2_bytes_from_ark(vk.beta_g2);
    let gamma_bytes = g2_bytes_from_ark(vk.gamma_g2);
    let delta_bytes = g2_bytes_from_ark(vk.delta_g2);

    let mut ic = Vec::new(env);
    for ic_point in &vk.gamma_abc_g1 {
        let ic_bytes = g1_bytes_from_ark(*ic_point);
        ic.push_back(BytesN::from_array(env, &ic_bytes));
    }

    VerificationKeyBytes {
        alpha: BytesN::from_array(env, &alpha_bytes),
        beta: BytesN::from_array(env, &beta_bytes),
        gamma: BytesN::from_array(env, &gamma_bytes),
        delta: BytesN::from_array(env, &delta_bytes),
        ic,
    }
}

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
    /// Relayer fee (paid from the withdrawal amount)
    pub fee: U256,
    /// Encrypted data for the first output UTXO
    pub encrypted_output0: Bytes,
    /// Encrypted data for the second output UTXO
    pub encrypted_output1: Bytes,
}

/// Hash external data using Keccak256
///
/// Serializes the external data to XDR, hashes it with Keccak256,
/// and reduces the result modulo the BN256 field size.
///
/// # Arguments
///
/// * `env` - The Soroban environment
/// * `ext` - The external data to hash
///
/// # Returns
///
/// Returns the 32-byte hash of the external data
pub fn hash_ext_data(env: &Env, ext: &ExtData) -> BytesN<32> {
    let payload = ext.clone().to_xdr(env);
    let digest: BytesN<32> = env.crypto().keccak256(&payload).into();
    let digest_u256 = U256::from_be_bytes(env, &Bytes::from(digest));
    let reduced = digest_u256.rem_euclid(&bn256_modulus(env));
    let mut buf = [0u8; 32];
    reduced.to_be_bytes().copy_into_slice(&mut buf);
    BytesN::from_array(env, &buf)
}