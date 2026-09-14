use ark_bn254::{G1Affine as ArkG1Affine, G2Affine as ArkG2Affine};
use ark_ff::{BigInteger, fields::PrimeField};
use contract_types::VerificationKeyBytes;
use soroban_sdk::{Address, BytesN, Env, IntoVal, TryFromVal, Val, Vec};
#[cfg(any(test, feature = "testutils"))]
use soroban_sdk::{contract, contractimpl};

/// Error returned by the shared admin helpers.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AdminError {
    /// No admin address is stored under the given key.
    NotInitialized,
}

/// Replaces the administrator stored under `admin_key` with `new_admin`.
///
/// The address already stored under `admin_key` must authorize the call. Each
/// contract passes its own storage key, so contracts sharing this helper keep
/// separate admin entries.
///
/// # Errors
///
/// Returns [`AdminError::NotInitialized`] if no address is stored under
/// `admin_key`.
///
/// # Panics
///
/// Panics if the address stored under `admin_key` does not authorize the call,
/// because `require_auth` raises a host error rather than returning.
pub fn update_admin<K>(env: &Env, admin_key: &K, new_admin: &Address) -> Result<(), AdminError>
where
    K: IntoVal<Env, Val> + TryFromVal<Env, Val> + Clone,
{
    let store = env.storage().persistent();
    let admin: Address = store.get(admin_key).ok_or(AdminError::NotInitialized)?;
    admin.require_auth();

    store.set(admin_key, new_admin);
    Ok(())
}

/// Mock token contract for testing purposes
#[cfg(any(test, feature = "testutils"))]
#[contract]
pub struct MockToken;

#[cfg(any(test, feature = "testutils"))]
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
    let x_bytes: [u8; 32] =
        p.x.into_bigint()
            .to_bytes_be()
            .try_into()
            .expect("length mismatch");
    let y_bytes: [u8; 32] =
        p.y.into_bigint()
            .to_bytes_be()
            .try_into()
            .expect("length mismatch");
    out[..32].copy_from_slice(&x_bytes);
    out[32..].copy_from_slice(&y_bytes);
    out
}

pub fn g2_bytes_from_ark(p: ArkG2Affine) -> [u8; 128] {
    let mut out = [0u8; 128];
    let x0: [u8; 32] =
        p.x.c0
            .into_bigint()
            .to_bytes_be()
            .try_into()
            .expect("length mismatch");
    let x1: [u8; 32] =
        p.x.c1
            .into_bigint()
            .to_bytes_be()
            .try_into()
            .expect("length mismatch");
    let y0: [u8; 32] =
        p.y.c0
            .into_bigint()
            .to_bytes_be()
            .try_into()
            .expect("length mismatch");
    let y1: [u8; 32] =
        p.y.c1
            .into_bigint()
            .to_bytes_be()
            .try_into()
            .expect("length mismatch");

    // Imaginary component first, real component second
    // According to Soroban G2Affine documentation
    out[..32].copy_from_slice(&x1); // x.c1 (imaginary)
    out[32..64].copy_from_slice(&x0); // x.c0 (real)
    out[64..96].copy_from_slice(&y1); // y.c1 (imaginary)
    out[96..].copy_from_slice(&y0); // y.c0 (real)
    out
}

/// Convert an ark-groth16 VerifyingKey to Soroban VerificationKeyBytes
///
/// # Arguments
/// * `env` - The Soroban environment
/// * `vk` - The ark-groth16 `VerifyingKey<Bn254>`
///
/// # Returns
/// A VerificationKeyBytes struct suitable for use with the
/// CircomGroth16Verifier contract
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
