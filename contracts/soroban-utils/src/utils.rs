use ark_bn254::{G1Affine as ArkG1Affine, G2Affine as ArkG2Affine};
use ark_ff::{BigInteger, fields::PrimeField};
use contract_types::VerificationKeyBytes;
use soroban_sdk::{Address, BytesN, Env, IntoVal, Val, Vec, contractevent};
#[cfg(any(test, feature = "testutils"))]
use soroban_sdk::{contract, contractimpl};

/// Error returned by the shared admin helpers.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AdminError {
    /// No admin address is stored under the given key.
    NotInitialized,
    /// No admin transfer is pending under the given key.
    NoPendingAdmin,
}

/// The event [`update_admin`] publishes when the admin proposes a successor.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminTransferProposed {
    /// The admin that made the proposal.
    pub admin: Address,
    /// The address that becomes admin if it accepts.
    pub pending_admin: Address,
}

/// The event [`cancel_admin_transfer`] publishes when the admin withdraws a
/// proposal.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminTransferCancelled {
    /// The admin that withdrew the proposal.
    pub admin: Address,
    /// The address that was proposed.
    pub pending_admin: Address,
}

/// The event [`accept_admin`] publishes when the proposed address takes over.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminTransferAccepted {
    /// The admin replaced by the transfer.
    pub old_admin: Address,
    /// The admin installed by the transfer.
    pub new_admin: Address,
}

/// Returns the administrator stored under `admin_key` in persistent storage.
///
/// # Errors
///
/// Returns [`AdminError::NotInitialized`] if no address is stored under
/// `admin_key`.
pub fn get_admin<K>(env: &Env, admin_key: &K) -> Result<Address, AdminError>
where
    K: IntoVal<Env, Val>,
{
    env.storage()
        .persistent()
        .get(admin_key)
        .ok_or(AdminError::NotInitialized)
}

/// Returns the administrator proposed under `pending_key`, or `None` when no
/// transfer is pending.
pub fn get_pending_admin<K>(env: &Env, pending_key: &K) -> Option<Address>
where
    K: IntoVal<Env, Val>,
{
    env.storage().persistent().get(pending_key)
}

/// Proposes `new_admin` as the next administrator.
///
/// Stores the proposal under `pending_key`, replacing any earlier one, and
/// publishes [`AdminTransferProposed`]. The admin keeps every power until
/// `new_admin` calls [`accept_admin`]. Each contract passes its own keys, so
/// contracts sharing this helper keep separate entries.
///
/// # Errors
///
/// Returns [`AdminError::NotInitialized`] if no address is stored under
/// `admin_key`.
///
/// # Panics
///
/// Panics if the address stored under `admin_key` does not authorize the call.
pub fn update_admin<K>(
    env: &Env,
    admin_key: &K,
    pending_key: &K,
    new_admin: &Address,
) -> Result<(), AdminError>
where
    K: IntoVal<Env, Val>,
{
    let admin = get_admin(env, admin_key)?;
    admin.require_auth();

    env.storage().persistent().set(pending_key, new_admin);
    AdminTransferProposed {
        admin,
        pending_admin: new_admin.clone(),
    }
    .publish(env);
    Ok(())
}

/// Withdraws the proposal stored under `pending_key`.
///
/// Publishes [`AdminTransferCancelled`].
///
/// # Errors
///
/// Returns [`AdminError::NotInitialized`] if no address is stored under
/// `admin_key`, and [`AdminError::NoPendingAdmin`] if no proposal is stored
/// under `pending_key`.
///
/// # Panics
///
/// Panics if the address stored under `admin_key` does not authorize the call.
pub fn cancel_admin_transfer<K>(env: &Env, admin_key: &K, pending_key: &K) -> Result<(), AdminError>
where
    K: IntoVal<Env, Val>,
{
    let admin = get_admin(env, admin_key)?;
    admin.require_auth();
    let pending_admin = get_pending_admin(env, pending_key).ok_or(AdminError::NoPendingAdmin)?;

    env.storage().persistent().remove(pending_key);
    AdminTransferCancelled {
        admin,
        pending_admin,
    }
    .publish(env);
    Ok(())
}

/// Installs the address proposed under `pending_key` as the administrator.
///
/// Replaces the address under `admin_key`, removes the proposal, and publishes
/// [`AdminTransferAccepted`].
///
/// # Errors
///
/// Returns [`AdminError::NoPendingAdmin`] if no proposal is stored under
/// `pending_key`, and [`AdminError::NotInitialized`] if no address is stored
/// under `admin_key`.
///
/// # Panics
///
/// Panics if the proposed address does not authorize the call.
pub fn accept_admin<K>(env: &Env, admin_key: &K, pending_key: &K) -> Result<(), AdminError>
where
    K: IntoVal<Env, Val>,
{
    let new_admin = get_pending_admin(env, pending_key).ok_or(AdminError::NoPendingAdmin)?;
    new_admin.require_auth();
    let old_admin = get_admin(env, admin_key)?;

    let storage = env.storage().persistent();
    storage.set(admin_key, &new_admin);
    storage.remove(pending_key);
    AdminTransferAccepted {
        old_admin,
        new_admin,
    }
    .publish(env);
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
