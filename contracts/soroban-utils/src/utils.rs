use soroban_sdk::{Address, Env, IntoVal, TryFromVal, Val};

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
