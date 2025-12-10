use soroban_sdk::{Address, Env, IntoVal, TryFromVal, Val, contract, contractimpl};
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
