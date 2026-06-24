#![no_std]

use soroban_sdk::{Address, Bytes, Env, contract, contractevent, contractimpl, contracttype};

/// User account registration data
///
/// Used for registering a user's public key to enable encrypted communication
/// for receiving transfers.
/// Not required to interact with the pool. But facilitates in-pool transfers
/// via events. As parties can learn about each other public key.
#[contracttype]
pub struct Account {
    /// Owner address of the account
    pub owner: Address,
    /// X25519 encryption public key for encrypting note data (32 bytes)
    pub encryption_key: Bytes,
    /// BN254 note public key for creating commitments (32 bytes)
    pub note_key: Bytes,
}

/// Event emitted when a user registers their public keys
///
/// This event allows other users to discover keys for sending private
/// transfers. Two key types are required:
/// - encryption_key: X25519 key for encrypting note data (amount, blinding)
/// - note_key: BN254 key for creating commitments in the ZK circuit
#[contractevent]
#[derive(Clone)]
pub struct PublicKeyEvent {
    /// Address of the account owner
    #[topic]
    pub owner: Address,
    /// X25519 encryption public key
    pub encryption_key: Bytes,
    /// BN254 note public key
    pub note_key: Bytes,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum DataKey {
    Registration(Address),
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
struct Registration {
    encryption_key: Bytes,
    note_key: Bytes,
}

/// Public key registry contract.
///
/// Emits one global registration event stream for user key discovery across
/// all pools in a deployment.
#[contract]
pub struct PublicKeyRegistry;

#[contractimpl]
impl PublicKeyRegistry {
    /// Register a user's public encryption and note keys.
    pub fn register(env: Env, account: Account) {
        account.owner.require_auth();
        assert_eq!(account.encryption_key.len(), 32);
        assert_eq!(account.note_key.len(), 32);

        let key = DataKey::Registration(account.owner.clone());
        let next = Registration {
            encryption_key: account.encryption_key.clone(),
            note_key: account.note_key.clone(),
        };

        if env
            .storage()
            .persistent()
            .get::<DataKey, Registration>(&key)
            == Some(next.clone())
        {
            return;
        }

        env.storage().persistent().set(&key, &next);
        PublicKeyEvent {
            owner: account.owner,
            encryption_key: account.encryption_key,
            note_key: account.note_key,
        }
        .publish(&env);
    }
}

#[cfg(test)]
mod test;
