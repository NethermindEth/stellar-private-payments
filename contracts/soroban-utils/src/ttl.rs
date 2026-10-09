//! Lifetime extensions for contract storage.
//!
//! Rewriting an entry keeps its lifetime, so storage a contract only rewrites
//! still archives. Each helper moves an entry towards [`LIFETIME_LEDGERS`], by
//! at most [`MAX_EXTENSION_LEDGERS`] per call and only once the entry has lost
//! [`MIN_EXTENSION_LEDGERS`], so one call pays for at most a day of each entry.
//! An operator who keeps entries above [`LIFETIME_LEDGERS`] turns these
//! extensions into no-ops.

use soroban_sdk::{Address, Env, IntoVal, Val};

/// Lifetime the helpers extend towards: 30 days of five-second ledgers.
pub const LIFETIME_LEDGERS: u32 = 518_400;

/// Lifetime an entry loses before a call extends it again: one hour.
pub const MIN_EXTENSION_LEDGERS: u32 = 720;

/// Most lifetime one call adds to one entry: one day.
pub const MAX_EXTENSION_LEDGERS: u32 = 17_280;

/// Extends the calling contract's instance and code.
pub fn extend_instance(env: &Env) {
    env.storage().instance().extend_ttl_with_limits(
        LIFETIME_LEDGERS,
        MIN_EXTENSION_LEDGERS,
        MAX_EXTENSION_LEDGERS,
    );
}

/// Extends the persistent entry stored under `key`.
///
/// # Panics
///
/// Panics if no persistent entry is stored under `key`.
pub fn extend_persistent<K>(env: &Env, key: &K)
where
    K: IntoVal<Env, Val>,
{
    env.storage().persistent().extend_ttl_with_limits(
        key,
        LIFETIME_LEDGERS,
        MIN_EXTENSION_LEDGERS,
        MAX_EXTENSION_LEDGERS,
    );
}

/// Extends the instance and code of `contract`.
///
/// # Panics
///
/// Panics if `contract` is not a deployed contract.
pub fn extend_contract(env: &Env, contract: &Address) {
    env.deployer().extend_ttl_with_limits(
        contract.clone(),
        LIFETIME_LEDGERS,
        MIN_EXTENSION_LEDGERS,
        MAX_EXTENSION_LEDGERS,
    );
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::{
        contract, contractimpl,
        testutils::{Deployer as _, Ledger as _, storage::Persistent as _},
    };

    const KEY: u32 = 1;

    #[contract]
    struct Probe;

    #[contractimpl]
    impl Probe {
        pub fn write(env: Env) {
            env.storage().persistent().set(&KEY, &0u32);
        }

        pub fn extend(env: Env, other: Address) {
            extend_persistent(&env, &KEY);
            extend_instance(&env);
            extend_contract(&env, &other);
        }
    }

    /// Disables snapshot writing, which Miri's isolation mode blocks.
    fn test_env() -> Env {
        #[cfg(miri)]
        {
            use soroban_sdk::testutils::EnvTestConfig;
            Env::new_with_config(EnvTestConfig {
                capture_snapshot_at_drop: false,
            })
        }
        #[cfg(not(miri))]
        {
            Env::default()
        }
    }

    fn entry_ttl(env: &Env, id: &Address) -> u32 {
        env.as_contract(id, || env.storage().persistent().get_ttl(&KEY))
    }

    fn advance(env: &Env, ledgers: u32) {
        env.ledger()
            .set_sequence_number(env.ledger().sequence().saturating_add(ledgers));
    }

    #[test]
    fn extend_persistent_adds_a_day_when_far_below_the_target() {
        let env = test_env();
        let id = env.register(Probe, ());
        let probe = ProbeClient::new(&env, &id);
        probe.write();
        let before = entry_ttl(&env, &id);

        probe.extend(&id);

        assert_eq!(
            entry_ttl(&env, &id),
            before.saturating_add(MAX_EXTENSION_LEDGERS)
        );
    }

    #[test]
    fn extensions_wait_until_an_hour_is_lost() {
        let env = test_env();
        env.ledger()
            .set_min_persistent_entry_ttl(LIFETIME_LEDGERS.saturating_add(1));
        let id = env.register(Probe, ());
        let other = env.register(Probe, ());
        let probe = ProbeClient::new(&env, &id);
        probe.write();
        let ttls = || {
            let deployer = env.deployer();
            [
                entry_ttl(&env, &id),
                deployer.get_contract_instance_ttl(&id),
                deployer.get_contract_instance_ttl(&other),
            ]
        };

        let short_of_an_hour = MIN_EXTENSION_LEDGERS.saturating_sub(1);
        advance(&env, short_of_an_hour);
        probe.extend(&other);
        let unchanged = LIFETIME_LEDGERS.saturating_sub(short_of_an_hour);
        assert_eq!(ttls(), [unchanged; 3]);

        advance(&env, 1);
        probe.extend(&other);
        assert_eq!(ttls(), [LIFETIME_LEDGERS; 3]);
    }
}
