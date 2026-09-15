//! Ledger entry lifetime extensions.
//!
//! Every ledger entry carries a time to live (TTL) measured in ledgers, and the
//! network archives an entry whose TTL reaches zero. Writing an entry does not
//! refresh its TTL, so a persistent entry created with the network minimum is
//! archived seven days later unless something extends it. Each helper below
//! extends an entry to [`EXTEND_TO`] once fewer than [`THRESHOLD`] ledgers
//! remain, which keeps the state a contract touches alive for as long
//! as the contract keeps being called.
//!
//! Call [`bump_entry`] only on a key that already holds a value. Extending a
//! missing persistent entry is a host error that traps the invocation.

use soroban_sdk::{Address, Env, IntoVal, Val};

/// Ledgers per day at the five-second close time.
pub const DAY_IN_LEDGERS: u32 = 17_280;

/// Remaining lifetime below which an extension takes effect.
pub const THRESHOLD: u32 = 30 * DAY_IN_LEDGERS;

/// Lifetime that an extension targets, equal to the network maximum entry TTL.
///
/// The host clamps an extension to the network maximum, so this value is safe
/// on a network whose maximum is lower.
pub const EXTEND_TO: u32 = 180 * DAY_IN_LEDGERS;

/// Extends the TTL of the calling contract's instance and code entries.
pub fn bump_instance(env: &Env) {
    env.storage().instance().extend_ttl(THRESHOLD, EXTEND_TO);
}

/// Extends the TTL of the persistent entry stored under `key`.
///
/// # Panics
///
/// Panics if no persistent entry is stored under `key`, because the host
/// rejects an extension of an entry that does not exist.
pub fn bump_entry<K>(env: &Env, key: &K)
where
    K: IntoVal<Env, Val>,
{
    env.storage()
        .persistent()
        .extend_ttl(key, THRESHOLD, EXTEND_TO);
}

/// Extends the TTL of the instance and code entries of `contract`.
///
/// Use this to keep a contract that this one calls out to reachable, such as a
/// proof verifier or a policy registry.
///
/// # Panics
///
/// Panics if `contract` does not name a deployed contract, because the host
/// rejects an extension of an instance or code entry that does not exist.
pub fn bump_dependency(env: &Env, contract: &Address) {
    env.deployer()
        .extend_ttl(contract.clone(), THRESHOLD, EXTEND_TO);
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::{
        contract, contractimpl,
        testutils::{
            Ledger as _,
            storage::{Instance as _, Persistent as _},
        },
    };

    const KEY: u32 = 7;

    #[contract]
    struct TtlProbe;

    #[contractimpl]
    impl TtlProbe {
        pub fn write(env: Env) {
            env.storage().persistent().set(&KEY, &1u32);
        }

        pub fn bump_key(env: Env) {
            bump_entry(&env, &KEY);
        }

        pub fn bump_self(env: Env) {
            bump_instance(&env);
        }

        pub fn bump_other(env: Env, contract: Address) {
            bump_dependency(&env, &contract);
        }
    }

    fn entry_ttl(env: &Env, id: &Address) -> u32 {
        env.as_contract(id, || env.storage().persistent().get_ttl(&KEY))
    }

    fn instance_ttl(env: &Env, id: &Address) -> u32 {
        env.as_contract(id, || env.storage().instance().get_ttl())
    }

    fn advance(env: &Env, ledgers: u32) {
        let next = env.ledger().sequence().saturating_add(ledgers);
        env.ledger().set_sequence_number(next);
    }

    #[test]
    fn bump_entry_extends_a_fresh_entry_to_the_target() {
        let env = Env::default();
        let id = env.register(TtlProbe, ());
        let client = TtlProbeClient::new(&env, &id);

        client.write();
        client.bump_key();

        assert_eq!(entry_ttl(&env, &id), EXTEND_TO);
    }

    #[test]
    fn bump_entry_is_a_no_op_above_the_threshold() {
        let env = Env::default();
        let id = env.register(TtlProbe, ());
        let client = TtlProbeClient::new(&env, &id);

        client.write();
        client.bump_key();
        advance(&env, 1);
        client.bump_key();

        assert_eq!(entry_ttl(&env, &id), EXTEND_TO.saturating_sub(1));
    }

    #[test]
    fn bump_entry_extends_again_once_below_the_threshold() {
        let env = Env::default();
        let id = env.register(TtlProbe, ());
        let client = TtlProbeClient::new(&env, &id);

        client.write();
        client.bump_key();
        advance(&env, EXTEND_TO.saturating_sub(THRESHOLD).saturating_add(1));
        client.bump_key();

        assert_eq!(entry_ttl(&env, &id), EXTEND_TO);
    }

    #[test]
    fn bump_entry_is_clamped_to_the_network_maximum() {
        let env = Env::default();
        // Above the environment's minimum persistent entry TTL, so a fresh
        // entry starts below the maximum and the clamp is observable.
        env.ledger().set_max_entry_ttl(100_000);
        let id = env.register(TtlProbe, ());
        let client = TtlProbeClient::new(&env, &id);

        client.write();
        client.bump_key();

        assert_eq!(entry_ttl(&env, &id), 100_000);
    }

    #[test]
    fn bump_instance_extends_the_instance() {
        let env = Env::default();
        let id = env.register(TtlProbe, ());
        let client = TtlProbeClient::new(&env, &id);

        client.bump_self();

        assert_eq!(instance_ttl(&env, &id), EXTEND_TO);
    }

    #[test]
    fn bump_dependency_extends_another_contract() {
        let env = Env::default();
        let caller = env.register(TtlProbe, ());
        let dependency = env.register(TtlProbe, ());

        TtlProbeClient::new(&env, &caller).bump_other(&dependency);

        assert_eq!(instance_ttl(&env, &dependency), EXTEND_TO);
    }

    /// This test is skipped under Miri because the panic formatting path
    /// triggers undefined behavior in the `ethnum` crate's unsafe
    /// formatting code. See: https://github.com/nlordell/ethnum-rs/issues/34
    #[test]
    #[cfg_attr(miri, ignore)]
    #[should_panic(expected = "MissingValue")]
    fn bump_entry_on_a_missing_key_panics() {
        let env = Env::default();
        let id = env.register(TtlProbe, ());

        TtlProbeClient::new(&env, &id).bump_key();
    }
}
