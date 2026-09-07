#![cfg(test)]

extern crate alloc;

use super::*;
use asp_membership::{ASPMembership, ASPMembershipClient};
use soroban_sdk::{
    Address, Bytes, BytesN, Env, IntoVal, InvokeError, Symbol, U256, Val, Vec,
    events::Event,
    testutils::{
        Address as _, Events, Ledger as _, MockAuth, MockAuthInvoke,
        storage::{Instance as _, Persistent as _},
    },
    vec,
    xdr::{self, ToXdr},
};
use soroban_utils::{
    pausable::{MUTATIONS, PauseState},
    ttl::{EXTEND_TO, THRESHOLD},
};
use stellar_access::access_control::RoleGranted;
use stellar_governance::timelock::{OperationCancelled, OperationExecuted, OperationScheduled};

const DELAY: u32 = DELAY_FLOOR;
const RECOVERY_DELAY: u32 = 20;
const GRACE: u32 = 5;
const GUARDIAN_PAUSE: u32 = 15;

/// Create a test environment that disables snapshot writing under Miri.
/// Miri's isolation mode blocks filesystem operations, which the Soroban SDK
/// uses for test snapshots.
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

#[contracttype]
enum MockKey {
    LastPoke,
}

/// A target the governor can call, recording the argument it was called with.
#[contract]
pub struct MockTarget;

#[contractimpl]
impl MockTarget {
    pub fn poke(env: Env, x: u32) {
        env.storage().instance().set(&MockKey::LastPoke, &x);
    }

    pub fn last_poke(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&MockKey::LastPoke)
            .unwrap_or(0)
    }

    pub fn fail() {
        panic!()
    }
}

struct Setup {
    mock: Address,
    governor: Address,
    council: Address,
    recovery: Address,
    guardian: Address,
}

fn roles(env: &Env, council: &Address, recovery: &Address, guardian: &Address) -> Vec<RoleGrant> {
    vec![
        env,
        RoleGrant {
            role: COUNCIL,
            member: council.clone(),
        },
        RoleGrant {
            role: RECOVERY,
            member: recovery.clone(),
        },
        RoleGrant {
            role: GUARDIAN,
            member: guardian.clone(),
        },
    ]
}

fn register_governor(
    env: &Env,
    delay: u32,
    recovery_delay: u32,
    grace: u32,
    guardian_pause: u32,
    roles: Vec<RoleGrant>,
    fn_roles: Vec<FnRule>,
) -> Address {
    env.register(
        Governor,
        (
            delay,
            recovery_delay,
            grace,
            guardian_pause,
            roles,
            fn_roles,
        ),
    )
}

fn setup(env: &Env) -> Setup {
    let mock = env.register(MockTarget, ());
    let council = Address::generate(env);
    let recovery = Address::generate(env);
    let guardian = Address::generate(env);
    let governor = register_governor(
        env,
        DELAY,
        RECOVERY_DELAY,
        GRACE,
        GUARDIAN_PAUSE,
        roles(env, &council, &recovery, &guardian),
        Vec::new(env),
    );
    Setup {
        mock,
        governor,
        council,
        recovery,
        guardian,
    }
}

/// The value a `try_` client yields for a contract error raised by a function
/// that declares no error type of its own.
fn host_error(code: u32) -> soroban_sdk::Error {
    soroban_sdk::Error::from_contract_error(code)
}

fn no_predecessor(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0u8; 32])
}

fn salt(env: &Env, byte: u8) -> BytesN<32> {
    BytesN::from_array(env, &[byte; 32])
}

fn poke(env: &Env) -> Symbol {
    Symbol::new(env, "poke")
}

fn poke_args(env: &Env, x: u32) -> Vec<Val> {
    vec![env, x.into_val(env)]
}

fn grant_role_fn(env: &Env) -> Symbol {
    Symbol::new(env, "grant_role")
}

/// Schedules `poke(7)` on the mock from the council and returns its id.
fn schedule_poke(env: &Env, s: &Setup) -> BytesN<32> {
    GovernorClient::new(env, &s.governor).schedule(
        &s.mock,
        &poke(env),
        &poke_args(env, 7),
        &no_predecessor(env),
        &salt(env, 1),
        &s.council,
    )
}

/// Schedules `grant_role` on the governor from the recovery role and returns
/// its id.
fn schedule_recovery(env: &Env, s: &Setup, byte: u8) -> BytesN<32> {
    GovernorClient::new(env, &s.governor).schedule(
        &s.governor,
        &grant_role_fn(env),
        &Vec::new(env),
        &no_predecessor(env),
        &salt(env, byte),
        &s.recovery,
    )
}

// ---------------------------------------------------------------- constructor

// Every test below that asserts a panic carries `#[cfg_attr(miri, ignore)]`,
// because the panic formatting path triggers undefined behavior in the
// `ethnum` crate's unsafe formatting code.
// See: https://github.com/nlordell/ethnum-rs/issues/34

#[test]
#[cfg_attr(miri, ignore)]
#[should_panic(expected = "Error(Contract, #3001)")]
fn constructor_rejects_delay_below_floor() {
    let env = test_env();
    let council = Address::generate(&env);
    let recovery = Address::generate(&env);
    let guardian = Address::generate(&env);

    register_governor(
        &env,
        DELAY_FLOOR - 1,
        RECOVERY_DELAY,
        GRACE,
        GUARDIAN_PAUSE,
        roles(&env, &council, &recovery, &guardian),
        Vec::new(&env),
    );
}

#[test]
#[cfg_attr(miri, ignore)]
#[should_panic(expected = "Error(Contract, #3001)")]
fn constructor_rejects_recovery_delay_below_delay() {
    let env = test_env();
    let council = Address::generate(&env);
    let recovery = Address::generate(&env);
    let guardian = Address::generate(&env);

    register_governor(
        &env,
        DELAY,
        DELAY - 1,
        GRACE,
        GUARDIAN_PAUSE,
        roles(&env, &council, &recovery, &guardian),
        Vec::new(&env),
    );
}

#[test]
#[cfg_attr(miri, ignore)]
#[should_panic(expected = "Error(Contract, #3001)")]
fn constructor_rejects_zero_grace() {
    let env = test_env();
    let council = Address::generate(&env);
    let recovery = Address::generate(&env);
    let guardian = Address::generate(&env);

    register_governor(
        &env,
        DELAY,
        RECOVERY_DELAY,
        0,
        GUARDIAN_PAUSE,
        roles(&env, &council, &recovery, &guardian),
        Vec::new(&env),
    );
}

#[test]
#[cfg_attr(miri, ignore)]
#[should_panic(expected = "Error(Contract, #3001)")]
fn constructor_rejects_a_guardian_pause_equal_to_the_delay() {
    let env = test_env();
    let council = Address::generate(&env);
    let recovery = Address::generate(&env);
    let guardian = Address::generate(&env);

    register_governor(
        &env,
        DELAY,
        RECOVERY_DELAY,
        GRACE,
        DELAY,
        roles(&env, &council, &recovery, &guardian),
        Vec::new(&env),
    );
}

#[test]
#[cfg_attr(miri, ignore)]
#[should_panic(expected = "Error(Contract, #3001)")]
fn constructor_rejects_an_unknown_role() {
    let env = test_env();
    let council = Address::generate(&env);
    let recovery = Address::generate(&env);
    let guardian = Address::generate(&env);
    let stranger = Address::generate(&env);

    let mut grants = roles(&env, &council, &recovery, &guardian);
    grants.push_back(RoleGrant {
        role: Symbol::new(&env, "auditor"),
        member: stranger,
    });

    register_governor(
        &env,
        DELAY,
        RECOVERY_DELAY,
        GRACE,
        GUARDIAN_PAUSE,
        grants,
        Vec::new(&env),
    );
}

#[test]
#[cfg_attr(miri, ignore)]
#[should_panic(expected = "Error(Contract, #3001)")]
fn constructor_rejects_a_missing_council() {
    let env = test_env();
    let recovery = Address::generate(&env);
    let guardian = Address::generate(&env);

    register_governor(
        &env,
        DELAY,
        RECOVERY_DELAY,
        GRACE,
        GUARDIAN_PAUSE,
        vec![
            &env,
            RoleGrant {
                role: RECOVERY,
                member: recovery,
            },
            RoleGrant {
                role: GUARDIAN,
                member: guardian,
            },
        ],
        Vec::new(&env),
    );
}

#[test]
#[cfg_attr(miri, ignore)]
#[should_panic(expected = "Error(Contract, #3001)")]
fn constructor_rejects_a_missing_recovery_holder() {
    let env = test_env();
    let council = Address::generate(&env);
    let guardian = Address::generate(&env);

    register_governor(
        &env,
        DELAY,
        RECOVERY_DELAY,
        GRACE,
        GUARDIAN_PAUSE,
        vec![
            &env,
            RoleGrant {
                role: COUNCIL,
                member: council,
            },
            RoleGrant {
                role: GUARDIAN,
                member: guardian,
            },
        ],
        Vec::new(&env),
    );
}

#[test]
#[cfg_attr(miri, ignore)]
#[should_panic(expected = "Error(Contract, #3001)")]
fn constructor_rejects_a_missing_guardian() {
    let env = test_env();
    let council = Address::generate(&env);
    let recovery = Address::generate(&env);

    register_governor(
        &env,
        DELAY,
        RECOVERY_DELAY,
        GRACE,
        GUARDIAN_PAUSE,
        vec![
            &env,
            RoleGrant {
                role: COUNCIL,
                member: council,
            },
            RoleGrant {
                role: RECOVERY,
                member: recovery,
            },
        ],
        Vec::new(&env),
    );
}

#[test]
#[cfg_attr(miri, ignore)]
#[should_panic(expected = "Error(Contract, #3001)")]
fn constructor_rejects_one_address_under_two_roles() {
    let env = test_env();
    let council = Address::generate(&env);
    let recovery = Address::generate(&env);
    let guardian = Address::generate(&env);

    let mut grants = roles(&env, &council, &recovery, &guardian);
    grants.push_back(RoleGrant {
        role: OPERATOR,
        member: council,
    });

    register_governor(
        &env,
        DELAY,
        RECOVERY_DELAY,
        GRACE,
        GUARDIAN_PAUSE,
        grants,
        Vec::new(&env),
    );
}

#[test]
fn constructor_sets_every_getter() {
    let env = test_env();
    let s = setup(&env);
    let client = GovernorClient::new(&env, &s.governor);

    assert_eq!(
        client.get_delays(),
        Delays {
            delay: DELAY,
            recovery_delay: RECOVERY_DELAY,
            grace: GRACE,
            guardian_pause: GUARDIAN_PAUSE,
        }
    );

    assert!(client.has_role(&s.council, &COUNCIL));
    assert!(client.has_role(&s.recovery, &RECOVERY));
    assert!(client.has_role(&s.guardian, &GUARDIAN));
    assert!(!client.has_role(&s.guardian, &COUNCIL));

    assert_eq!(client.get_role_member_count(&COUNCIL), 1);
    assert_eq!(client.get_role_member_count(&OPERATOR), 0);
    assert_eq!(client.get_role_member(&COUNCIL, &0), s.council);

    assert_eq!(client.get_fn_role(&s.mock, &poke(&env)), None);
    assert_eq!(client.get_pending(), Vec::new(&env));

    env.mock_all_auths();
    assert_eq!(
        client.hash_operation(
            &s.mock,
            &poke(&env),
            &poke_args(&env, 7),
            &no_predecessor(&env),
            &salt(&env, 1),
        ),
        schedule_poke(&env, &s)
    );
}

#[test]
fn constructor_emits_role_granted() {
    let env = test_env();
    let council = Address::generate(&env);
    let recovery = Address::generate(&env);
    let guardian = Address::generate(&env);
    let governor = register_governor(
        &env,
        DELAY,
        RECOVERY_DELAY,
        GRACE,
        GUARDIAN_PAUSE,
        roles(&env, &council, &recovery, &guardian),
        Vec::new(&env),
    );

    let events = env.events().all();
    let expected = RoleGranted {
        role: COUNCIL,
        account: council,
        caller: governor.clone(),
    }
    .to_xdr(&env, &governor);
    assert_eq!(events.events()[0], expected);
}

#[test]
fn the_constructor_extends_the_ttl_of_the_role_entries() {
    let env = test_env();
    let s = setup(&env);

    env.as_contract(&s.governor, || {
        let store = env.storage().persistent();
        assert_eq!(
            store.get_ttl(&access::AccessControlStorageKey::HasRole(
                s.council.clone(),
                COUNCIL
            )),
            EXTEND_TO
        );
        assert_eq!(
            store.get_ttl(&access::AccessControlStorageKey::RoleAccountsCount(COUNCIL)),
            EXTEND_TO
        );
        assert_eq!(
            store.get_ttl(&access::AccessControlStorageKey::ExistingRoles),
            EXTEND_TO
        );
    });
}

/// The governor's storage keys as OpenZeppelin encodes them, in lowercase
/// hexadecimal XDR.
///
/// The same five constants appear in `tools/ttl-keeper/src/keys.rs`, which
/// rebuilds these keys from their variant names alone because it cannot depend
/// on the key types. The pair of tests is what ties those names to this
/// contract: a rename upstream fails the test below, and a wrong name in the
/// keeper fails the keeper's own.
const EXISTING_ROLES_XDR: &str = concat!(
    "0000001000000001000000010000000f0000000d4578697374696e67526f6c65",
    "73000000",
);
const HAS_ROLE_XDR: &str = concat!(
    "0000001000000001000000030000000f00000007486173526f6c650000000012",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "00000000000000000000000f00000008677561726469616e",
);
const ROLE_ACCOUNTS_COUNT_XDR: &str = concat!(
    "0000001000000001000000020000000f00000011526f6c654163636f756e7473",
    "436f756e740000000000000f00000008677561726469616e",
);
const ROLE_ACCOUNTS_XDR: &str = concat!(
    "0000001000000001000000020000000f0000000c526f6c654163636f756e7473",
    "0000001100000001000000020000000f00000005696e64657800000000000003",
    "000000000000000f00000004726f6c650000000f00000008677561726469616e",
);
const OPERATION_LEDGER_XDR: &str = concat!(
    "0000001000000001000000020000000f0000000f4f7065726174696f6e4c6564",
    "676572000000000d000000200707070707070707070707070707070707070707",
    "070707070707070707070707",
);

/// The role holder the pinned `HasRole` and `RoleAccounts` keys name.
const PINNED_HOLDER: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

/// Asserts that `key` encodes to `expected`, given as lowercase hexadecimal.
#[track_caller]
fn assert_key_xdr(env: &Env, key: impl IntoVal<Env, Val>, expected: &str) {
    assert_eq!(xdr_hex(&key.to_xdr(env)), expected);
}

/// Returns `bytes` as lowercase hexadecimal.
fn xdr_hex(bytes: &Bytes) -> alloc::string::String {
    let len = usize::try_from(bytes.len()).expect("a key shorter than the address space");
    let mut raw = [0u8; 256];
    let raw = raw.get_mut(..len).expect("a key under 256 bytes");
    bytes.copy_into_slice(raw);
    hex::encode(raw)
}

#[test]
fn the_openzeppelin_storage_keys_encode_as_the_keeper_expects() {
    let env = test_env();
    let holder = Address::from_str(&env, PINNED_HOLDER);
    let operation = BytesN::from_array(&env, &[7u8; 32]);

    assert_key_xdr(
        &env,
        access::AccessControlStorageKey::ExistingRoles,
        EXISTING_ROLES_XDR,
    );
    assert_key_xdr(
        &env,
        access::AccessControlStorageKey::HasRole(holder, GUARDIAN),
        HAS_ROLE_XDR,
    );
    assert_key_xdr(
        &env,
        access::AccessControlStorageKey::RoleAccountsCount(GUARDIAN),
        ROLE_ACCOUNTS_COUNT_XDR,
    );
    assert_key_xdr(
        &env,
        timelock::TimelockStorageKey::OperationLedger(operation),
        OPERATION_LEDGER_XDR,
    );
}

/// `RoleAccounts` is the one key of the five whose type the access control
/// module keeps private, so this reads it out of the footprint a constructed
/// governor leaves behind rather than naming it. The key holds the role and the
/// index and not the holder, which is what lets it match a fixed encoding.
#[test]
fn the_role_enumeration_key_encodes_as_the_keeper_expects() {
    let env = test_env();
    let s = setup(&env);

    let found = env.as_contract(&s.governor, || {
        env.storage()
            .persistent()
            .all()
            .keys()
            .iter()
            .any(|key| xdr_hex(&key.to_xdr(&env)) == ROLE_ACCOUNTS_XDR)
    });
    assert!(found, "the guardian's enumeration slot is in the footprint");
}

// ------------------------------------------------------------------- schedule

#[test]
fn schedule_accepts_any_target_from_the_council() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();
    let client = GovernorClient::new(&env, &s.governor);

    let id = schedule_poke(&env, &s);

    assert_eq!(client.get_operation_state(&id), OperationStatus::Waiting);
}

#[test]
fn schedule_accepts_a_role_change_from_recovery() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();
    let client = GovernorClient::new(&env, &s.governor);

    let id = schedule_recovery(&env, &s, 1);

    assert_eq!(client.get_operation_state(&id), OperationStatus::Waiting);
}

#[test]
fn schedule_accepts_a_role_revocation_from_recovery() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();
    let client = GovernorClient::new(&env, &s.governor);

    let id = client.schedule(
        &s.governor,
        &Symbol::new(&env, "revoke_role"),
        &Vec::new(&env),
        &no_predecessor(&env),
        &salt(&env, 1),
        &s.recovery,
    );

    assert_eq!(client.get_operation_state(&id), OperationStatus::Waiting);
}

#[test]
fn schedule_rejects_recovery_on_a_mock_target() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();
    let client = GovernorClient::new(&env, &s.governor);

    assert!(matches!(
        client.try_schedule(
            &s.mock,
            &poke(&env),
            &poke_args(&env, 7),
            &no_predecessor(&env),
            &salt(&env, 1),
            &s.recovery,
        ),
        Err(Ok(Error::Unauthorized))
    ));
}

#[test]
fn schedule_rejects_recovery_on_a_non_role_function() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();
    let client = GovernorClient::new(&env, &s.governor);

    assert!(matches!(
        client.try_schedule(
            &s.governor,
            &Symbol::new(&env, "set_fn_role"),
            &Vec::new(&env),
            &no_predecessor(&env),
            &salt(&env, 1),
            &s.recovery,
        ),
        Err(Ok(Error::Unauthorized))
    ));
}

#[test]
fn schedule_gives_a_council_operation_the_delay() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();
    let client = GovernorClient::new(&env, &s.governor);
    let scheduled_at = env.ledger().sequence();

    schedule_poke(&env, &s);

    let entry = client.get_pending().get(0).expect("one pending operation");
    assert_eq!(entry.ready_ledger, scheduled_at.saturating_add(DELAY));
}

#[test]
fn schedule_gives_a_recovery_operation_the_recovery_delay() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();
    let client = GovernorClient::new(&env, &s.governor);
    let scheduled_at = env.ledger().sequence();

    schedule_recovery(&env, &s, 1);

    let entry = client.get_pending().get(0).expect("one pending operation");
    assert_eq!(
        entry.ready_ledger,
        scheduled_at.saturating_add(RECOVERY_DELAY)
    );
}

#[test]
fn schedule_rejects_a_caller_with_no_role() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();
    let client = GovernorClient::new(&env, &s.governor);
    let stranger = Address::generate(&env);

    assert!(matches!(
        client.try_schedule(
            &s.mock,
            &poke(&env),
            &poke_args(&env, 7),
            &no_predecessor(&env),
            &salt(&env, 1),
            &stranger,
        ),
        Err(Ok(Error::Unauthorized))
    ));
}

#[test]
fn schedule_rejects_a_duplicate_operation() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();
    let client = GovernorClient::new(&env, &s.governor);

    schedule_poke(&env, &s);

    assert!(matches!(
        client.try_schedule(
            &s.mock,
            &poke(&env),
            &poke_args(&env, 7),
            &no_predecessor(&env),
            &salt(&env, 1),
            &s.council,
        ),
        Err(Err(InvokeError::Contract(4000)))
    ));
}

#[test]
fn get_pending_lists_the_scheduled_operation() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();
    let client = GovernorClient::new(&env, &s.governor);
    let scheduled_at = env.ledger().sequence();

    let id = schedule_poke(&env, &s);

    let pending = client.get_pending();
    assert_eq!(pending.len(), 1);
    let entry = pending.get(0).expect("one pending operation");
    assert_eq!(entry.id, id);
    assert_eq!(entry.ready_ledger, scheduled_at.saturating_add(DELAY));
    assert_eq!(entry.operation.target, s.mock);
    assert_eq!(entry.operation.function, poke(&env));
    assert_eq!(entry.operation.args, poke_args(&env, 7));
}

#[test]
fn schedule_accepts_two_operations_with_different_salts() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();
    let client = GovernorClient::new(&env, &s.governor);

    let first = schedule_poke(&env, &s);
    let second = client.schedule(
        &s.mock,
        &poke(&env),
        &poke_args(&env, 7),
        &no_predecessor(&env),
        &salt(&env, 2),
        &s.council,
    );

    assert_ne!(first, second);
    assert_eq!(client.get_pending().len(), 2);
}

#[test]
fn schedule_rejects_a_delay_that_overflows_the_ledger() {
    let env = test_env();
    let mock = env.register(MockTarget, ());
    let council = Address::generate(&env);
    let recovery = Address::generate(&env);
    let guardian = Address::generate(&env);
    // The delay is fixed at construction, so a ready ledger beyond `u32::MAX`
    // needs a governor whose delay is near the maximum. The guardian pause
    // must still exceed it, which leaves two ledgers of headroom.
    let governor = register_governor(
        &env,
        u32::MAX - 2,
        u32::MAX - 1,
        GRACE,
        u32::MAX - 1,
        roles(&env, &council, &recovery, &guardian),
        Vec::new(&env),
    );
    env.mock_all_auths();
    // Any non-zero ledger overflows a delay this large, and this one is inside
    // the lifetime of the entries the call reads.
    env.ledger().set_sequence_number(1_000_000);

    assert!(matches!(
        GovernorClient::new(&env, &governor).try_schedule(
            &mock,
            &poke(&env),
            &poke_args(&env, 7),
            &no_predecessor(&env),
            &salt(&env, 1),
            &council,
        ),
        Err(Ok(Error::Overflow))
    ));
}

#[test]
fn schedule_prunes_an_operation_that_outlived_its_grace_window() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();
    let client = GovernorClient::new(&env, &s.governor);

    let expiring = schedule_poke(&env, &s);
    advance_to_ready(&env, &s, GRACE.saturating_add(1));
    let fresh = client.schedule(
        &s.mock,
        &poke(&env),
        &poke_args(&env, 7),
        &no_predecessor(&env),
        &salt(&env, 2),
        &s.council,
    );

    let pending = client.get_pending();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending.get(0).expect("one pending operation").id, fresh);
    assert_eq!(
        client.get_operation_state(&expiring),
        OperationStatus::Unset
    );
}

#[test]
fn schedule_rejects_an_operation_once_the_council_queue_is_full() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();
    let client = GovernorClient::new(&env, &s.governor);

    for byte in 0..MAX_PENDING_COUNCIL {
        client.schedule(
            &s.mock,
            &poke(&env),
            &poke_args(&env, 7),
            &no_predecessor(&env),
            &salt(&env, u8::try_from(byte).expect("a salt byte")),
            &s.council,
        );
    }

    assert!(matches!(
        client.try_schedule(
            &s.mock,
            &poke(&env),
            &poke_args(&env, 7),
            &no_predecessor(&env),
            &salt(&env, 200),
            &s.council,
        ),
        Err(Ok(Error::QueueFull))
    ));
}

#[test]
fn a_full_council_queue_still_leaves_room_for_recovery() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();
    let client = GovernorClient::new(&env, &s.governor);

    for byte in 0..MAX_PENDING_COUNCIL {
        client.schedule(
            &s.mock,
            &poke(&env),
            &poke_args(&env, 7),
            &no_predecessor(&env),
            &salt(&env, u8::try_from(byte).expect("a salt byte")),
            &s.council,
        );
    }
    for byte in MAX_PENDING_COUNCIL..MAX_PENDING {
        schedule_recovery(&env, &s, u8::try_from(byte).expect("a salt byte"));
    }

    assert_eq!(client.get_pending().len(), MAX_PENDING);
    assert!(matches!(
        client.try_schedule(
            &s.governor,
            &grant_role_fn(&env),
            &Vec::new(&env),
            &no_predecessor(&env),
            &salt(&env, 200),
            &s.recovery,
        ),
        Err(Ok(Error::QueueFull))
    ));
}

#[test]
fn schedule_extends_the_instance_and_operation_ttl() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();

    let id = schedule_poke(&env, &s);

    env.as_contract(&s.governor, || {
        let store = env.storage().persistent();
        assert_eq!(env.storage().instance().get_ttl(), EXTEND_TO);
        assert_eq!(store.get_ttl(&DataKey::Operation(id.clone())), EXTEND_TO);
        assert_eq!(
            store.get_ttl(&timelock::TimelockStorageKey::OperationLedger(id.clone())),
            EXTEND_TO
        );
    });
}

#[test]
#[cfg_attr(miri, ignore)]
#[should_panic(expected = "Error(Auth, InvalidAction)")]
fn schedule_requires_the_caller_signature() {
    let env = test_env();
    let s = setup(&env);

    schedule_poke(&env, &s);
}

#[test]
fn schedule_emits_operation_scheduled() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();

    let id = schedule_poke(&env, &s);

    let events = env.events().all();
    let expected = OperationScheduled {
        id,
        target: s.mock.clone(),
        function: poke(&env),
        args: poke_args(&env, 7),
        predecessor: no_predecessor(&env),
        salt: salt(&env, 1),
        delay: DELAY,
    }
    .to_xdr(&env, &s.governor);
    assert_eq!(
        *events.events().last().expect("a scheduled event"),
        expected
    );
}

// -------------------------------------------------------------------- execute

/// Advances the ledger to the ready ledger of the first queued operation, plus
/// `offset`.
fn advance_to_ready(env: &Env, s: &Setup, offset: u32) {
    let ready = GovernorClient::new(env, &s.governor)
        .get_pending()
        .get(0)
        .expect("one pending operation")
        .ready_ledger;
    env.ledger()
        .set_sequence_number(ready.saturating_add(offset));
}

fn try_execute_poke(
    env: &Env,
    s: &Setup,
) -> Result<Result<Val, soroban_sdk::ConversionError>, Result<Error, InvokeError>> {
    GovernorClient::new(env, &s.governor).try_execute(
        &s.mock,
        &poke(env),
        &poke_args(env, 7),
        &no_predecessor(env),
        &salt(env, 1),
    )
}

fn execute_poke(env: &Env, s: &Setup) -> Val {
    GovernorClient::new(env, &s.governor).execute(
        &s.mock,
        &poke(env),
        &poke_args(env, 7),
        &no_predecessor(env),
        &salt(env, 1),
    )
}

#[test]
fn execute_rejects_an_operation_that_is_not_ready() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();

    schedule_poke(&env, &s);
    advance_to_ready(&env, &s, 0);
    let now = env.ledger().sequence();
    env.ledger().set_sequence_number(now.saturating_sub(1));

    assert!(matches!(
        try_execute_poke(&env, &s),
        Err(Err(InvokeError::Contract(4002)))
    ));
}

#[test]
fn execute_invokes_the_target_at_the_ready_ledger() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();
    let client = GovernorClient::new(&env, &s.governor);

    let id = schedule_poke(&env, &s);
    advance_to_ready(&env, &s, 0);
    execute_poke(&env, &s);

    assert_eq!(MockTargetClient::new(&env, &s.mock).last_poke(), 7);
    assert_eq!(client.get_pending(), Vec::new(&env));
    assert_eq!(client.get_operation_state(&id), OperationStatus::Done);
}

#[test]
fn execute_rejects_a_replay() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();

    schedule_poke(&env, &s);
    advance_to_ready(&env, &s, 0);
    execute_poke(&env, &s);

    assert!(matches!(
        try_execute_poke(&env, &s),
        Err(Err(InvokeError::Contract(4002)))
    ));
}

#[test]
fn execute_accepts_the_last_ledger_of_the_grace_window() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();

    schedule_poke(&env, &s);
    advance_to_ready(&env, &s, GRACE);
    execute_poke(&env, &s);

    assert_eq!(MockTargetClient::new(&env, &s.mock).last_poke(), 7);
}

#[test]
fn execute_rejects_an_expired_operation() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();
    let client = GovernorClient::new(&env, &s.governor);

    let id = schedule_poke(&env, &s);
    advance_to_ready(&env, &s, GRACE.saturating_add(1));

    assert!(matches!(
        try_execute_poke(&env, &s),
        Err(Ok(Error::Expired))
    ));
    assert_eq!(client.get_pending().len(), 1);
    assert_eq!(client.get_operation_state(&id), OperationStatus::Expired);
}

#[test]
fn execute_rejects_an_unexecuted_predecessor() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();
    let client = GovernorClient::new(&env, &s.governor);

    let first = schedule_poke(&env, &s);
    client.schedule(
        &s.mock,
        &poke(&env),
        &poke_args(&env, 8),
        &first,
        &salt(&env, 2),
        &s.council,
    );
    advance_to_ready(&env, &s, 0);

    assert!(matches!(
        client.try_execute(
            &s.mock,
            &poke(&env),
            &poke_args(&env, 8),
            &first,
            &salt(&env, 2),
        ),
        Err(Err(InvokeError::Contract(4003)))
    ));
}

#[test]
fn execute_accepts_a_predecessor_that_is_done() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();
    let client = GovernorClient::new(&env, &s.governor);

    let first = schedule_poke(&env, &s);
    client.schedule(
        &s.mock,
        &poke(&env),
        &poke_args(&env, 8),
        &first,
        &salt(&env, 2),
        &s.council,
    );
    advance_to_ready(&env, &s, 0);

    execute_poke(&env, &s);
    client.execute(
        &s.mock,
        &poke(&env),
        &poke_args(&env, 8),
        &first,
        &salt(&env, 2),
    );

    assert_eq!(MockTargetClient::new(&env, &s.mock).last_poke(), 8);
    assert_eq!(client.get_pending(), Vec::new(&env));
}

#[test]
fn execute_rejects_a_self_operation_with_the_wrong_argument_count() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();
    let client = GovernorClient::new(&env, &s.governor);

    let id = schedule_recovery(&env, &s, 1);
    advance_to_ready(&env, &s, 0);

    assert!(matches!(
        client.try_execute(
            &s.governor,
            &grant_role_fn(&env),
            &Vec::new(&env),
            &no_predecessor(&env),
            &salt(&env, 1),
        ),
        Err(Ok(Error::InvalidArgs))
    ));
    assert_eq!(client.get_pending().len(), 1);
    assert_eq!(client.get_operation_state(&id), OperationStatus::Ready);
}

#[test]
fn execute_leaves_a_failing_target_ready() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();
    let client = GovernorClient::new(&env, &s.governor);

    let id = client.schedule(
        &s.mock,
        &Symbol::new(&env, "fail"),
        &Vec::new(&env),
        &no_predecessor(&env),
        &salt(&env, 1),
        &s.council,
    );
    advance_to_ready(&env, &s, 0);

    assert!(
        client
            .try_execute(
                &s.mock,
                &Symbol::new(&env, "fail"),
                &Vec::new(&env),
                &no_predecessor(&env),
                &salt(&env, 1),
            )
            .is_err()
    );
    assert_eq!(client.get_operation_state(&id), OperationStatus::Ready);
    assert_eq!(client.get_pending().len(), 1);
}

#[test]
fn execute_needs_no_signature() {
    let env = test_env();
    let s = setup(&env);

    env.mock_all_auths();
    schedule_poke(&env, &s);
    advance_to_ready(&env, &s, 0);
    env.set_auths(&[]);

    execute_poke(&env, &s);

    assert_eq!(MockTargetClient::new(&env, &s.mock).last_poke(), 7);
}

#[test]
fn execute_emits_operation_executed() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();

    let id = schedule_poke(&env, &s);
    advance_to_ready(&env, &s, 0);
    execute_poke(&env, &s);

    let events = env.events().all();
    let expected = OperationExecuted {
        id,
        target: s.mock.clone(),
        function: poke(&env),
        args: poke_args(&env, 7),
        predecessor: no_predecessor(&env),
        salt: salt(&env, 1),
    }
    .to_xdr(&env, &s.governor);
    assert!(events.events().contains(&expected));
}

// --------------------------------------------------------------------- cancel

fn cancel_poke(env: &Env, s: &Setup, caller: &Address) {
    GovernorClient::new(env, &s.governor).cancel(
        &s.mock,
        &poke(env),
        &poke_args(env, 7),
        &no_predecessor(env),
        &salt(env, 1),
        caller,
    );
}

fn try_cancel_poke(
    env: &Env,
    s: &Setup,
    caller: &Address,
) -> Result<Result<(), soroban_sdk::ConversionError>, Result<soroban_sdk::Error, InvokeError>> {
    GovernorClient::new(env, &s.governor).try_cancel(
        &s.mock,
        &poke(env),
        &poke_args(env, 7),
        &no_predecessor(env),
        &salt(env, 1),
        caller,
    )
}

#[test]
fn cancel_removes_a_waiting_operation() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();
    let client = GovernorClient::new(&env, &s.governor);

    let id = schedule_poke(&env, &s);
    cancel_poke(&env, &s, &s.council);

    assert_eq!(client.get_pending(), Vec::new(&env));
    assert_eq!(client.get_operation_state(&id), OperationStatus::Unset);
}

#[test]
fn cancel_removes_a_ready_operation() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();
    let client = GovernorClient::new(&env, &s.governor);

    schedule_poke(&env, &s);
    advance_to_ready(&env, &s, 0);
    cancel_poke(&env, &s, &s.council);

    assert_eq!(client.get_pending(), Vec::new(&env));
}

#[test]
fn cancel_removes_an_expired_operation() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();
    let client = GovernorClient::new(&env, &s.governor);

    schedule_poke(&env, &s);
    advance_to_ready(&env, &s, GRACE.saturating_add(1));
    cancel_poke(&env, &s, &s.council);

    assert_eq!(client.get_pending(), Vec::new(&env));
}

#[test]
fn cancel_rejects_non_council_callers_on_a_mock_operation() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();
    let client = GovernorClient::new(&env, &s.governor);

    schedule_poke(&env, &s);

    assert!(matches!(
        try_cancel_poke(&env, &s, &s.recovery),
        Err(Ok(e)) if e == host_error(2000)
    ));
    assert!(matches!(
        try_cancel_poke(&env, &s, &s.guardian),
        Err(Ok(e)) if e == host_error(2000)
    ));
    assert_eq!(client.get_pending().len(), 1);
}

#[test]
fn cancel_rejects_non_council_callers_on_a_governor_operation() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();
    let client = GovernorClient::new(&env, &s.governor);

    schedule_recovery(&env, &s, 1);

    for caller in [&s.recovery, &s.guardian] {
        assert!(matches!(
            client.try_cancel(
                &s.governor,
                &grant_role_fn(&env),
                &Vec::new(&env),
                &no_predecessor(&env),
                &salt(&env, 1),
                caller,
            ),
            Err(Ok(e)) if e == host_error(2000)
        ));
    }
    assert_eq!(client.get_pending().len(), 1);
}

#[test]
fn cancel_rejects_a_done_operation() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();

    schedule_poke(&env, &s);
    advance_to_ready(&env, &s, 0);
    execute_poke(&env, &s);

    assert!(matches!(
        try_cancel_poke(&env, &s, &s.council),
        Err(Ok(e)) if e == host_error(4002)
    ));
}

#[test]
fn cancel_rejects_an_unset_operation() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();

    assert!(matches!(
        try_cancel_poke(&env, &s, &s.council),
        Err(Ok(e)) if e == host_error(4002)
    ));
}

#[test]
fn cancel_rejects_the_wrong_salt() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();
    let client = GovernorClient::new(&env, &s.governor);

    schedule_poke(&env, &s);

    assert!(matches!(
        client.try_cancel(
            &s.mock,
            &poke(&env),
            &poke_args(&env, 7),
            &no_predecessor(&env),
            &salt(&env, 9),
            &s.council,
        ),
        Err(Ok(e)) if e == host_error(4002)
    ));
    assert_eq!(client.get_pending().len(), 1);
}

#[test]
fn cancel_leaves_the_other_pending_operation() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();
    let client = GovernorClient::new(&env, &s.governor);

    schedule_poke(&env, &s);
    let second = client.schedule(
        &s.mock,
        &poke(&env),
        &poke_args(&env, 7),
        &no_predecessor(&env),
        &salt(&env, 2),
        &s.council,
    );

    cancel_poke(&env, &s, &s.council);

    let pending = client.get_pending();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending.get(0).expect("one pending operation").id, second);
}

#[test]
#[cfg_attr(miri, ignore)]
#[should_panic(expected = "Error(Auth, InvalidAction)")]
fn cancel_requires_the_council_signature() {
    let env = test_env();
    let s = setup(&env);

    env.mock_all_auths();
    schedule_poke(&env, &s);
    env.set_auths(&[]);

    cancel_poke(&env, &s, &s.council);
}

#[test]
fn cancel_emits_operation_cancelled() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();

    let id = schedule_poke(&env, &s);
    cancel_poke(&env, &s, &s.council);

    let events = env.events().all();
    let expected = OperationCancelled { id }.to_xdr(&env, &s.governor);
    assert_eq!(
        *events.events().last().expect("a cancelled event"),
        expected
    );
}

// ----------------------------------------------------------- permission table

struct TableSetup {
    asp: Address,
    governor: Address,
    council: Address,
    recovery: Address,
    guardian: Address,
    operator: Address,
}

fn insert_leaf(env: &Env) -> Symbol {
    Symbol::new(env, "insert_leaf")
}

fn leaf_args(env: &Env, value: u32) -> Vec<Val> {
    vec![env, U256::from_u32(env, value).into_val(env)]
}

/// Registers an ASP with a Merkle tree `levels` deep and a governor whose
/// table lets the operator insert leaves, then hands the ASP over to the
/// governor the way a deployment does.
fn table_setup(env: &Env, levels: u32) -> TableSetup {
    let deployer = Address::generate(env);
    let asp = env.register(ASPMembership, (deployer, levels));
    let council = Address::generate(env);
    let recovery = Address::generate(env);
    let guardian = Address::generate(env);
    let operator = Address::generate(env);
    let mut grants = roles(env, &council, &recovery, &guardian);
    grants.push_back(RoleGrant {
        role: OPERATOR,
        member: operator.clone(),
    });
    let governor = register_governor(
        env,
        DELAY,
        RECOVERY_DELAY,
        GRACE,
        GUARDIAN_PAUSE,
        grants,
        vec![
            env,
            FnRule {
                target: asp.clone(),
                function: insert_leaf(env),
                role: OPERATOR,
            },
        ],
    );
    env.mock_all_auths();
    ASPMembershipClient::new(env, &asp).update_admin(&governor);
    TableSetup {
        asp,
        governor,
        council,
        recovery,
        guardian,
        operator,
    }
}

#[test]
fn execute_now_lets_the_operator_call_a_mapped_function() {
    let env = test_env();
    let t = table_setup(&env, 3);
    let asp = ASPMembershipClient::new(&env, &t.asp);
    let root_before = asp.get_root();

    let args = leaf_args(&env, 7);
    // Only the operator's own call is authorized, and nothing beneath it, so
    // the ASP's admin check passes on the governor being its direct invoker.
    env.mock_auths(&[MockAuth {
        address: &t.operator,
        invoke: &MockAuthInvoke {
            contract: &t.governor,
            fn_name: "execute_now",
            args: (
                t.asp.clone(),
                insert_leaf(&env),
                args.clone(),
                t.operator.clone(),
            )
                .into_val(&env),
            sub_invokes: &[],
        },
    }]);
    GovernorClient::new(&env, &t.governor).execute_now(
        &t.asp,
        &insert_leaf(&env),
        &args,
        &t.operator,
    );

    // The ASP's event struct is private to its crate, so the topic is the
    // strongest shape this crate can name.
    let asp_events = env.events().all().filter_by_contract(&t.asp);
    assert_eq!(asp_events.events().len(), 1);
    let xdr::ContractEventBody::V0(body) = &asp_events.events()[0].body;
    assert_eq!(
        body.topics.first().expect("a topic"),
        &xdr::ScVal::Symbol(xdr::ScSymbol(
            "LeafAdded".try_into().expect("a topic symbol")
        ))
    );
    assert_ne!(asp.get_root(), root_before);
}

#[test]
fn schedule_rejects_the_guardian_and_the_operator() {
    let env = test_env();
    let t = table_setup(&env, 3);
    let client = GovernorClient::new(&env, &t.governor);

    for caller in [&t.guardian, &t.operator] {
        assert!(matches!(
            client.try_schedule(
                &t.asp,
                &insert_leaf(&env),
                &leaf_args(&env, 7),
                &no_predecessor(&env),
                &salt(&env, 1),
                caller,
            ),
            Err(Ok(Error::Unauthorized))
        ));
    }
    assert!(client.get_pending().is_empty());
}

#[test]
fn the_constructor_records_the_permission_table() {
    let env = test_env();
    let t = table_setup(&env, 3);
    let client = GovernorClient::new(&env, &t.governor);

    assert_eq!(
        client.get_fn_role(&t.asp, &insert_leaf(&env)),
        Some(OPERATOR)
    );
    assert_eq!(
        client.get_fn_role(&t.asp, &Symbol::new(&env, "update_admin")),
        None
    );

    env.as_contract(&t.governor, || {
        assert_eq!(
            env.storage()
                .persistent()
                .get_ttl(&DataKey::FnRole(t.asp.clone(), insert_leaf(&env))),
            EXTEND_TO
        );
    });
}

#[test]
fn execute_now_rejects_the_operator_on_an_unmapped_function() {
    let env = test_env();
    let t = table_setup(&env, 3);
    let client = GovernorClient::new(&env, &t.governor);
    let stranger = Address::generate(&env);

    assert!(matches!(
        client.try_execute_now(
            &t.asp,
            &Symbol::new(&env, "update_admin"),
            &vec![&env, stranger.into_val(&env)],
            &t.operator,
        ),
        Err(Ok(Error::Unauthorized))
    ));
}

#[test]
fn execute_now_rejects_an_unmapped_target() {
    let env = test_env();
    let t = table_setup(&env, 3);
    let mock = env.register(MockTarget, ());
    let client = GovernorClient::new(&env, &t.governor);

    assert!(matches!(
        client.try_execute_now(&mock, &poke(&env), &poke_args(&env, 7), &t.operator),
        Err(Ok(Error::Unauthorized))
    ));
}

// A panic raised inside a nested invocation is formatted with the failing
// frame's events, and the association set provider's leaves are `U256`
// values, so these two reach the same `ethnum` formatting path the
// `should_panic` tests above avoid.
#[test]
#[cfg_attr(miri, ignore)]
fn execute_now_rejects_every_role_but_the_one_the_row_names() {
    let env = test_env();
    let t = table_setup(&env, 3);
    let client = GovernorClient::new(&env, &t.governor);

    for caller in [&t.council, &t.guardian, &t.recovery] {
        assert!(matches!(
            client.try_execute_now(&t.asp, &insert_leaf(&env), &leaf_args(&env, 7), caller),
            Err(Err(InvokeError::Contract(2000)))
        ));
    }
}

#[test]
fn execute_now_rejects_the_governor_as_target() {
    let env = test_env();
    let t = table_setup(&env, 3);
    let client = GovernorClient::new(&env, &t.governor);

    assert!(matches!(
        client.try_execute_now(
            &t.governor,
            &grant_role_fn(&env),
            &Vec::new(&env),
            &t.operator,
        ),
        Err(Ok(Error::Unauthorized))
    ));
}

#[test]
#[cfg_attr(miri, ignore)]
fn execute_now_forwards_a_failure_from_the_target() {
    let env = test_env();
    // A one-level tree holds two leaves, so the third insertion is refused.
    let t = table_setup(&env, 1);
    let client = GovernorClient::new(&env, &t.governor);
    let asp = ASPMembershipClient::new(&env, &t.asp);

    for value in 1..=2u32 {
        client.execute_now(
            &t.asp,
            &insert_leaf(&env),
            &leaf_args(&env, value),
            &t.operator,
        );
    }
    let root_before = asp.get_root();

    assert!(matches!(
        client.try_execute_now(&t.asp, &insert_leaf(&env), &leaf_args(&env, 3), &t.operator),
        Err(Err(InvokeError::Contract(2)))
    ));
    assert_eq!(asp.get_root(), root_before);
}

#[test]
#[cfg_attr(miri, ignore)]
#[should_panic(expected = "Error(Contract, #3001)")]
fn constructor_rejects_a_table_entry_with_an_unknown_role() {
    let env = test_env();
    let mock = env.register(MockTarget, ());
    let council = Address::generate(&env);
    let recovery = Address::generate(&env);
    let guardian = Address::generate(&env);

    register_governor(
        &env,
        DELAY,
        RECOVERY_DELAY,
        GRACE,
        GUARDIAN_PAUSE,
        roles(&env, &council, &recovery, &guardian),
        vec![
            &env,
            FnRule {
                target: mock,
                function: poke(&env),
                role: Symbol::new(&env, "auditor"),
            },
        ],
    );
}

#[test]
#[cfg_attr(miri, ignore)]
#[should_panic(expected = "Error(Auth, InvalidAction)")]
fn execute_now_requires_the_caller_signature() {
    let env = test_env();
    let t = table_setup(&env, 3);
    env.set_auths(&[]);

    GovernorClient::new(&env, &t.governor).execute_now(
        &t.asp,
        &insert_leaf(&env),
        &leaf_args(&env, 7),
        &t.operator,
    );
}

// ---------------------------------------------------------------------- pause

fn pause_state(env: &Env, t: &TableSetup) -> PauseState {
    ASPMembershipClient::new(env, &t.asp).get_pause_state()
}

#[test]
fn pause_sets_the_guardian_deadline_on_the_target() {
    let env = test_env();
    let t = table_setup(&env, 3);
    let now = env.ledger().sequence();

    GovernorClient::new(&env, &t.governor).pause(&t.asp, &MUTATIONS, &t.guardian);

    assert_eq!(
        pause_state(&env, &t),
        PauseState {
            flags: MUTATIONS,
            until: Some(now.saturating_add(GUARDIAN_PAUSE)),
        }
    );
}

#[test]
fn pause_rejects_every_role_but_the_guardian() {
    let env = test_env();
    let t = table_setup(&env, 3);
    let client = GovernorClient::new(&env, &t.governor);

    for caller in [&t.council, &t.recovery, &t.operator] {
        assert!(matches!(
            client.try_pause(&t.asp, &MUTATIONS, caller),
            Err(Err(InvokeError::Contract(2000)))
        ));
    }
    assert_eq!(pause_state(&env, &t), PauseState::default());
}

#[test]
fn a_second_guardian_pause_keeps_the_deadline() {
    let env = test_env();
    let t = table_setup(&env, 3);
    let client = GovernorClient::new(&env, &t.governor);
    let now = env.ledger().sequence();

    client.pause(&t.asp, &MUTATIONS, &t.guardian);
    env.ledger().set_sequence_number(now.saturating_add(5));
    client.pause(&t.asp, &MUTATIONS, &t.guardian);

    assert_eq!(
        pause_state(&env, &t).until,
        Some(now.saturating_add(GUARDIAN_PAUSE))
    );
}

// The next two refusals are the association set provider's own errors, raised
// inside the nested invocation, so they reach the `ethnum` formatting path
// described above.
#[test]
#[cfg_attr(miri, ignore)]
fn pause_is_refused_after_the_council_cleared_the_window() {
    let env = test_env();
    let t = table_setup(&env, 3);
    let client = GovernorClient::new(&env, &t.governor);

    client.pause(&t.asp, &MUTATIONS, &t.guardian);
    client.unpause(&t.asp, &MUTATIONS, &t.council);
    let cleared = pause_state(&env, &t);

    assert!(matches!(
        client.try_pause(&t.asp, &MUTATIONS, &t.guardian),
        Err(Err(InvokeError::Contract(8)))
    ));
    assert_eq!(pause_state(&env, &t), cleared);
}

#[test]
#[cfg_attr(miri, ignore)]
fn pause_forwards_the_targets_rejection_of_the_flags() {
    let env = test_env();
    let t = table_setup(&env, 3);

    assert!(matches!(
        GovernorClient::new(&env, &t.governor).try_pause(&t.asp, &2, &t.guardian),
        Err(Err(InvokeError::Contract(7)))
    ));
    assert_eq!(pause_state(&env, &t), PauseState::default());
}

#[test]
fn pause_is_accepted_at_the_deadline_and_records_a_new_one() {
    let env = test_env();
    let t = table_setup(&env, 3);
    let client = GovernorClient::new(&env, &t.governor);
    let until = env.ledger().sequence().saturating_add(GUARDIAN_PAUSE);

    client.pause(&t.asp, &MUTATIONS, &t.guardian);
    client.unpause(&t.asp, &MUTATIONS, &t.council);
    env.ledger().set_sequence_number(until);
    client.pause(&t.asp, &MUTATIONS, &t.guardian);

    assert_eq!(
        pause_state(&env, &t),
        PauseState {
            flags: MUTATIONS,
            until: Some(until.saturating_add(GUARDIAN_PAUSE)),
        }
    );
}

#[test]
fn the_council_pauses_without_a_deadline_through_the_queue() {
    let env = test_env();
    let t = table_setup(&env, 3);
    let client = GovernorClient::new(&env, &t.governor);
    let pause_fn = Symbol::new(&env, "pause");
    let args = vec![&env, MUTATIONS.into_val(&env), None::<u32>.into_val(&env)];

    client.schedule(
        &t.asp,
        &pause_fn,
        &args,
        &no_predecessor(&env),
        &salt(&env, 1),
        &t.council,
    );
    let ready = client
        .get_pending()
        .get(0)
        .expect("one pending operation")
        .ready_ledger;
    env.ledger().set_sequence_number(ready);
    client.execute(
        &t.asp,
        &pause_fn,
        &args,
        &no_predecessor(&env),
        &salt(&env, 1),
    );
    assert_eq!(
        pause_state(&env, &t),
        PauseState {
            flags: MUTATIONS,
            until: None,
        }
    );

    client.pause(&t.asp, &MUTATIONS, &t.guardian);
    assert_eq!(pause_state(&env, &t).until, None);

    client.unpause(&t.asp, &MUTATIONS, &t.council);
    assert_eq!(pause_state(&env, &t).flags, 0);
}

#[test]
fn unpause_rejects_every_role_but_the_council() {
    let env = test_env();
    let t = table_setup(&env, 3);
    let client = GovernorClient::new(&env, &t.governor);

    client.pause(&t.asp, &MUTATIONS, &t.guardian);
    for caller in [&t.guardian, &t.recovery, &t.operator] {
        assert!(matches!(
            client.try_unpause(&t.asp, &MUTATIONS, caller),
            Err(Ok(e)) if e == host_error(2000)
        ));
    }
    assert_eq!(pause_state(&env, &t).flags, MUTATIONS);

    client.unpause(&t.asp, &MUTATIONS, &t.council);
    assert_eq!(pause_state(&env, &t).flags, 0);
}

#[test]
fn pause_rejects_a_deadline_that_overflows_the_ledger() {
    let env = test_env();
    let mock = env.register(MockTarget, ());
    let council = Address::generate(&env);
    let recovery = Address::generate(&env);
    let guardian = Address::generate(&env);
    // The guardian pause is fixed at construction, so a deadline beyond
    // `u32::MAX` needs a governor whose window is near the maximum, on a ledger
    // inside the lifetime of the entries the call reads.
    let governor = register_governor(
        &env,
        DELAY,
        RECOVERY_DELAY,
        GRACE,
        u32::MAX,
        roles(&env, &council, &recovery, &guardian),
        Vec::new(&env),
    );
    env.mock_all_auths();
    env.ledger().set_sequence_number(1_000_000);

    assert!(matches!(
        GovernorClient::new(&env, &governor).try_pause(&mock, &MUTATIONS, &guardian),
        Err(Ok(Error::Overflow))
    ));
}

#[test]
#[cfg_attr(miri, ignore)]
#[should_panic(expected = "Error(Auth, InvalidAction)")]
fn pause_requires_the_guardian_signature() {
    let env = test_env();
    let t = table_setup(&env, 3);
    env.set_auths(&[]);

    GovernorClient::new(&env, &t.governor).pause(&t.asp, &MUTATIONS, &t.guardian);
}

#[test]
#[cfg_attr(miri, ignore)]
#[should_panic(expected = "Error(Auth, InvalidAction)")]
fn unpause_requires_the_council_signature() {
    let env = test_env();
    let t = table_setup(&env, 3);
    env.set_auths(&[]);

    GovernorClient::new(&env, &t.governor).unpause(&t.asp, &MUTATIONS, &t.council);
}

// ------------------------------------------------------------ self-operations

fn role_args(env: &Env, member: &Address, role: &Symbol) -> Vec<Val> {
    vec![env, member.into_val(env), role.into_val(env)]
}

fn fn_role_args(env: &Env, target: &Address, function: &Symbol, role: &Symbol) -> Vec<Val> {
    vec![
        env,
        target.into_val(env),
        function.into_val(env),
        role.into_val(env),
    ]
}

/// Schedules `function(args)` against the governor from `caller`, advances the
/// ledger to the operation's ready ledger, and executes it.
fn try_execute_self(
    env: &Env,
    governor: &Address,
    function: &str,
    args: &Vec<Val>,
    byte: u8,
    caller: &Address,
) -> Result<Result<Val, soroban_sdk::ConversionError>, Result<Error, InvokeError>> {
    let client = GovernorClient::new(env, governor);
    let function = Symbol::new(env, function);
    let id = client.schedule(
        governor,
        &function,
        args,
        &no_predecessor(env),
        &salt(env, byte),
        caller,
    );
    let ready = client
        .get_pending()
        .iter()
        .find(|entry| entry.id == id)
        .expect("the scheduled operation")
        .ready_ledger;
    env.ledger().set_sequence_number(ready);
    client.try_execute(
        governor,
        &function,
        args,
        &no_predecessor(env),
        &salt(env, byte),
    )
}

fn execute_self(
    env: &Env,
    governor: &Address,
    function: &str,
    args: &Vec<Val>,
    byte: u8,
    caller: &Address,
) {
    try_execute_self(env, governor, function, args, byte, caller)
        .expect("the operation executes")
        .expect("a void result");
}

fn try_cancel_self(
    env: &Env,
    governor: &Address,
    function: &str,
    args: &Vec<Val>,
    byte: u8,
    caller: &Address,
) -> Result<Result<(), soroban_sdk::ConversionError>, Result<soroban_sdk::Error, InvokeError>> {
    GovernorClient::new(env, governor).try_cancel(
        governor,
        &Symbol::new(env, function),
        args,
        &no_predecessor(env),
        &salt(env, byte),
        caller,
    )
}

#[test]
fn grant_role_through_the_queue_adds_the_holder() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();
    let client = GovernorClient::new(&env, &s.governor);
    let second = Address::generate(&env);

    execute_self(
        &env,
        &s.governor,
        "grant_role",
        &role_args(&env, &second, &GUARDIAN),
        1,
        &s.council,
    );

    assert!(client.has_role(&second, &GUARDIAN));
    assert_eq!(client.get_role_member_count(&GUARDIAN), 2);
    assert_eq!(client.get_role_member(&GUARDIAN, &1), second);
}

#[test]
fn revoke_role_through_the_queue_removes_the_only_guardian() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();
    let client = GovernorClient::new(&env, &s.governor);

    execute_self(
        &env,
        &s.governor,
        "revoke_role",
        &role_args(&env, &s.guardian, &GUARDIAN),
        1,
        &s.council,
    );

    assert!(!client.has_role(&s.guardian, &GUARDIAN));
    assert_eq!(client.get_role_member_count(&GUARDIAN), 0);
    assert!(matches!(
        client.try_pause(&s.mock, &MUTATIONS, &s.guardian),
        Err(Err(InvokeError::Contract(2000)))
    ));
}

#[test]
fn set_fn_role_through_the_queue_opens_the_fast_path() {
    let env = test_env();
    let t = table_setup(&env, 3);
    let mock = env.register(MockTarget, ());
    let client = GovernorClient::new(&env, &t.governor);

    execute_self(
        &env,
        &t.governor,
        "set_fn_role",
        &fn_role_args(&env, &mock, &poke(&env), &OPERATOR),
        1,
        &t.council,
    );

    assert_eq!(client.get_fn_role(&mock, &poke(&env)), Some(OPERATOR));
    client.execute_now(&mock, &poke(&env), &poke_args(&env, 7), &t.operator);
    assert_eq!(MockTargetClient::new(&env, &mock).last_poke(), 7);
}

#[test]
fn clear_fn_role_through_the_queue_closes_the_fast_path() {
    let env = test_env();
    let t = table_setup(&env, 3);
    let client = GovernorClient::new(&env, &t.governor);

    execute_self(
        &env,
        &t.governor,
        "clear_fn_role",
        &vec![&env, t.asp.into_val(&env), insert_leaf(&env).into_val(&env)],
        1,
        &t.council,
    );

    assert_eq!(client.get_fn_role(&t.asp, &insert_leaf(&env)), None);
    assert!(matches!(
        client.try_execute_now(&t.asp, &insert_leaf(&env), &leaf_args(&env, 7), &t.operator),
        Err(Ok(Error::Unauthorized))
    ));
}

#[test]
fn grant_role_with_an_unknown_role_stays_ready_until_cancelled() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();
    let client = GovernorClient::new(&env, &s.governor);
    let args = role_args(
        &env,
        &Address::generate(&env),
        &Symbol::new(&env, "auditor"),
    );

    assert!(matches!(
        try_execute_self(&env, &s.governor, "grant_role", &args, 1, &s.council),
        Err(Ok(Error::UnknownRole))
    ));
    let id = client
        .get_pending()
        .get(0)
        .expect("one pending operation")
        .id;
    assert_eq!(client.get_operation_state(&id), OperationStatus::Ready);

    try_cancel_self(&env, &s.governor, "grant_role", &args, 1, &s.council)
        .expect("the council cancels")
        .expect("a void result");
    assert_eq!(client.get_pending(), Vec::new(&env));
}

#[test]
fn grant_role_for_a_holder_changes_nothing() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();
    let client = GovernorClient::new(&env, &s.governor);

    execute_self(
        &env,
        &s.governor,
        "grant_role",
        &role_args(&env, &s.guardian, &GUARDIAN),
        1,
        &s.council,
    );

    assert_eq!(client.get_role_member_count(&GUARDIAN), 1);
    assert_eq!(client.get_role_member(&GUARDIAN, &0), s.guardian);
}

#[test]
fn grant_role_refuses_a_second_role_for_one_address() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();
    let client = GovernorClient::new(&env, &s.governor);
    let args = role_args(&env, &s.council, &GUARDIAN);

    assert!(matches!(
        try_execute_self(&env, &s.governor, "grant_role", &args, 1, &s.council),
        Err(Ok(Error::RoleInvariant))
    ));
    let id = client
        .get_pending()
        .get(0)
        .expect("one pending operation")
        .id;
    assert_eq!(client.get_operation_state(&id), OperationStatus::Ready);

    try_cancel_self(&env, &s.governor, "grant_role", &args, 1, &s.council)
        .expect("the council cancels")
        .expect("a void result");
    assert!(!client.has_role(&s.council, &GUARDIAN));
    assert_eq!(client.get_pending(), Vec::new(&env));
}

#[test]
fn revoke_role_for_a_non_holder_panics() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();

    assert!(matches!(
        try_execute_self(
            &env,
            &s.governor,
            "revoke_role",
            &role_args(&env, &Address::generate(&env), &OPERATOR),
            1,
            &s.council,
        ),
        Err(Err(InvokeError::Contract(2007)))
    ));
}

#[test]
fn revoke_role_keeps_the_last_council_holder_while_recovery_is_empty() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();
    let client = GovernorClient::new(&env, &s.governor);
    let revoke_council = role_args(&env, &s.council, &COUNCIL);

    execute_self(
        &env,
        &s.governor,
        "revoke_role",
        &role_args(&env, &s.recovery, &RECOVERY),
        1,
        &s.council,
    );
    assert!(matches!(
        try_execute_self(
            &env,
            &s.governor,
            "revoke_role",
            &revoke_council,
            2,
            &s.council
        ),
        Err(Ok(Error::RoleInvariant))
    ));
    assert!(client.has_role(&s.council, &COUNCIL));

    execute_self(
        &env,
        &s.governor,
        "grant_role",
        &role_args(&env, &Address::generate(&env), &RECOVERY),
        3,
        &s.council,
    );
    execute_self(
        &env,
        &s.governor,
        "revoke_role",
        &revoke_council,
        4,
        &s.council,
    );

    assert_eq!(client.get_role_member_count(&COUNCIL), 0);
}

#[test]
fn revoke_role_removes_one_of_two_council_holders_while_recovery_is_empty() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();
    let client = GovernorClient::new(&env, &s.governor);
    let second = Address::generate(&env);

    execute_self(
        &env,
        &s.governor,
        "grant_role",
        &role_args(&env, &second, &COUNCIL),
        1,
        &s.council,
    );
    execute_self(
        &env,
        &s.governor,
        "revoke_role",
        &role_args(&env, &s.recovery, &RECOVERY),
        2,
        &s.council,
    );
    execute_self(
        &env,
        &s.governor,
        "revoke_role",
        &role_args(&env, &s.council, &COUNCIL),
        3,
        &s.council,
    );

    assert_eq!(client.get_role_member_count(&COUNCIL), 1);
    assert!(client.has_role(&second, &COUNCIL));
}

#[test]
fn revoke_role_extends_the_ttl_of_the_holder_count() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();
    let second = Address::generate(&env);
    let count = access::AccessControlStorageKey::RoleAccountsCount(GUARDIAN);

    execute_self(
        &env,
        &s.governor,
        "grant_role",
        &role_args(&env, &second, &GUARDIAN),
        1,
        &s.council,
    );
    // Age the count entry past the point where an extension takes effect. The
    // role's other entries stay alive, so the revoke can still read them. The
    // guardian role is the one whose revoke reaches no getter that would
    // extend the count on its own.
    let aged = env
        .ledger()
        .sequence()
        .saturating_add(EXTEND_TO.saturating_sub(THRESHOLD).saturating_add(1));
    env.ledger().set_sequence_number(aged);
    env.as_contract(&s.governor, || {
        assert!(env.storage().persistent().get_ttl(&count) < THRESHOLD);
    });

    execute_self(
        &env,
        &s.governor,
        "revoke_role",
        &role_args(&env, &second, &GUARDIAN),
        2,
        &s.council,
    );

    env.as_contract(&s.governor, || {
        assert_eq!(env.storage().persistent().get_ttl(&count), EXTEND_TO);
    });
}

#[test]
fn revoke_role_keeps_the_last_recovery_holder_while_the_council_is_empty() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();
    let client = GovernorClient::new(&env, &s.governor);
    let revoke_recovery = role_args(&env, &s.recovery, &RECOVERY);
    let council = Address::generate(&env);

    execute_self(
        &env,
        &s.governor,
        "revoke_role",
        &role_args(&env, &s.council, &COUNCIL),
        1,
        &s.council,
    );
    assert!(matches!(
        try_execute_self(
            &env,
            &s.governor,
            "revoke_role",
            &revoke_recovery,
            2,
            &s.recovery
        ),
        Err(Ok(Error::RoleInvariant))
    ));
    assert!(client.has_role(&s.recovery, &RECOVERY));

    execute_self(
        &env,
        &s.governor,
        "grant_role",
        &role_args(&env, &council, &COUNCIL),
        3,
        &s.recovery,
    );
    execute_self(
        &env,
        &s.governor,
        "revoke_role",
        &revoke_recovery,
        4,
        &council,
    );

    assert_eq!(client.get_role_member_count(&RECOVERY), 0);
}

// The old operator's refusal is raised inside a call whose arguments hold a
// `U256` leaf, which reaches the `ethnum` formatting path described above.
#[test]
#[cfg_attr(miri, ignore)]
fn the_council_replaces_the_operator_through_the_queue() {
    let env = test_env();
    let t = table_setup(&env, 3);
    let client = GovernorClient::new(&env, &t.governor);
    let asp = ASPMembershipClient::new(&env, &t.asp);
    let operator = Address::generate(&env);

    execute_self(
        &env,
        &t.governor,
        "revoke_role",
        &role_args(&env, &t.operator, &OPERATOR),
        1,
        &t.council,
    );
    execute_self(
        &env,
        &t.governor,
        "grant_role",
        &role_args(&env, &operator, &OPERATOR),
        2,
        &t.council,
    );

    assert!(matches!(
        client.try_execute_now(&t.asp, &insert_leaf(&env), &leaf_args(&env, 7), &t.operator),
        Err(Err(InvokeError::Contract(2000)))
    ));
    let root_before = asp.get_root();
    client.execute_now(&t.asp, &insert_leaf(&env), &leaf_args(&env, 7), &operator);
    assert_ne!(asp.get_root(), root_before);
}

#[test]
fn recovery_replaces_a_lost_council() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();
    let client = GovernorClient::new(&env, &s.governor);
    let council = Address::generate(&env);
    let grant = role_args(&env, &council, &COUNCIL);
    let scheduled_at = env.ledger().sequence();

    let id = client.schedule(
        &s.governor,
        &grant_role_fn(&env),
        &grant,
        &no_predecessor(&env),
        &salt(&env, 1),
        &s.recovery,
    );
    let ready = client
        .get_pending()
        .get(0)
        .expect("one pending operation")
        .ready_ledger;
    assert_eq!(ready, scheduled_at.saturating_add(RECOVERY_DELAY));
    env.ledger().set_sequence_number(ready);
    env.set_auths(&[]);
    client.execute(
        &s.governor,
        &grant_role_fn(&env),
        &grant,
        &no_predecessor(&env),
        &salt(&env, 1),
    );
    assert_eq!(client.get_operation_state(&id), OperationStatus::Done);
    assert!(client.has_role(&council, &COUNCIL));

    env.mock_all_auths();
    execute_self(
        &env,
        &s.governor,
        "revoke_role",
        &role_args(&env, &s.council, &COUNCIL),
        2,
        &council,
    );
    assert!(!client.has_role(&s.council, &COUNCIL));
    assert_eq!(client.get_role_member_count(&COUNCIL), 1);
}

#[test]
fn execute_rejects_a_self_operation_with_the_wrong_argument_type() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();

    assert!(matches!(
        try_execute_self(
            &env,
            &s.governor,
            "grant_role",
            &vec![&env, 7u32.into_val(&env), GUARDIAN.into_val(&env)],
            1,
            &s.council,
        ),
        Err(Ok(Error::InvalidArgs))
    ));
}

#[test]
fn update_delay_is_not_a_governor_function() {
    let env = test_env();
    let s = setup(&env);
    env.mock_all_auths();

    assert!(matches!(
        try_execute_self(
            &env,
            &s.governor,
            "update_delay",
            &vec![&env, 100u32.into_val(&env)],
            1,
            &s.council,
        ),
        Err(Ok(Error::UnknownFunction))
    ));
    assert_eq!(
        GovernorClient::new(&env, &s.governor).get_delays().delay,
        DELAY
    );
}

#[test]
fn the_council_replaces_the_guardian_through_the_queue() {
    let env = test_env();
    let t = table_setup(&env, 3);
    let client = GovernorClient::new(&env, &t.governor);
    let guardian = Address::generate(&env);
    let revoke = role_args(&env, &t.guardian, &GUARDIAN);
    let grant = role_args(&env, &guardian, &GUARDIAN);

    let revoke_fn = Symbol::new(&env, "revoke_role");
    client.schedule(
        &t.governor,
        &revoke_fn,
        &revoke,
        &no_predecessor(&env),
        &salt(&env, 1),
        &t.council,
    );
    client.schedule(
        &t.governor,
        &grant_role_fn(&env),
        &grant,
        &no_predecessor(&env),
        &salt(&env, 2),
        &t.council,
    );

    assert!(matches!(
        try_cancel_self(&env, &t.governor, "revoke_role", &revoke, 1, &t.guardian),
        Err(Ok(e)) if e == host_error(2000)
    ));
    assert!(matches!(
        try_cancel_self(&env, &t.governor, "grant_role", &grant, 2, &t.guardian),
        Err(Ok(e)) if e == host_error(2000)
    ));
    assert_eq!(client.get_pending().len(), 2);

    let ready = client
        .get_pending()
        .get(0)
        .expect("two pending operations")
        .ready_ledger;
    env.ledger().set_sequence_number(ready);
    client.execute(
        &t.governor,
        &revoke_fn,
        &revoke,
        &no_predecessor(&env),
        &salt(&env, 1),
    );
    client.execute(
        &t.governor,
        &grant_role_fn(&env),
        &grant,
        &no_predecessor(&env),
        &salt(&env, 2),
    );

    client.pause(&t.asp, &MUTATIONS, &guardian);
    assert_eq!(pause_state(&env, &t).flags, MUTATIONS);
    assert!(matches!(
        client.try_pause(&t.asp, &MUTATIONS, &t.guardian),
        Err(Err(InvokeError::Contract(2000)))
    ));
}

#[test]
fn the_guardian_cannot_cancel_a_table_change() {
    let env = test_env();
    let t = table_setup(&env, 3);
    let client = GovernorClient::new(&env, &t.governor);
    let update_admin = Symbol::new(&env, "update_admin");
    let args = fn_role_args(&env, &t.asp, &update_admin, &OPERATOR);

    client.schedule(
        &t.governor,
        &Symbol::new(&env, "set_fn_role"),
        &args,
        &no_predecessor(&env),
        &salt(&env, 1),
        &t.council,
    );

    assert!(matches!(
        try_cancel_self(&env, &t.governor, "set_fn_role", &args, 1, &t.guardian),
        Err(Ok(e)) if e == host_error(2000)
    ));
    assert_eq!(client.get_pending().len(), 1);

    try_cancel_self(&env, &t.governor, "set_fn_role", &args, 1, &t.council)
        .expect("the council cancels")
        .expect("a void result");
    assert_eq!(client.get_pending(), Vec::new(&env));
    assert!(matches!(
        client.try_execute_now(
            &t.asp,
            &update_admin,
            &vec![&env, Address::generate(&env).into_val(&env)],
            &t.operator,
        ),
        Err(Ok(Error::Unauthorized))
    ));
}
