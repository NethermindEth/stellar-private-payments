#![cfg(test)]

use super::*;
use soroban_sdk::{
    Address, BytesN, Env, IntoVal, InvokeError, Symbol, Val, Vec,
    events::Event,
    testutils::{
        Address as _, Events, Ledger as _,
        storage::{Instance as _, Persistent as _},
    },
    vec,
};
use soroban_utils::ttl::EXTEND_TO;
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
) -> Address {
    env.register(
        Governor,
        (delay, recovery_delay, grace, guardian_pause, roles),
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

    register_governor(&env, DELAY, RECOVERY_DELAY, GRACE, GUARDIAN_PAUSE, grants);
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

    register_governor(&env, DELAY, RECOVERY_DELAY, GRACE, GUARDIAN_PAUSE, grants);
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
fn execute_rejects_the_governor_as_target() {
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
        Err(Ok(Error::Unauthorized))
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
