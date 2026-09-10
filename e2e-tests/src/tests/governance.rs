//! End-to-end tests that drive the pool and the association set providers
//! through the governor.
//!
//! Each case runs against a real Groth16 proof and the compiled verifier, so an
//! operator write, a pause, or an administrator rotation is observed the way a
//! deployment observes it: through the governor, with the target's own
//! administrator role already handed over.

use super::utils::{
    ASP_MEMBERSHIP_LEVELS, GOV_DELAY, GOV_GUARDIAN_PAUSE, GOV_RECOVERY_DELAY, GovernedContracts,
    TransactOutcome, allowlist_leaves, bigint_to_u256, deploy_governed_contracts,
    non_membership_overrides_from_pubs, prove_transaction, scalar_to_u256, sync_pool_state,
    test_env, transact,
};
use anyhow::Result;
use asp_membership::{ASPMembership, ASPMembershipClient};
use governor::GovernorClient;
use pool::{Error, ExtData, PoolContractClient, Proof};
use soroban_sdk::{
    Address, BytesN, Env, IntoVal, InvokeError, Symbol, U256, Val, Vec,
    events::Event as _,
    testutils::{Address as _, Events as _, Ledger as _, MockAuth, MockAuthInvoke},
};
use soroban_utils::{AdminUpdated, pausable};

/// Result of `GovernorClient::try_execute_now`.
type ExecuteNowOutcome =
    Result<Result<Val, soroban_sdk::ConversionError>, Result<governor::Error, InvokeError>>;

/// A governed deployment with one proven pool transaction ready to send.
struct GovernedFixture {
    env: Env,
    gov: GovernedContracts,
    proof: Proof,
    ext_data: ExtData,
}

impl GovernedFixture {
    fn governor(&self) -> GovernorClient<'_> {
        GovernorClient::new(&self.env, &self.gov.governor)
    }

    fn pool(&self) -> PoolContractClient<'_> {
        PoolContractClient::new(&self.env, &self.gov.contracts.pool)
    }

    /// Sends the transaction to the pool contract.
    fn transact(&self) -> TransactOutcome {
        transact(&self.env, &self.gov.contracts, &self.proof, &self.ext_data)
    }

    /// Inserts one allowlist leaf through the governor's undelayed path as
    /// `caller`, returning the outcome so a refusal can be observed.
    fn try_allowlist(&self, leaf: u32, caller: &Address) -> ExecuteNowOutcome {
        self.governor().try_execute_now(
            &self.gov.contracts.asp_membership,
            &insert_leaf(&self.env),
            &soroban_sdk::vec![
                &self.env,
                U256::from_u32(&self.env, leaf).into_val(&self.env),
            ],
            caller,
        )
    }
}

fn insert_leaf(env: &Env) -> Symbol {
    Symbol::new(env, "insert_leaf")
}

fn no_predecessor(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0u8; 32])
}

fn salt(env: &Env, byte: u8) -> BytesN<32> {
    BytesN::from_array(env, &[byte; 32])
}

/// Moves the ledger forward by `ledgers`.
fn advance(env: &Env, ledgers: u32) {
    let target = env.ledger().sequence().saturating_add(ledgers);
    env.ledger().set_sequence_number(target);
}

/// Queues `function(args)` on `target` from the council.
fn schedule(
    env: &Env,
    gov: &GovernedContracts,
    target: &Address,
    function: &Symbol,
    args: &Vec<Val>,
    byte: u8,
) {
    GovernorClient::new(env, &gov.governor).schedule(
        target,
        function,
        args,
        &no_predecessor(env),
        &salt(env, byte),
        &gov.council,
    );
}

/// Executes a ready operation with no signature at all, the way any observer
/// would once the delay has passed.
fn execute_by_anyone(
    env: &Env,
    gov: &GovernedContracts,
    target: &Address,
    function: &Symbol,
    args: &Vec<Val>,
    byte: u8,
) {
    env.set_auths(&[]);
    GovernorClient::new(env, &gov.governor).execute(
        target,
        function,
        args,
        &no_predecessor(env),
        &salt(env, byte),
    );
    env.mock_all_auths();
}

/// Builds a governed deployment and proves one pool transaction against the
/// association set state the operator writes into it.
///
/// Every allowlist and blocklist write goes through `execute_now`, so the roots
/// the pool checks are the ones the governor produced.
fn governed_fixture(
    in_amounts: [u64; 2],
    out_amounts: [u64; 2],
    ext_amount: i32,
) -> Result<GovernedFixture> {
    let env = test_env();
    let mut proven = prove_transaction(&env, in_amounts, out_amounts, ext_amount)?;

    env.mock_all_auths();
    let gov = deploy_governed_contracts(&env);
    let client = GovernorClient::new(&env, &gov.governor);

    for leaf in allowlist_leaves(&proven.case, &proven.membership_trees, &proven.witness) {
        client.execute_now(
            &gov.contracts.asp_membership,
            &insert_leaf(&env),
            &soroban_sdk::vec![&env, scalar_to_u256(&env, leaf).into_val(&env)],
            &gov.operator,
        );
    }
    for (key, value) in non_membership_overrides_from_pubs(&proven.witness.public_keys) {
        client.execute_now(
            &gov.contracts.asp_non_membership,
            &insert_leaf(&env),
            &soroban_sdk::vec![
                &env,
                bigint_to_u256(&env, &key).into_val(&env),
                bigint_to_u256(&env, &value).into_val(&env),
            ],
            &gov.operator,
        );
    }

    let roots = sync_pool_state(
        &env,
        &gov.contracts,
        &proven.case,
        &mut proven.leaves,
        &proven.witness,
    );

    let ext_data = proven.ext_data.clone();
    Ok(GovernedFixture {
        proof: proven.into_proof(&env, &roots),
        env,
        gov,
        ext_data,
    })
}

/// The operator writes both association sets through the governor, a deposit
/// proved against the resulting roots verifies on chain, and the council does
/// not reach the operator's row.
#[test]
#[cfg_attr(miri, ignore)]
fn the_operator_writes_both_association_sets_through_the_governor() -> Result<()> {
    let fixture = governed_fixture([0, 0], [13, 0], 13)?;

    assert_ne!(
        fixture.proof.asp_membership_root,
        U256::from_u32(&fixture.env, 0),
        "the allowlist writes must have landed"
    );
    assert!(
        fixture.transact().is_ok(),
        "a deposit proved against the governed roots should verify"
    );
    assert!(
        matches!(
            fixture.try_allowlist(42, &fixture.gov.council),
            Err(Err(InvokeError::Contract(2000)))
        ),
        "the council must not reach the operator's row"
    );
    Ok(())
}

/// A guardian shuts deposits through the governor and only the council reopens
/// them.
#[test]
#[cfg_attr(miri, ignore)]
fn a_guardian_pause_of_deposits_holds_until_the_council_lifts_it() -> Result<()> {
    let fixture = governed_fixture([0, 0], [13, 0], 13)?;
    let pool = fixture.gov.contracts.pool.clone();
    let root_before = fixture.pool().get_root();

    fixture
        .governor()
        .pause(&pool, &pausable::DEPOSITS, &fixture.gov.guardian);

    assert!(
        matches!(fixture.transact(), Err(Ok(Error::Paused))),
        "a paused pool must refuse the deposit"
    );
    assert_eq!(
        fixture.pool().get_root(),
        root_before,
        "a refused deposit must leave the commitment tree alone"
    );

    fixture
        .governor()
        .unpause(&pool, &pausable::DEPOSITS, &fixture.gov.council);

    assert!(
        fixture.transact().is_ok(),
        "the deposit should land once the council lifts the pause"
    );
    Ok(())
}

/// The incident script's shape: the guardian pauses the pool and both
/// association set providers in three calls, and every write stops.
#[test]
#[cfg_attr(miri, ignore)]
fn the_guardian_pauses_the_pool_and_both_association_sets() -> Result<()> {
    let fixture = governed_fixture([0, 0], [13, 0], 13)?;
    let gov = &fixture.gov;
    let governor = fixture.governor();

    governor.pause(&gov.contracts.pool, &pausable::DEPOSITS, &gov.guardian);
    governor.pause(
        &gov.contracts.asp_membership,
        &pausable::MUTATIONS,
        &gov.guardian,
    );
    governor.pause(
        &gov.contracts.asp_non_membership,
        &pausable::MUTATIONS,
        &gov.guardian,
    );

    assert!(
        matches!(
            fixture.try_allowlist(42, &gov.operator),
            Err(Err(InvokeError::Contract(code)))
                if code == asp_membership::Error::Paused as u32
        ),
        "a paused association set must refuse an operator write"
    );
    assert!(
        matches!(fixture.transact(), Err(Ok(Error::Paused))),
        "the paused pool must refuse the deposit"
    );
    Ok(())
}

/// A guardian's pause of withdrawals releases itself, and a proof made before
/// it still verifies afterwards.
#[test]
#[cfg_attr(miri, ignore)]
fn a_guardian_pause_of_withdrawals_expires_on_its_own() -> Result<()> {
    let fixture = governed_fixture([13, 0], [0, 0], -13)?;
    let pool = fixture.gov.contracts.pool.clone();

    fixture
        .governor()
        .pause(&pool, &pausable::WITHDRAWALS, &fixture.gov.guardian);

    assert!(
        matches!(fixture.transact(), Err(Ok(Error::Paused))),
        "a paused pool must refuse the withdrawal"
    );

    advance(&fixture.env, GOV_GUARDIAN_PAUSE);

    assert!(
        fixture.transact().is_ok(),
        "the withdrawal should land once the guardian's pause lapses"
    );
    Ok(())
}

/// The council's pause with no deadline is a queued call to the pool's own
/// `pause`, and it outlives the guardian's window that covered the delay.
#[test]
#[cfg_attr(miri, ignore)]
fn the_council_pauses_without_a_deadline_through_the_queue() -> Result<()> {
    let fixture = governed_fixture([13, 0], [0, 0], -13)?;
    let env = &fixture.env;
    let gov = &fixture.gov;
    let pool = gov.contracts.pool.clone();
    let pause = Symbol::new(env, "pause");
    let args = soroban_sdk::vec![
        env,
        pausable::POOL_MASK.into_val(env),
        None::<u32>.into_val(env),
    ];

    fixture
        .governor()
        .pause(&pool, &pausable::POOL_MASK, &gov.guardian);
    schedule(env, gov, &pool, &pause, &args, 1);
    advance(env, GOV_DELAY);
    execute_by_anyone(env, gov, &pool, &pause, &args, 1);

    advance(env, GOV_GUARDIAN_PAUSE);
    assert_eq!(
        fixture.pool().get_pause_state(),
        pausable::PauseState {
            flags: pausable::POOL_MASK,
            until: None,
        }
    );
    assert!(
        matches!(fixture.transact(), Err(Ok(Error::Paused))),
        "the council's pause must hold after the guardian's window closed"
    );

    fixture
        .governor()
        .unpause(&pool, &pausable::POOL_MASK, &gov.council);

    assert!(
        fixture.transact().is_ok(),
        "the withdrawal should land once the council reopens the pool"
    );
    Ok(())
}

/// The guardian cannot cancel an administrator rotation; the council cancels
/// its own and the second attempt lands once the delay passes.
#[test]
#[cfg_attr(miri, ignore)]
fn the_council_rotates_the_pool_administrator_through_the_queue() {
    let env = test_env();
    env.mock_all_auths();
    let gov = deploy_governed_contracts(&env);
    let client = GovernorClient::new(&env, &gov.governor);
    let pool = gov.contracts.pool.clone();
    let successor = Address::generate(&env);
    let update_admin = Symbol::new(&env, "update_admin");
    let args = soroban_sdk::vec![&env, successor.clone().into_val(&env)];

    schedule(&env, &gov, &pool, &update_admin, &args, 1);
    assert!(
        matches!(
            client.try_cancel(
                &pool,
                &update_admin,
                &args,
                &no_predecessor(&env),
                &salt(&env, 1),
                &gov.guardian,
            ),
            Err(Ok(e)) if e == soroban_sdk::Error::from_contract_error(2000)
        ),
        "the guardian cancels nothing"
    );
    assert_eq!(client.get_pending().len(), 1);

    client.cancel(
        &pool,
        &update_admin,
        &args,
        &no_predecessor(&env),
        &salt(&env, 1),
        &gov.council,
    );
    assert_eq!(
        client.get_pending().len(),
        0,
        "the council clears its queue"
    );

    schedule(&env, &gov, &pool, &update_admin, &args, 2);
    advance(&env, GOV_DELAY);
    execute_by_anyone(&env, &gov, &pool, &update_admin, &args, 2);

    let expected = AdminUpdated {
        old_admin: gov.governor.clone(),
        new_admin: successor,
    }
    .to_xdr(&env, &pool);
    let pool_events = env.events().all().filter_by_contract(&pool);
    assert!(
        pool_events.events().contains(&expected),
        "the pool must record the rotation to the new administrator"
    );
}

/// The recovery address restores a council after its key is lost, and the
/// replacement then revokes the old one.
#[test]
#[cfg_attr(miri, ignore)]
fn the_recovery_address_replaces_a_lost_council() {
    let env = test_env();
    env.mock_all_auths();
    let gov = deploy_governed_contracts(&env);
    let client = GovernorClient::new(&env, &gov.governor);
    let successor = Address::generate(&env);
    let grant = Symbol::new(&env, "grant_role");
    let grant_args = soroban_sdk::vec![
        &env,
        successor.clone().into_val(&env),
        governor::COUNCIL.into_val(&env),
    ];
    let scheduled_at = env.ledger().sequence();

    client.schedule(
        &gov.governor,
        &grant,
        &grant_args,
        &no_predecessor(&env),
        &salt(&env, 1),
        &gov.recovery,
    );
    assert_eq!(
        client
            .get_pending()
            .get(0)
            .expect("one pending operation")
            .ready_ledger,
        scheduled_at.saturating_add(GOV_RECOVERY_DELAY)
    );
    advance(&env, GOV_RECOVERY_DELAY);
    execute_by_anyone(&env, &gov, &gov.governor, &grant, &grant_args, 1);
    assert!(client.has_role(&successor, &governor::COUNCIL));

    let revoke = Symbol::new(&env, "revoke_role");
    let revoke_args = soroban_sdk::vec![
        &env,
        gov.council.clone().into_val(&env),
        governor::COUNCIL.into_val(&env),
    ];
    client.schedule(
        &gov.governor,
        &revoke,
        &revoke_args,
        &no_predecessor(&env),
        &salt(&env, 2),
        &successor,
    );
    advance(&env, GOV_DELAY);
    execute_by_anyone(&env, &gov, &gov.governor, &revoke, &revoke_args, 2);

    assert!(!client.has_role(&gov.council, &governor::COUNCIL));
    assert_eq!(client.get_role_member_count(&governor::COUNCIL), 1);
}

/// The council re-points the pool at a second allowlist through the queue, and
/// the pool reads its root afterwards.
#[test]
#[cfg_attr(miri, ignore)]
fn the_council_re_points_the_pool_at_a_new_allowlist() {
    let env = test_env();
    env.mock_all_auths();
    let gov = deploy_governed_contracts(&env);
    let pool = PoolContractClient::new(&env, &gov.contracts.pool);
    let root_before = pool.get_asp_membership_root();

    let new_asp = env.register(
        ASPMembership,
        (
            Address::generate(&env),
            u32::try_from(ASP_MEMBERSHIP_LEVELS).expect("ASP_MEMBERSHIP_LEVELS fits in u32"),
        ),
    );
    let new_asp_client = ASPMembershipClient::new(&env, &new_asp);
    new_asp_client.insert_leaf(&U256::from_u32(&env, 42));
    assert_ne!(new_asp_client.get_root(), root_before);

    let update = Symbol::new(&env, "update_asp_membership");
    let args = soroban_sdk::vec![&env, new_asp.clone().into_val(&env)];
    schedule(&env, &gov, &gov.contracts.pool, &update, &args, 1);
    advance(&env, GOV_DELAY);
    execute_by_anyone(&env, &gov, &gov.contracts.pool, &update, &args, 1);

    assert_eq!(pool.get_asp_membership_root(), new_asp_client.get_root());
}

/// After the handover the association set answers the governor and nobody else,
/// including the address that deployed it.
#[test]
#[cfg_attr(miri, ignore)]
fn a_direct_association_set_write_is_refused_after_the_handover() {
    let env = test_env();
    env.mock_all_auths();
    let gov = deploy_governed_contracts(&env);
    let asp = ASPMembershipClient::new(&env, &gov.contracts.asp_membership);
    let leaf = U256::from_u32(&env, 42);
    let before = asp.get_root();

    // The deployer signs the call it could have made before the rotation. The
    // governor now holds the role, so the signature no longer authorizes it.
    env.mock_auths(&[MockAuth {
        address: &gov.contracts.deployer,
        invoke: &MockAuthInvoke {
            contract: &gov.contracts.asp_membership,
            fn_name: "insert_leaf",
            args: (leaf.clone(),).into_val(&env),
            sub_invokes: &[],
        },
    }]);
    assert!(
        matches!(asp.try_insert_leaf(&leaf), Err(Err(InvokeError::Abort))),
        "the deployer must not reach the association set after the handover"
    );
    assert_eq!(asp.get_root(), before);

    // The same write lands when the operator routes it through the governor.
    env.mock_all_auths();
    GovernorClient::new(&env, &gov.governor).execute_now(
        &gov.contracts.asp_membership,
        &insert_leaf(&env),
        &soroban_sdk::vec![&env, leaf.into_val(&env)],
        &gov.operator,
    );
    assert_ne!(asp.get_root(), before);
}
