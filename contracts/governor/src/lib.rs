//! Timelocked administration of the pools and the association set providers.
//!
//! This contract holds the privileged functions of every contract it
//! administers. A change is queued as an operation, waits out a delay, and is
//! then executed by anyone, so an observer has the whole delay in which to
//! react before the change takes effect.
//!
//! The queue, the operation hash, and the role table come from the
//! OpenZeppelin `stellar-governance` and `stellar-access` crates. What this
//! contract adds is the recovery path, the grace window after which a ready
//! operation stops being executable, an on-ledger list of what is queued, and
//! the queue cap that keeps that list readable.
//!
//! Four roles divide the authority. The council queues and cancels operations,
//! the recovery role queues role changes when the council keys are lost, the
//! guardian stops a contract without waiting for the queue, and the operator
//! makes the calls that the permission table opens to it.
#![no_std]
use soroban_sdk::{
    Address, BytesN, Env, Symbol, Val, Vec, contract, contractclient, contracterror, contractimpl,
    contracttype, panic_with_error, symbol_short,
};
use soroban_utils::{bump_entry, bump_instance};
use stellar_access::access_control as access;
use stellar_governance::timelock;
use stellar_macros::only_role;

/// Role that queues any operation against any target and cancels queued ones.
pub const COUNCIL: Symbol = symbol_short!("council");
/// Role that calls a target function the permission table opens to it.
pub const OPERATOR: Symbol = symbol_short!("operator");
/// Role that pauses a target without waiting out the delay.
pub const GUARDIAN: Symbol = symbol_short!("guardian");
/// Role that queues role changes when the council keys are lost.
pub const RECOVERY: Symbol = symbol_short!("recovery");

/// Smallest `delay` the constructor accepts, one minute of ledgers.
pub const DELAY_FLOOR: u32 = 12;

/// Most operations the queue holds at once.
///
/// An operation left past its grace window is never removed by
/// [`Governor::execute`], which rolls back, so without a ceiling the queue
/// grows for as long as nobody tends it.
pub const MAX_PENDING: u32 = 16;

/// Most operations the council may leave queued.
///
/// The gap up to [`MAX_PENDING`] belongs to the recovery role alone, so a
/// council whose keys are compromised cannot fill the queue and shut out the
/// role that exists to replace it.
pub const MAX_PENDING_COUNCIL: u32 = 12;

/// A role handed to an address when the governor is constructed.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoleGrant {
    /// One of the four roles the governor defines.
    pub role: Symbol,
    /// The address that receives the role.
    pub member: Address,
}

/// The role that one target function requires of an undelayed caller.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FnRule {
    /// The contract the rule covers.
    pub target: Address,
    /// The function on that contract.
    pub function: Symbol,
    /// The role a caller must hold to invoke it without the queue.
    pub role: Symbol,
}

/// The four waiting periods a governor is constructed with.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Delays {
    /// Ledgers between a council operation being queued and becoming ready.
    pub delay: u32,
    /// Ledgers between a recovery operation being queued and becoming ready.
    pub recovery_delay: u32,
    /// Ledgers a ready operation stays executable.
    pub grace: u32,
    /// Ledgers a guardian pause holds before the deadline it sets.
    pub guardian_pause: u32,
}

/// A queued operation together with the ledger at which it becomes ready.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingOperation {
    /// The operation hash, which is also its queue key.
    pub id: BytesN<32>,
    /// The call the operation performs once executed.
    pub operation: timelock::Operation,
    /// Ledger sequence number at which the operation may be executed.
    pub ready_ledger: u32,
}

/// Where an operation stands in the queue.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationStatus {
    /// No operation with this hash has been scheduled.
    Unset,
    /// Scheduled, and the delay has not run out.
    Waiting,
    /// The delay has run out and the grace window has not.
    Ready,
    /// The grace window closed before anyone executed the operation.
    Expired,
    /// The operation has been executed.
    Done,
}

/// Storage keys for contract data the governor owns.
///
/// The minimum delay, the operation ledgers, and the role table live under the
/// OpenZeppelin crates' own keys.
#[contracttype]
#[derive(Clone, Debug)]
enum DataKey {
    /// Ledgers a recovery operation waits before it becomes ready.
    RecoveryDelay,
    /// Ledgers a ready operation stays executable.
    Grace,
    /// Ledgers a guardian pause holds before the deadline it sets.
    GuardianPause,
    /// Hashes of the operations that are queued and not yet executed.
    Pending,
    /// The queued call, stored under its hash while it is pending.
    Operation(BytesN<32>),
    /// The role a target function requires of an undelayed caller.
    FnRole(Address, Symbol),
}

/// The errors the governor raises.
///
/// The codes start at 3000 so that a failure the governor raises is
/// distinguishable from one it forwards from a target contract, the same way
/// OpenZeppelin reserves 2000 for access control and 4000 for the timelock.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// The governor's configuration is absent, or the arguments given to the
    /// constructor break an invariant it requires.
    InvalidConfig = 3001,
    /// The requested delay is below the floor that applies to the call.
    InsufficientDelay = 3002,
    /// The grace window closed before anyone executed the operation.
    Expired = 3003,
    /// The caller holds no role that permits the call.
    Unauthorized = 3004,
    /// A ledger computation overflowed.
    Overflow = 3005,
    /// The permission table holds no row for the target function.
    UnknownFunction = 3006,
    /// The arguments do not match what the target function accepts.
    InvalidArgs = 3007,
    /// The change would leave the governor without a required role holder.
    RoleInvariant = 3008,
    /// The symbol names no role the governor defines.
    UnknownRole = 3009,
    /// The queue already holds as many operations as the caller's role may
    /// leave in it.
    QueueFull = 3010,
}

/// The pause entry points every contract the governor administers exposes.
#[contractclient(name = "PausableTargetClient")]
pub trait PausableTarget {
    /// Sets `flags`, which stop being honored at `until` when it is given.
    fn pause(env: Env, flags: u32, until: Option<u32>);
    /// Clears `flags`.
    fn unpause(env: Env, flags: u32);
}

/// The timelocked administrator of the pools and the association set providers.
#[contract]
pub struct Governor;

#[contractimpl]
impl Governor {
    /// Configures the waiting periods and hands out the initial roles.
    ///
    /// The four waiting periods are counts of ledgers: `delay` is at least
    /// [`DELAY_FLOOR`], `recovery_delay` is at least `delay`, `grace` is at
    /// least 1, and `guardian_pause` exceeds `delay` so that the council can
    /// queue an unpause inside the window. `roles` covers at least one council
    /// address, one recovery address, and one guardian, with no address under
    /// two roles. `fn_roles` is the permission table, one row per target
    /// function that a role may call without the queue.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidConfig`] if any of those conditions fails, or
    /// if a grant or a table row names a symbol that is not one of the four
    /// roles.
    ///
    /// # Events
    ///
    /// Publishes `RoleGranted` from the OpenZeppelin access control module for
    /// each grant, and `MinDelayChanged` from the OpenZeppelin timelock.
    pub fn __constructor(
        env: Env,
        delay: u32,
        recovery_delay: u32,
        grace: u32,
        guardian_pause: u32,
        roles: Vec<RoleGrant>,
        fn_roles: Vec<FnRule>,
    ) -> Result<(), Error> {
        if delay < DELAY_FLOOR || recovery_delay < delay || grace == 0 || guardian_pause <= delay {
            return Err(Error::InvalidConfig);
        }

        let governor = env.current_contract_address();
        for (index, grant) in roles.iter().enumerate() {
            if !is_known_role(&grant.role) {
                return Err(Error::InvalidConfig);
            }
            if roles
                .iter()
                .take(index)
                .any(|other| other.member == grant.member)
            {
                return Err(Error::InvalidConfig);
            }
            grant_role(&env, &grant.member, &grant.role, &governor);
        }
        if access::get_role_member_count(&env, &COUNCIL) == 0
            || access::get_role_member_count(&env, &RECOVERY) == 0
            || access::get_role_member_count(&env, &GUARDIAN) == 0
        {
            return Err(Error::InvalidConfig);
        }

        let store = env.storage().persistent();
        for rule in fn_roles.iter() {
            if !is_known_role(&rule.role) {
                return Err(Error::InvalidConfig);
            }
            let key = DataKey::FnRole(rule.target, rule.function);
            store.set(&key, &rule.role);
            bump_entry(&env, &key);
        }

        timelock::set_min_delay(&env, delay);
        let instance = env.storage().instance();
        instance.set(&DataKey::RecoveryDelay, &recovery_delay);
        instance.set(&DataKey::Grace, &grace);
        instance.set(&DataKey::GuardianPause, &guardian_pause);
        bump_instance(&env);
        Ok(())
    }

    /// Queues an operation and returns its hash.
    ///
    /// The council may queue any call against any contract and waits the
    /// governor's delay. A recovery address may queue only `grant_role` and
    /// `revoke_role` on the governor itself, and waits the recovery delay
    /// instead. Every operation whose grace window has closed is dropped from
    /// the queue before the new one is appended. `predecessor` is the hash of
    /// an operation that must execute first, or 32 zero bytes for none, and
    /// `salt` distinguishes two otherwise identical operations.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unauthorized`] if `caller` holds neither the council
    /// nor the recovery role, or holds only recovery and the call is not a
    /// role change on the governor; [`Error::Overflow`] if the ready ledger
    /// would exceed `u32::MAX`; and [`Error::QueueFull`] if the queue is
    /// already at [`MAX_PENDING_COUNCIL`] for the council, or [`MAX_PENDING`]
    /// for a recovery address, once the dead operations have been pruned.
    ///
    /// # Panics
    ///
    /// Panics with OpenZeppelin's `OperationAlreadyScheduled` if an operation
    /// with the same hash is already queued, and with
    /// [`Error::InvalidConfig`] if the governor holds no configuration, which
    /// a constructed governor always does.
    ///
    /// # Events
    ///
    /// Publishes `OperationScheduled` from the OpenZeppelin timelock.
    pub fn schedule(
        env: Env,
        target: Address,
        function: Symbol,
        args: Vec<Val>,
        predecessor: BytesN<32>,
        salt: BytesN<32>,
        caller: Address,
    ) -> Result<BytesN<32>, Error> {
        bump_instance(&env);
        caller.require_auth();

        let council = access::has_role(&env, &caller, &COUNCIL).is_some();
        let required = if council {
            timelock::get_min_delay(&env)
        } else if access::has_role(&env, &caller, &RECOVERY).is_some() {
            if target != env.current_contract_address() || !is_role_function(&env, &function) {
                return Err(Error::Unauthorized);
            }
            setting(&env, &DataKey::RecoveryDelay)
        } else {
            return Err(Error::Unauthorized);
        };

        env.ledger()
            .sequence()
            .checked_add(required)
            .ok_or(Error::Overflow)?;

        let mut pending = prune_pending(&env);
        let limit = if council {
            MAX_PENDING_COUNCIL
        } else {
            MAX_PENDING
        };
        if pending.len() >= limit {
            return Err(Error::QueueFull);
        }

        let operation = operation(target, function, args, predecessor, salt);
        let id = timelock::schedule_operation(&env, &operation, required);

        let key = DataKey::Operation(id.clone());
        env.storage().persistent().set(&key, &operation);
        bump_entry(&env, &key);
        // The timelock writes the ready ledger with the network minimum
        // lifetime, which on a delay of a week or more expires before the
        // operation it gates becomes executable.
        bump_entry(
            &env,
            &timelock::TimelockStorageKey::OperationLedger(id.clone()),
        );

        pending.push_back(id.clone());
        env.storage().persistent().set(&DataKey::Pending, &pending);
        bump_entry(&env, &DataKey::Pending);

        Ok(id)
    }

    /// Executes a ready operation and returns what the target returned.
    ///
    /// Anyone may execute. The delay is what protects the call, not the
    /// identity of whoever finally makes it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Expired`] if the grace window closed, and
    /// [`Error::Unauthorized`] if the target is the governor itself.
    ///
    /// # Panics
    ///
    /// Panics with OpenZeppelin's `InvalidOperationState` if the operation is
    /// not ready, `UnexecutedPredecessor` if its predecessor has not run, and
    /// [`Error::InvalidConfig`] if the governor holds no configuration, which
    /// a constructed governor always does.
    ///
    /// # Events
    ///
    /// Publishes `OperationExecuted` from the OpenZeppelin timelock.
    pub fn execute(
        env: Env,
        target: Address,
        function: Symbol,
        args: Vec<Val>,
        predecessor: BytesN<32>,
        salt: BytesN<32>,
    ) -> Result<Val, Error> {
        bump_instance(&env);
        let operation = operation(target, function, args, predecessor, salt);
        let id = timelock::hash_operation(&env, &operation);

        let ready = timelock::get_operation_ledger(&env, &id);
        if is_scheduled(ready)
            && env.ledger().sequence() > ready.saturating_add(setting(&env, &DataKey::Grace))
        {
            return Err(Error::Expired);
        }

        timelock::set_execute_operation(&env, &operation);
        forget(&env, &id);

        if operation.target == env.current_contract_address() {
            return Err(Error::Unauthorized);
        }
        Ok(env.invoke_contract::<Val>(&operation.target, &operation.function, operation.args))
    }

    /// Calls a target function that the permission table opens to the caller's
    /// role, without the queue.
    ///
    /// The table is what lets a compliance owner keep an allowlist current
    /// without a delay on every write. It never reaches the governor itself,
    /// so no row can hand out a role or change a delay.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unauthorized`] if `target` is the governor itself, or
    /// if the table holds no row for the target function.
    ///
    /// # Panics
    ///
    /// Panics with OpenZeppelin's `Unauthorized` if `caller` does not hold the
    /// role the row names.
    pub fn execute_now(
        env: Env,
        target: Address,
        function: Symbol,
        args: Vec<Val>,
        caller: Address,
    ) -> Result<Val, Error> {
        bump_instance(&env);
        caller.require_auth();
        if target == env.current_contract_address() {
            return Err(Error::Unauthorized);
        }
        let role = read_fn_role(&env, &target, &function).ok_or(Error::Unauthorized)?;
        access::ensure_role(&env, &role, &caller);
        Ok(env.invoke_contract::<Val>(&target, &function, args))
    }

    /// Cancels a queued operation, which is named by the call it would make.
    ///
    /// # Panics
    ///
    /// Panics with OpenZeppelin's `Unauthorized` if `caller` does not hold the
    /// council role, and `InvalidOperationState` if the operation is neither
    /// waiting nor ready.
    ///
    /// # Events
    ///
    /// Publishes `OperationCancelled` from the OpenZeppelin timelock.
    #[only_role(caller, "council")]
    pub fn cancel(
        env: Env,
        target: Address,
        function: Symbol,
        args: Vec<Val>,
        predecessor: BytesN<32>,
        salt: BytesN<32>,
        caller: Address,
    ) {
        bump_instance(&env);
        let id =
            timelock::hash_operation(&env, &operation(target, function, args, predecessor, salt));
        timelock::cancel_operation(&env, &id);
        forget(&env, &id);
    }

    /// Pauses `flags` on `target` until the guardian window closes.
    ///
    /// The deadline is the current ledger plus the guardian pause the governor
    /// was constructed with. The target decides what that deadline means: a
    /// contract with a pause already in force keeps the deadline it has and
    /// only adds the bits, one whose bits the council cleared while an earlier
    /// deadline is still ahead refuses the call, and one whose earlier deadline
    /// has passed takes the new deadline for every bit still set.
    ///
    /// That last case widens a pause beyond the bits `flags` names, because a
    /// lapsed deadline stops a bit being honored without clearing it. Read the
    /// target's pause state before pausing one shape, and have the council
    /// clear the stale bits through the queue.
    ///
    /// The council pauses without a deadline through the queue, as
    /// [`Governor::unpause`] describes. `flags` is read in the target's own
    /// mask.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Overflow`] if the deadline would exceed `u32::MAX`.
    ///
    /// # Panics
    ///
    /// Panics with OpenZeppelin's `Unauthorized` if `caller` does not hold the
    /// guardian role. A target that refuses the pause raises its own error,
    /// which rolls the call back: `InvalidPauseFlags` when `flags` is zero or
    /// outside its mask, and `TimedPauseArmed` when its bits were all cleared
    /// while an earlier deadline is still ahead. Panics with
    /// [`Error::InvalidConfig`] if the governor holds no configuration, which
    /// a constructed governor always does.
    #[only_role(caller, "guardian")]
    pub fn pause(env: Env, target: Address, flags: u32, caller: Address) -> Result<(), Error> {
        bump_instance(&env);
        let until = env
            .ledger()
            .sequence()
            .checked_add(setting(&env, &DataKey::GuardianPause))
            .ok_or(Error::Overflow)?;
        PausableTargetClient::new(&env, &target).pause(&flags, &Some(until));
        Ok(())
    }

    /// Clears `flags` on `target`.
    ///
    /// This is the only pause entry point the council holds. Its pause with
    /// no deadline is a queued call to the target's own `pause` with `until`
    /// absent: [`Governor::schedule`] it against the target, then
    /// [`Governor::execute`] it once the delay has passed. `flags` is read in
    /// the target's own mask.
    ///
    /// # Panics
    ///
    /// Panics with OpenZeppelin's `Unauthorized` if `caller` does not hold the
    /// council role, and with the target's `InvalidPauseFlags` if `flags` is
    /// zero or outside its mask.
    #[only_role(caller, "council")]
    pub fn unpause(env: Env, target: Address, flags: u32, caller: Address) {
        bump_instance(&env);
        PausableTargetClient::new(&env, &target).unpause(&flags);
    }

    /// Returns the four waiting periods the governor was constructed with.
    ///
    /// # Panics
    ///
    /// Panics with [`Error::InvalidConfig`] if the governor has no
    /// configuration stored, and with OpenZeppelin's `MinDelayNotSet` if it
    /// has no minimum delay.
    pub fn get_delays(env: Env) -> Delays {
        bump_instance(&env);
        Delays {
            delay: timelock::get_min_delay(&env),
            recovery_delay: setting(&env, &DataKey::RecoveryDelay),
            grace: setting(&env, &DataKey::Grace),
            guardian_pause: setting(&env, &DataKey::GuardianPause),
        }
    }

    /// Returns the role one target function requires of an undelayed caller,
    /// or `None` when the permission table holds no row for it.
    pub fn get_fn_role(env: Env, target: Address, function: Symbol) -> Option<Symbol> {
        bump_instance(&env);
        read_fn_role(&env, &target, &function)
    }

    /// Reports whether `member` holds `role`.
    pub fn has_role(env: Env, member: Address, role: Symbol) -> bool {
        bump_instance(&env);
        access::has_role(&env, &member, &role).is_some()
    }

    /// Returns the number of addresses that hold `role`.
    pub fn get_role_member_count(env: Env, role: Symbol) -> u32 {
        bump_instance(&env);
        access::get_role_member_count(&env, &role)
    }

    /// Returns the address holding `role` at `index`.
    ///
    /// # Panics
    ///
    /// Panics with OpenZeppelin's `IndexOutOfBounds` if fewer than `index + 1`
    /// addresses hold the role.
    pub fn get_role_member(env: Env, role: Symbol, index: u32) -> Address {
        bump_instance(&env);
        access::get_role_member(&env, &role, index)
    }

    /// Returns the hash that identifies the operation these arguments
    /// describe.
    pub fn hash_operation(
        env: Env,
        target: Address,
        function: Symbol,
        args: Vec<Val>,
        predecessor: BytesN<32>,
        salt: BytesN<32>,
    ) -> BytesN<32> {
        bump_instance(&env);
        timelock::hash_operation(&env, &operation(target, function, args, predecessor, salt))
    }

    /// Returns where the operation identified by `id` stands in the queue.
    ///
    /// An expired operation is still ready as far as the OpenZeppelin timelock
    /// is concerned, so [`Governor::cancel`] accepts it while
    /// [`Governor::execute`] refuses it.
    ///
    /// # Panics
    ///
    /// Panics with [`Error::InvalidConfig`] if the governor has no grace
    /// window stored.
    pub fn get_operation_state(env: Env, id: BytesN<32>) -> OperationStatus {
        bump_instance(&env);
        let ready = timelock::get_operation_ledger(&env, &id);
        let now = env.ledger().sequence();
        match ready {
            timelock::UNSET_LEDGER => OperationStatus::Unset,
            timelock::DONE_LEDGER => OperationStatus::Done,
            _ if ready > now => OperationStatus::Waiting,
            _ if now > ready.saturating_add(setting(&env, &DataKey::Grace)) => {
                OperationStatus::Expired
            }
            _ => OperationStatus::Ready,
        }
    }

    /// Returns every queued operation with the ledger at which it becomes
    /// ready.
    ///
    /// Public RPC keeps events for about a week, which is shorter than the
    /// delay a deployment may choose, so the queue is answered from ledger
    /// state rather than from the event log.
    pub fn get_pending(env: Env) -> Vec<PendingOperation> {
        bump_instance(&env);
        let mut pending = Vec::new(&env);
        for id in pending_ids(&env).iter() {
            let key = DataKey::Operation(id.clone());
            let Some(operation) = env.storage().persistent().get(&key) else {
                continue;
            };
            bump_entry(&env, &key);
            let ready_ledger = timelock::get_operation_ledger(&env, &id);
            pending.push_back(PendingOperation {
                id,
                operation,
                ready_ledger,
            });
        }
        pending
    }
}

/// Assembles the operation these arguments describe.
fn operation(
    target: Address,
    function: Symbol,
    args: Vec<Val>,
    predecessor: BytesN<32>,
    salt: BytesN<32>,
) -> timelock::Operation {
    timelock::Operation {
        target,
        function,
        args,
        predecessor,
        salt,
    }
}

/// Reports whether `role` is one of the four roles the governor defines.
fn is_known_role(role: &Symbol) -> bool {
    [COUNCIL, OPERATOR, GUARDIAN, RECOVERY].contains(role)
}

/// Reports whether `function` is one of the role changes a recovery address
/// may queue against the governor.
fn is_role_function(env: &Env, function: &Symbol) -> bool {
    *function == Symbol::new(env, "grant_role") || *function == Symbol::new(env, "revoke_role")
}

/// Reports whether `ready_ledger` belongs to an operation that is queued
/// rather than one that is unset or already done.
fn is_scheduled(ready_ledger: u32) -> bool {
    ready_ledger != timelock::UNSET_LEDGER && ready_ledger != timelock::DONE_LEDGER
}

/// Grants `role` to `member` and extends the lifetime of the entries the grant
/// writes.
///
/// The access control module writes one more entry, the role enumeration slot
/// that [`Governor::get_role_member`] reads, under a key private to the
/// module. Reading the member back through the module's own getter is what
/// extends that one, because the module writes it without ever reading it.
/// That read lands at the module's own 90-day amount rather than
/// [`soroban_utils::ttl::EXTEND_TO`], because the key type the entry needs is
/// private and [`bump_entry`] cannot name it.
fn grant_role(env: &Env, member: &Address, role: &Symbol, caller: &Address) {
    access::grant_role_no_auth(env, member, role, caller);
    bump_entry(
        env,
        &access::AccessControlStorageKey::HasRole(member.clone(), role.clone()),
    );
    bump_entry(
        env,
        &access::AccessControlStorageKey::RoleAccountsCount(role.clone()),
    );
    bump_entry(env, &access::AccessControlStorageKey::ExistingRoles);
    if let Some(index) = access::has_role(env, member, role) {
        access::get_role_member(env, role, index);
    }
}

/// Reads one of the governor's own waiting periods from instance storage.
///
/// # Panics
///
/// Panics with [`Error::InvalidConfig`] if the governor holds no value under
/// `key`, which a constructed governor always does.
fn setting(env: &Env, key: &DataKey) -> u32 {
    env.storage()
        .instance()
        .get(key)
        .unwrap_or_else(|| panic_with_error!(env, Error::InvalidConfig))
}

/// Reads one permission table row and extends the entry's lifetime.
fn read_fn_role(env: &Env, target: &Address, function: &Symbol) -> Option<Symbol> {
    let key = DataKey::FnRole(target.clone(), function.clone());
    env.storage()
        .persistent()
        .get(&key)
        .inspect(|_| bump_entry(env, &key))
}

/// Reads the queued operation hashes, treating an absent list as empty.
fn pending_ids(env: &Env) -> Vec<BytesN<32>> {
    env.storage()
        .persistent()
        .get(&DataKey::Pending)
        .inspect(|_| bump_entry(env, &DataKey::Pending))
        .unwrap_or_else(|| Vec::new(env))
}

/// Returns the queue with every operation that can no longer be executed
/// dropped, and forgets the call each dropped operation held.
///
/// An operation left past its grace window returns [`Error::Expired`] from
/// [`Governor::execute`], which rolls back, so nothing removes it on its own.
/// Pruning on the way into [`Governor::schedule`] is what keeps a queue that
/// nobody tends from growing until governance can no longer act.
fn prune_pending(env: &Env) -> Vec<BytesN<32>> {
    let grace = setting(env, &DataKey::Grace);
    let now = env.ledger().sequence();
    let mut kept = Vec::new(env);
    for id in pending_ids(env).iter() {
        let ready = timelock::get_operation_ledger(env, &id);
        let scheduled = is_scheduled(ready);
        if scheduled && now <= ready.saturating_add(grace) {
            kept.push_back(id);
        } else {
            if scheduled {
                timelock::cancel_operation(env, &id);
            }
            env.storage().persistent().remove(&DataKey::Operation(id));
        }
    }
    kept
}

/// Drops an operation from the queue once it has executed or been cancelled.
fn forget(env: &Env, id: &BytesN<32>) {
    env.storage()
        .persistent()
        .remove(&DataKey::Operation(id.clone()));
    let mut pending = pending_ids(env);
    if let Some(index) = pending.first_index_of(id) {
        pending.remove(index);
        env.storage().persistent().set(&DataKey::Pending, &pending);
    }
}

mod test;
