//! Pause bits that stop a contract from accepting some of its calls.
//!
//! A contract keeps one persistent entry holding a bit set, so a gated call
//! reads a single entry to learn whether it may proceed. The bits belong to the
//! contract: pools recognize [`DEPOSITS`], [`TRANSFERS`], and [`WITHDRAWALS`],
//! and the ASP contracts recognize [`MUTATIONS`]. Every caller passes the mask
//! of bits it honors, so a mistyped flag is refused rather than setting a bit
//! nothing ever reads.
//!
//! Only [`WITHDRAWALS`] expires. A timed pause names the ledger from which
//! withdrawals resume, so an operator can hold deposits and transfers shut for
//! as long as an incident lasts while withdrawals reopen on their own. The
//! module enforces less than that promise suggests: a second timed pause is
//! refused while one is armed, so the recorded ledger cannot be pushed back.
//! An [`unpause`] drops it along with the bits it names, and an untimed
//! [`pause`] drops it too, which leaves a set [`WITHDRAWALS`] bit paused with
//! no deadline at all.
//!
//! None of these functions authorizes anyone. A contract that exposes a pause
//! or an unpause is responsible for requiring its administrator's
//! authorization first.

use soroban_sdk::{Env, I256, contractevent, contracttype};

use crate::ttl::bump_entry;

/// Pool bit gating deposits.
pub const DEPOSITS: u32 = 1;

/// Pool bit gating transfers.
pub const TRANSFERS: u32 = 2;

/// Pool bit gating withdrawals, and the only bit a timed pause releases.
pub const WITHDRAWALS: u32 = 4;

/// The one bit for ASP contracts, gating inserts and deletes.
pub const MUTATIONS: u32 = 1;

/// Every bit a pool honors.
pub const POOL_MASK: u32 = DEPOSITS | TRANSFERS | WITHDRAWALS;

/// The pause bits a contract has set.
#[contracttype]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PauseState {
    /// Bits set by the last pause or unpause. [`WITHDRAWALS`] is honored only
    /// until the ledger in `until`, so read the answer from [`is_paused`]
    /// rather than testing this field.
    pub flags: u32,
    /// Ledger from which the [`WITHDRAWALS`] bit is no longer honored.
    pub until: Option<u32>,
    /// Set by a timed pause; cleared only by an untimed pause or an unpause.
    pub armed: bool,
}

#[contracttype]
#[derive(Clone)]
enum PausableKey {
    Pause,
}

/// Emitted whenever the pause bits change.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PauseChanged {
    /// Bits set after the change.
    pub flags: u32,
    /// Expiry ledger for [`WITHDRAWALS`] after the change.
    pub until: Option<u32>,
}

/// Reason a pause or an unpause was refused.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PauseError {
    /// The flags were zero, or held a bit outside the caller's mask.
    InvalidFlags,
    /// A timed pause is already in force, and a second one would move the
    /// ledger that users were promised.
    TimedPauseArmed,
}

/// Returns the stored pause state, or an all-clear state when none is stored.
///
/// Extends the entry's lifetime when it exists, so a contract that is called
/// keeps its own pause state alive.
pub fn get_state(env: &Env) -> PauseState {
    env.storage()
        .persistent()
        .get(&PausableKey::Pause)
        .inspect(|_| bump_entry(env, &PausableKey::Pause))
        .unwrap_or_default()
}

/// Sets `flags` in the stored pause state, timed by `until`.
///
/// `mask` is the set of bits the calling contract honors. Passing `Some(until)`
/// promises that [`WITHDRAWALS`] reopens at that ledger, and that promise
/// cannot be extended: a second timed pause is refused until an untimed pause
/// or an unpause clears the arm.
///
/// # Errors
///
/// Returns [`PauseError::InvalidFlags`] if `flags` is zero or holds a bit
/// outside `mask`, and [`PauseError::TimedPauseArmed`] if `until` is `Some`
/// while a timed pause is already armed.
///
/// # Events
///
/// Publishes [`PauseChanged`] from the calling contract on success.
pub fn pause(env: &Env, flags: u32, until: Option<u32>, mask: u32) -> Result<(), PauseError> {
    check_flags(flags, mask)?;
    let mut state = get_state(env);
    if until.is_some() && state.armed {
        return Err(PauseError::TimedPauseArmed);
    }

    state.flags |= flags;
    state.until = until;
    state.armed = until.is_some();
    store(env, &state);
    Ok(())
}

/// Clears `flags` from the stored pause state.
///
/// `mask` is the set of bits the calling contract honors. Clearing bits that
/// are not set is accepted, and any call clears the timed pause along with the
/// named bits.
///
/// # Errors
///
/// Returns [`PauseError::InvalidFlags`] if `flags` is zero or holds a bit
/// outside `mask`.
///
/// # Events
///
/// Publishes [`PauseChanged`] from the calling contract on success.
pub fn unpause(env: &Env, flags: u32, mask: u32) -> Result<(), PauseError> {
    check_flags(flags, mask)?;
    let mut state = get_state(env);

    state.flags &= !flags;
    state.until = None;
    state.armed = false;
    store(env, &state);
    Ok(())
}

/// Reports whether `bit` is paused at the current ledger.
///
/// [`WITHDRAWALS`] stops being honored from the timed pause's ledger onwards.
/// No other bit expires.
pub fn is_paused(env: &Env, bit: u32) -> bool {
    let state = get_state(env);
    let expired = bit == WITHDRAWALS
        && state
            .until
            .is_some_and(|until| env.ledger().sequence() >= until);

    state.flags & bit != 0 && !expired
}

/// Returns the pool bit that governs a transaction moving `ext_amount`.
///
/// A positive amount is a deposit, a negative one a withdrawal, and zero a
/// transfer between notes already inside the pool.
pub fn shape_bit(env: &Env, ext_amount: &I256) -> u32 {
    let zero = I256::from_i32(env, 0);
    if *ext_amount > zero {
        DEPOSITS
    } else if *ext_amount < zero {
        WITHDRAWALS
    } else {
        TRANSFERS
    }
}

fn check_flags(flags: u32, mask: u32) -> Result<(), PauseError> {
    if flags == 0 || flags & !mask != 0 {
        Err(PauseError::InvalidFlags)
    } else {
        Ok(())
    }
}

fn store(env: &Env, state: &PauseState) {
    env.storage().persistent().set(&PausableKey::Pause, state);
    bump_entry(env, &PausableKey::Pause);
    PauseChanged {
        flags: state.flags,
        until: state.until,
    }
    .publish(env);
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ttl::{EXTEND_TO, THRESHOLD};
    use soroban_sdk::{
        Address, contract, contracterror, contractimpl,
        events::Event,
        testutils::{Events, Ledger as _, storage::Persistent as _},
    };

    /// Contract-facing form of [`PauseError`], so the probe's failures cross
    /// the host boundary the way a real target's do.
    #[contracterror]
    #[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
    #[repr(u32)]
    enum ProbeError {
        InvalidFlags = 1,
        TimedPauseArmed = 2,
    }

    impl From<PauseError> for ProbeError {
        fn from(error: PauseError) -> Self {
            match error {
                PauseError::InvalidFlags => Self::InvalidFlags,
                PauseError::TimedPauseArmed => Self::TimedPauseArmed,
            }
        }
    }

    #[contract]
    struct PauseProbe;

    #[contractimpl]
    impl PauseProbe {
        pub fn pause(
            env: Env,
            flags: u32,
            until: Option<u32>,
            mask: u32,
        ) -> Result<(), ProbeError> {
            super::pause(&env, flags, until, mask).map_err(ProbeError::from)
        }

        pub fn unpause(env: Env, flags: u32, mask: u32) -> Result<(), ProbeError> {
            super::unpause(&env, flags, mask).map_err(ProbeError::from)
        }

        pub fn state(env: Env) -> PauseState {
            get_state(&env)
        }

        pub fn paused(env: Env, bit: u32) -> bool {
            is_paused(&env, bit)
        }
    }

    fn probe(env: &Env) -> (Address, PauseProbeClient<'_>) {
        let id = env.register(PauseProbe, ());
        let client = PauseProbeClient::new(env, &id);
        (id, client)
    }

    #[test]
    fn shape_bit_reads_the_sign_of_the_external_amount() {
        let env = Env::default();

        assert_eq!(shape_bit(&env, &I256::from_i32(&env, 500)), DEPOSITS);
        assert_eq!(shape_bit(&env, &I256::from_i32(&env, 0)), TRANSFERS);
        assert_eq!(shape_bit(&env, &I256::from_i32(&env, -300)), WITHDRAWALS);
    }

    #[test]
    fn pause_rejects_flags_outside_the_mask() {
        let env = Env::default();
        let (_, client) = probe(&env);

        assert_eq!(
            client.try_pause(&8u32, &None, &POOL_MASK),
            Err(Ok(ProbeError::InvalidFlags))
        );
    }

    #[test]
    fn pause_rejects_zero_flags() {
        let env = Env::default();
        let (_, client) = probe(&env);

        assert_eq!(
            client.try_pause(&0u32, &None, &POOL_MASK),
            Err(Ok(ProbeError::InvalidFlags))
        );
        assert_eq!(
            client.try_unpause(&0u32, &POOL_MASK),
            Err(Ok(ProbeError::InvalidFlags))
        );
    }

    #[test]
    fn the_mutations_mask_accepts_only_its_own_bit() {
        let env = Env::default();
        let (_, client) = probe(&env);

        client.pause(&MUTATIONS, &None, &MUTATIONS);

        assert_eq!(client.state().flags, MUTATIONS);
        assert_eq!(
            client.try_pause(&TRANSFERS, &None, &MUTATIONS),
            Err(Ok(ProbeError::InvalidFlags))
        );
    }

    #[test]
    fn a_fresh_state_pauses_nothing() {
        let env = Env::default();
        let (_, client) = probe(&env);

        assert_eq!(
            client.state(),
            PauseState {
                flags: 0,
                until: None,
                armed: false,
            }
        );
        for bit in [DEPOSITS, TRANSFERS, WITHDRAWALS] {
            assert!(!client.paused(&bit));
        }
    }

    #[test]
    fn a_timed_pause_records_the_ledger_and_arms() {
        let env = Env::default();
        let (_, client) = probe(&env);

        client.pause(&WITHDRAWALS, &Some(500), &POOL_MASK);

        assert_eq!(
            client.state(),
            PauseState {
                flags: WITHDRAWALS,
                until: Some(500),
                armed: true,
            }
        );
        assert!(client.paused(&WITHDRAWALS));
    }

    #[test]
    fn a_second_timed_pause_is_refused_while_armed() {
        let env = Env::default();
        let (_, client) = probe(&env);
        client.pause(&WITHDRAWALS, &Some(500), &POOL_MASK);

        assert_eq!(
            client.try_pause(&DEPOSITS, &Some(900), &POOL_MASK),
            Err(Ok(ProbeError::TimedPauseArmed))
        );
        assert_eq!(client.state().until, Some(500));
        assert_eq!(client.state().flags, WITHDRAWALS);
    }

    #[test]
    fn an_untimed_pause_keeps_the_flags_and_clears_the_arm() {
        let env = Env::default();
        let (_, client) = probe(&env);
        client.pause(&WITHDRAWALS, &Some(500), &POOL_MASK);

        client.pause(&DEPOSITS, &None, &POOL_MASK);

        assert_eq!(
            client.state(),
            PauseState {
                flags: DEPOSITS | WITHDRAWALS,
                until: None,
                armed: false,
            }
        );
    }

    #[test]
    fn unpause_clears_only_the_named_bits() {
        let env = Env::default();
        let (_, client) = probe(&env);
        client.pause(&POOL_MASK, &None, &POOL_MASK);

        client.unpause(&DEPOSITS, &POOL_MASK);

        assert_eq!(client.state().flags, TRANSFERS | WITHDRAWALS);
    }

    #[test]
    fn unpause_of_unset_bits_still_clears_the_timed_pause() {
        let env = Env::default();
        let (_, client) = probe(&env);
        client.pause(&WITHDRAWALS, &Some(500), &POOL_MASK);

        client.unpause(&DEPOSITS, &POOL_MASK);

        assert_eq!(
            client.state(),
            PauseState {
                flags: WITHDRAWALS,
                until: None,
                armed: false,
            }
        );
    }

    #[test]
    fn withdrawals_stop_being_honored_at_the_recorded_ledger() {
        let env = Env::default();
        let (_, client) = probe(&env);
        let until = env.ledger().sequence().saturating_add(10);
        client.pause(&POOL_MASK, &Some(until), &POOL_MASK);

        env.ledger().set_sequence_number(until.saturating_sub(1));
        assert!(client.paused(&WITHDRAWALS));

        env.ledger().set_sequence_number(until);
        assert!(!client.paused(&WITHDRAWALS));
        assert!(client.paused(&DEPOSITS));
        assert!(client.paused(&TRANSFERS));
    }

    /// The one sequence in which a user who watched withdrawals reopen finds
    /// them shut again, and with no deadline the second time.
    #[test]
    fn an_untimed_pause_reshuts_withdrawals_that_the_timer_released() {
        let env = Env::default();
        let (_, client) = probe(&env);
        let until = env.ledger().sequence().saturating_add(10);
        client.pause(&WITHDRAWALS, &Some(until), &POOL_MASK);
        env.ledger().set_sequence_number(until);
        assert!(!client.paused(&WITHDRAWALS));

        client.pause(&DEPOSITS, &None, &POOL_MASK);

        assert!(client.paused(&WITHDRAWALS));
        assert_eq!(client.state().until, None);
    }

    #[test]
    fn a_ledger_already_past_never_honors_withdrawals_but_still_arms() {
        let env = Env::default();
        env.ledger().set_sequence_number(1_000);
        let (_, client) = probe(&env);

        client.pause(&POOL_MASK, &Some(500), &POOL_MASK);

        assert!(!client.paused(&WITHDRAWALS));
        assert!(client.paused(&DEPOSITS));
        assert!(client.state().armed);
    }

    #[test]
    fn pause_emits_pause_changed() {
        let env = Env::default();
        let (id, client) = probe(&env);

        client.pause(&DEPOSITS, &Some(500), &POOL_MASK);

        let events = env.events().all();
        assert_eq!(events.events().len(), 1);
        let expected = PauseChanged {
            flags: DEPOSITS,
            until: Some(500),
        }
        .to_xdr(&env, &id);
        assert_eq!(events.events()[0], expected);
    }

    #[test]
    fn unpause_emits_pause_changed() {
        let env = Env::default();
        let (id, client) = probe(&env);
        client.pause(&(DEPOSITS | TRANSFERS), &None, &POOL_MASK);

        client.unpause(&DEPOSITS, &POOL_MASK);

        let events = env.events().all();
        assert_eq!(events.events().len(), 1);
        let expected = PauseChanged {
            flags: TRANSFERS,
            until: None,
        }
        .to_xdr(&env, &id);
        assert_eq!(events.events()[0], expected);
    }

    #[test]
    fn get_state_extends_the_entry() {
        let env = Env::default();
        let (id, client) = probe(&env);
        client.pause(&DEPOSITS, &None, &POOL_MASK);
        let decayed = env
            .ledger()
            .sequence()
            .saturating_add(EXTEND_TO.saturating_sub(THRESHOLD).saturating_add(1));
        env.ledger().set_sequence_number(decayed);

        client.state();

        let ttl = env.as_contract(&id, || {
            env.storage().persistent().get_ttl(&PausableKey::Pause)
        });
        assert_eq!(ttl, EXTEND_TO);
    }
}
