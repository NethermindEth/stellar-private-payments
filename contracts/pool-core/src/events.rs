//! Events both pools publish, so a client reads one schema whichever pool
//! raised them.

use soroban_sdk::contractevent;

/// The event a pool publishes each time its deposit flag changes.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DepositPauseChanged {
    /// The new value: `true` while the pool refuses deposits.
    pub paused: bool,
}

/// The event a pool publishes when the admin pauses deposits that are already
/// paused.
///
/// That call writes nothing, so this event is what shows a watcher following
/// the pool's events that the admin's authorization was spent, as when a
/// pre-signed pause lands after another pause.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DepositPauseRepeated;
