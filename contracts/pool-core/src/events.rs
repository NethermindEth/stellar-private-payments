//! Events both pools publish, so clients decode one schema.

use soroban_sdk::contractevent;

/// The event a pool publishes each time its deposit flag changes.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DepositPauseChanged {
    /// `true` while the pool refuses deposits.
    pub paused: bool,
}

/// The event a pool publishes when the admin pauses an already paused pool.
///
/// The call writes nothing, so this event is the only record that it spent
/// the admin's authorization, such as a second pre-signed pause.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DepositPauseRepeated;
