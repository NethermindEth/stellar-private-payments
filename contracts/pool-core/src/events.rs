//! Events both pools publish, so clients decode one schema.

use soroban_sdk::contractevent;

/// The event a pool publishes each time its deposit flag changes.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DepositPauseChanged {
    /// `true` while the pool refuses deposits.
    pub paused: bool,
}

/// The event a pool publishes when a pause or unpause leaves its deposit flag
/// unchanged.
///
/// It records that the call spent the admin's authorization, such as a
/// pre-signed pause.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DepositPauseRepeated {
    /// `true` while the pool refuses deposits.
    pub paused: bool,
}
