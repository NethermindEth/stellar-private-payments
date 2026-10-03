//! Events both pools publish, so clients decode one schema.

use soroban_sdk::{Address, contractevent};

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

/// The event a pool publishes each time the admin sets the allowlist it reads.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AspMembershipUpdated {
    /// The allowlist the pool read before the change.
    pub old_tree: Address,
    /// The allowlist the pool reads after the change.
    pub new_tree: Address,
}

/// The event a pool publishes each time the admin sets the blocklist it reads.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AspNonMembershipUpdated {
    /// The blocklist the pool read before the change.
    pub old_tree: Address,
    /// The blocklist the pool reads after the change.
    pub new_tree: Address,
}
