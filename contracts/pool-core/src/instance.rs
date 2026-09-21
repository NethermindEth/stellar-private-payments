//! Keeping the contract instance alive for as long as the tree it configures.
//!
//! The pool keeps its configuration — the token, the verifier, the association
//! set addresses, the deposit cap, the policy flags and the tree depth — in the
//! contract instance, and its tree in one persistent entry. Every insertion
//! rewrites the tree entry, so the host bumps that entry's lifetime to the
//! network's floor each time. Nothing rewrites the instance after the
//! constructor, so its lifetime only decays.
//!
//! That asymmetry ends with the contract archived while its tree is still live,
//! and an archived instance takes every entry point with it rather than one
//! key. Restoring the instance on the same schedule as the tree keeps the two
//! on one clock.

use soroban_sdk::Env;

/// Ledgers of instance lifetime an entry point restores.
///
/// This is mainnet's `min_persistent_ttl`, the floor the host bumps a written
/// persistent entry to, so the instance tracks the tree entry that every
/// insertion rewrites. It must stay at or below the network's `max_entry_ttl`,
/// which the host enforces by trapping, so a network configured with a lower
/// ceiling needs this lowered to match.
pub const INSTANCE_LIFETIME_LEDGERS: u32 = 2_073_600;

/// Restores the instance's lifetime when it has decayed below
/// [`INSTANCE_LIFETIME_LEDGERS`].
///
/// Call this from every entry point that reads the configuration without
/// writing it. The host charges rent only when the extension actually moves
/// the entry's lifetime, so a call that follows a recent one costs nothing.
pub fn extend_instance(env: &Env) {
    env.storage()
        .instance()
        .extend_ttl(INSTANCE_LIFETIME_LEDGERS, INSTANCE_LIFETIME_LEDGERS);
}
