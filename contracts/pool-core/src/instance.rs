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
/// persistent entry to there, so on mainnet the instance tracks the tree entry
/// that every insertion rewrites.
///
/// Other networks set that floor lower — testnet uses 120,960 — so there the
/// instance outlives the tree and the first call after a decay pays rent for
/// more lifetime than the tree holds. That is deliberate: one constant is worth
/// more than matching each network's floor, and the overshoot costs rent only
/// where entries are cheap.
///
/// Both networks cap `max_entry_ttl` at 3,110,400 and the host traps above it,
/// so this must stay at or below that. Values read from testnet and mainnet on
/// 2026-09-21.
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
