//! Global View Key (GVK) mode and ciphertext types.
//!
//! Mirrors `pool::policy`'s style: a small discrete mode plus pure
//! validation functions. Unlike `PolicyFlags`, view-only and traceable are
//! mutually exclusive: a pool that wants GVK off is simply deployed from
//! `contracts/pool`

use soroban_sdk::{U256, contracttype};

/// Only output notes are encrypted under the admin view key.
pub const VIEW_ONLY: u32 = 1;
/// Both input and output notes are encrypted under the admin view key.
pub const TRACEABLE: u32 = 2;

/// Whether `mode` is one of the two supported GVK modes.
pub fn is_valid(mode: u32) -> bool {
    mode == VIEW_ONLY || mode == TRACEABLE
}

/// Whether `mode` requires input notes to be encrypted (traceable only).
pub fn requires_input_encryption(mode: u32) -> bool {
    mode == TRACEABLE
}

/// A Baby JubJub curve point, stored as raw, unvalidated coordinates.
///
/// The GVK circuits already run `BabyCheck` plus a low-order/cofactor guard
/// on every proof's public `D` input, so no redundant on-chain validation is
/// needed here — the same precedent `public-key-registry` sets by storing
/// raw, unvalidated key bytes.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BabyJubJubPoint {
    pub x: U256,
    pub y: U256,
}

/// A single note's Global View Key ciphertext: ephemeral key `R` and the
/// three masked field elements. Field names mirror
/// `sdk/types::GlobalViewKeyCiphertext` (no code sharing is possible since
/// this crate is `#![no_std]`), keeping future `contract_state.rs`/indexer
/// mapping mechanical.
#[contracttype]
#[derive(Clone)]
pub struct GvkCiphertext {
    pub r: BabyJubJubPoint,
    pub c1: U256,
    pub c2: U256,
    pub c3: U256,
}

#[cfg(test)]
mod test {
    use super::{TRACEABLE, VIEW_ONLY, is_valid, requires_input_encryption};

    #[test]
    fn view_only_and_traceable_are_valid() {
        assert!(is_valid(VIEW_ONLY));
        assert!(is_valid(TRACEABLE));
    }

    #[test]
    fn anything_else_is_invalid() {
        assert!(!is_valid(0));
        assert!(!is_valid(3));
        assert!(!is_valid(u32::MAX));
    }

    #[test]
    fn only_traceable_requires_input_encryption() {
        assert!(!requires_input_encryption(VIEW_ONLY));
        assert!(requires_input_encryption(TRACEABLE));
    }
}
