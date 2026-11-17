//! Global View Key (GVK) mode and ciphertext types.
//!
//! Mirrors `pool::policy`'s style: a small discrete mode plus pure
//! validation functions. Unlike `PolicyFlags`, view-only and traceable are
//! mutually exclusive: a pool that wants GVK off is simply deployed from
//! `contracts/pool`

use soroban_sdk::{U256, contracttype, crypto::bn254::Bn254Fr};

/// Baby JubJub twisted Edwards coefficients: `a·x² + y² = 1 + d·x²·y²` over
/// the BN254 scalar field.
pub const CURVE_A: u32 = 168700;
pub const CURVE_D: u32 = 168696;

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

/// Affine coordinates of a Baby JubJub point.
///
/// The type itself carries no guarantee: ciphertext `R` points are circuit
/// outputs and are stored as received, while the admin view key is checked
/// once at construction.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BabyJubJubPoint {
    pub x: U256,
    pub y: U256,
}

impl BabyJubJubPoint {
    /// Whether the point satisfies the curve equation.
    ///
    /// Coordinates must already be below the field modulus: `Bn254Fr`
    /// reduces larger values silently.
    pub fn is_on_curve(&self) -> bool {
        let env = self.x.env();
        let bn254 = env.crypto().bn254();
        let fr = |v: u32| Bn254Fr::from_u256(U256::from_u32(env, v));
        let x = Bn254Fr::from_u256(self.x.clone());
        let y = Bn254Fr::from_u256(self.y.clone());
        let x2 = bn254.fr_mul(&x, &x);
        let y2 = bn254.fr_mul(&y, &y);
        let lhs = bn254.fr_add(&bn254.fr_mul(&fr(CURVE_A), &x2), &y2);
        let dx2y2 = bn254.fr_mul(&fr(CURVE_D), &bn254.fr_mul(&x2, &y2));
        let rhs = bn254.fr_add(&fr(1), &dx2y2);
        lhs.as_u256() == rhs.as_u256()
    }

    /// Whether `8·P` is the identity, for a point on the curve.
    ///
    /// These are the eight points with `x = 0` (orders 1 and 2), `y = 0`
    /// (order 4) or `y² = a·x²` (order 8: their double has `y = 0`).
    pub fn has_small_order(&self) -> bool {
        let env = self.x.env();
        let zero = U256::from_u32(env, 0);
        if self.x == zero || self.y == zero {
            return true;
        }
        let bn254 = env.crypto().bn254();
        let a = Bn254Fr::from_u256(U256::from_u32(env, CURVE_A));
        let x = Bn254Fr::from_u256(self.x.clone());
        let y = Bn254Fr::from_u256(self.y.clone());
        let ax2 = bn254.fr_mul(&a, &bn254.fr_mul(&x, &x));
        bn254.fr_mul(&y, &y).as_u256() == ax2.as_u256()
    }
}

/// A single note's Global View Key ciphertext: ephemeral key `R` and the
/// three masked field elements. Field names mirror
/// `stellar_private_payments::types::GlobalViewKeyCiphertext` (no code sharing
/// is possible since this crate is `#![no_std]`), keeping future
/// `contract_state.rs`/indexer mapping mechanical.
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
