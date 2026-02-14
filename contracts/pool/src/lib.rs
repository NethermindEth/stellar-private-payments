//! Privacy pool contract for Stellar private transactions.
#![no_std]
#![allow(
    missing_docs,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::unwrap_used
)]

pub mod merkle_with_history;
pub mod pool;

pub use pool::*;

#[cfg(test)]
mod test;
