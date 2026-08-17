#![no_std]
pub mod gvk;
pub mod pool_gvk;

// Shared with `contracts/pool` via `pool-core`. Re-exported under their
// original paths so `pool_gvk::policy`/`pool_gvk::merkle_with_history`
// keep resolving.
pub use pool_core::{merkle_with_history, policy};

pub use pool_gvk::*;

#[cfg(test)]
mod test;
