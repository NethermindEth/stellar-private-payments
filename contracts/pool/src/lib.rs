#![no_std]
pub mod pool;

// `merkle_with_history`/`policy` now live in `pool-core`, shared with
// `pool-gvk`. Re-exported under their original paths so `pool::policy` and
// `pool::merkle_with_history` keep working for existing consumers.
pub use pool_core::{merkle_with_history, policy};

pub use pool::*;

#[cfg(test)]
mod test;
