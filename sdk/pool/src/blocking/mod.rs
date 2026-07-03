//! Synchronous private-pool API
//!
//! **Do not call this from inside an existing Tokio runtime**. It will
//! intentionally panic.
//! Use [`crate::PrivatePool`] with `.await` in async code instead.

mod chain;
mod pool;
mod runtime;

pub use chain::{confirm_tx, prepare_register, submit_tx};
pub use pool::PrivatePool;
