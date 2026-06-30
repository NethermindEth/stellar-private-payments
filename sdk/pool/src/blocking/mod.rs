//! Synchronous private-pool API
//!
//! **Do not call this from inside an existing Tokio runtime**. It will
//! intentionally panic.
//! Use [`crate::PrivatePool`] with `.await` in async code instead.

mod pool;
mod runtime;

pub use pool::PrivatePool;