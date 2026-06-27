//! Synchronous private-pool API (native only).

use std::future::Future;

mod pool;
mod runtime;

pub use pool::PrivatePool;

/// Block on an async SDK future using the shared native Tokio runtime.
pub fn block_on<F: Future>(future: F) -> F::Output {
    runtime::block_on(future)
}
