//! Drive async SDK calls to completion from the synchronous CLI.
//!
//! The SDK's blocking wrapper keeps its runtime private, so commands that use
//! the async `StateFetcher` directly (e.g. `register`) own a
//! short-lived Tokio runtime for their RPC round-trips.

use std::future::Future;

use anyhow::{Context, Result};

pub fn block_on<F: Future>(fut: F) -> Result<F::Output> {
    let runtime = tokio::runtime::Runtime::new().context("init tokio runtime")?;
    Ok(runtime.block_on(fut))
}
