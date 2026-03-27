//! Unified SQLite storage for the shielded pool.

/// Storage types.
pub mod types;

#[cfg(not(target_arch = "wasm32"))]
mod native;
#[cfg(not(target_arch = "wasm32"))]
pub use native::Storage;

#[cfg(target_arch = "wasm32")]
mod wasm;
#[cfg(target_arch = "wasm32")]
pub use wasm::Storage;

pub(crate) const SCHEMA: &str = include_str!("schema.sql");
