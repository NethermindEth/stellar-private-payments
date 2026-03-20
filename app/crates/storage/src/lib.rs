//! Unified SQLite storage for the shielded pool.
//!
//! Native: `rusqlite`. WASM: in-memory `BTreeMap`s (temporary).

/// Storage types.
pub mod types;

#[cfg(not(target_arch = "wasm32"))]
mod native;
#[cfg(target_arch = "wasm32")]
mod wasm;

#[cfg(not(target_arch = "wasm32"))]
pub use native::Storage;
#[cfg(target_arch = "wasm32")]
pub use wasm::Storage;

pub(crate) const SCHEMA: &str = include_str!("schema.sql");
