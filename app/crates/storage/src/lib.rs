//! Unified SQLite storage for the shielded pool.
//!
//! [`Storage`] compiles to two backends selected by target architecture:
//! - **Native**: `rusqlite` (CLI, tests)
//! - **WASM**: in-memory `BTreeMap`s (temporary — to be replaced with `sqlite-wasm-rs` + OPFS)

/// Storage types mirroring the JS `@typedef` objects in `app/js/state/`.
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
