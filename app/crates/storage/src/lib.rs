//! Unified SQLite storage for the shielded pool.
//!
//! Currently native-only (`rusqlite`).
//! TODO: WASM backend (`sqlite-wasm-rs` + OPFS) — added when `app/js/state/db.js` is replaced.

/// Storage types.
pub mod types;

mod native;
pub use native::Storage;

pub(crate) const SCHEMA: &str = include_str!("schema.sql");
