//! Shared utilities for shielded pool state modules.
//!
//! Literal port of the pure-logic portions of `app/js/state/utils.js` and
//! `app/js/state/retention-verifier.js`. No Stellar RPC calls; no DB access.

// ---------------------------------------------------------------------------
// Tree constants — must match circuit and contract deployments.
// ---------------------------------------------------------------------------

/// Depth of the shielded pool Merkle tree.
pub const TREE_DEPTH: usize = 10;

/// Depth of the ASP sparse Merkle tree.
pub const SMT_DEPTH: usize = 10;

// ---------------------------------------------------------------------------
// Ledger / retention constants (from retention-verifier.js).
// ---------------------------------------------------------------------------

/// Seconds between ledger closes (Stellar protocol).
pub const LEDGER_RATE_SECONDS: u32 = 5;

/// Approximate ledger count for 24 hours (`24 * 60 * 60 / 5`).
pub const LEDGERS_24H: u32 = 17_280;

/// Approximate ledger count for 7 days (`7 * 24 * 60 * 60 / 5`).
pub const LEDGERS_7D: u32 = 120_960;

/// Ledger range used when probing RPC event retention.
pub const RETENTION_PROBE_SPAN: u32 = 32;

// ---------------------------------------------------------------------------
// Hex utilities.
// ---------------------------------------------------------------------------

/// Decodes a hex string (with or without `0x` prefix) to bytes.
///
/// Returns an error on invalid hex characters or odd-length input.
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, ::hex::FromHexError> {
    let stripped = hex.strip_prefix("0x").unwrap_or(hex);
    ::hex::decode(stripped)
}

/// Encodes bytes as a `0x`-prefixed lowercase hex string.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    format!("0x{}", ::hex::encode(bytes))
}

/// Ensures a hex string has a `0x` prefix.
pub fn normalize_hex(hex: &str) -> String {
    if hex.starts_with("0x") {
        hex.to_owned()
    } else {
        format!("0x{hex}")
    }
}

/// Decodes a big-endian hex string and reverses the bytes to little-endian,
/// as required for Rust Merkle tree insertion (`from_le_bytes_mod_order`).
///
/// Soroban stores U256 as big-endian; the Rust Merkle tree uses little-endian.
pub fn hex_to_bytes_for_tree(hex: &str) -> Result<Vec<u8>, ::hex::FromHexError> {
    let mut bytes = hex_to_bytes(hex)?;
    bytes.reverse();
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// Duration formatting (from retention-verifier.js: `ledgersToDuration`).
// ---------------------------------------------------------------------------

/// Converts a ledger count to a human-readable duration string.
///
/// Examples: `120960` → `"7d"`, `17280` → `"1d"`, `360` → `"30m"`.
pub fn ledgers_to_duration(ledgers: u32) -> String {
    let seconds = u64::from(ledgers).saturating_mul(u64::from(LEDGER_RATE_SECONDS));
    let hours = seconds / 3600;
    let days = hours / 24;

    if days > 0 {
        let remaining_hours = hours % 24;
        if remaining_hours > 0 {
            format!("{days}d {remaining_hours}h")
        } else {
            format!("{days}d")
        }
    } else if hours > 0 {
        let minutes = (seconds % 3600) / 60;
        if minutes > 0 {
            format!("{hours}h {minutes}m")
        } else {
            format!("{hours}h")
        }
    } else {
        let minutes = seconds / 60;
        format!("{minutes}m")
    }
}
