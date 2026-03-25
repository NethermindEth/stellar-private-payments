//! Integration tests for the `utils` crate.

use utils::{
    LEDGER_RATE_SECONDS, LEDGERS_7D, LEDGERS_24H, RETENTION_PROBE_SPAN, SMT_DEPTH, TREE_DEPTH,
    bytes_to_hex, hex_to_bytes, hex_to_bytes_for_tree, ledgers_to_duration, normalize_hex,
};

// Shared test data — typed by declaration, no inline suffixes needed.
const TEST_HEX: &str = "0xdeadbeef";
const TEST_BYTES: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
const TEST_BYTES_LE: [u8; 4] = [0xef, 0xbe, 0xad, 0xde]; // TEST_BYTES reversed

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_match_js() {
    assert_eq!(TREE_DEPTH, 10);
    assert_eq!(SMT_DEPTH, 10);
    assert_eq!(LEDGER_RATE_SECONDS, 5);
    assert_eq!(LEDGERS_24H, 17_280);
    assert_eq!(LEDGERS_7D, 120_960);
    assert_eq!(RETENTION_PROBE_SPAN, 32);
}

// ---------------------------------------------------------------------------
// Hex utilities
// ---------------------------------------------------------------------------

#[test]
fn hex_encode_decode_roundtrip() {
    // bytes → hex → bytes
    assert_eq!(bytes_to_hex(&TEST_BYTES), TEST_HEX);
    assert_eq!(hex_to_bytes(TEST_HEX).expect("valid hex"), TEST_BYTES);
    // strip_prefix: with and without 0x produce the same result
    assert_eq!(
        hex_to_bytes("deadbeef").expect("no prefix"),
        hex_to_bytes(TEST_HEX).expect("with prefix")
    );
}

#[test]
fn hex_to_bytes_error_cases() {
    assert!(hex_to_bytes("0xZZ").is_err(), "invalid chars should fail");
    assert!(hex_to_bytes("abc").is_err(), "odd-length should fail");
}

#[test]
fn normalize_hex_ensures_prefix() {
    assert_eq!(normalize_hex("deadbeef"), TEST_HEX);
    assert_eq!(normalize_hex(TEST_HEX), TEST_HEX); // idempotent
}

#[test]
fn hex_to_bytes_for_tree_reverses_be_to_le() {
    // Soroban stores U256 big-endian; Rust Merkle tree uses little-endian.
    assert_eq!(
        hex_to_bytes_for_tree(TEST_HEX).expect("valid hex"),
        TEST_BYTES_LE
    );
}

// ---------------------------------------------------------------------------
// Duration formatting
// ---------------------------------------------------------------------------

#[test]
fn ledgers_to_duration_covers_all_branches() {
    // days only: 120960 * 5s = 604800s = 7d
    assert_eq!(ledgers_to_duration(LEDGERS_7D), "7d");
    // days + hours: 18000 * 5s = 90000s = 1d 1h
    assert_eq!(ledgers_to_duration(18_000), "1d 1h");
    // hours + minutes: 840 * 5s = 4200s = 1h 10m
    assert_eq!(ledgers_to_duration(840), "1h 10m");
    // hours only: 720 * 5s = 3600s = 1h
    assert_eq!(ledgers_to_duration(720), "1h");
    // minutes only: 360 * 5s = 1800s = 30m
    assert_eq!(ledgers_to_duration(360), "30m");
}
