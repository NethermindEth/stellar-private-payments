//! Integration tests for the `utils` crate.

use utils::{
    LEDGERS_7D, LEDGERS_24H, TREE_DEPTH, bytes_to_hex, field_to_hex, hex_to_bytes,
    hex_to_bytes_for_tree, ledgers_to_duration, normalize_hex,
};

#[test]
fn constants_match_js() {
    assert_eq!(TREE_DEPTH, 10);
    assert_eq!(LEDGERS_24H, 17_280);
    assert_eq!(LEDGERS_7D, 120_960);
}

#[test]
fn hex_roundtrip() {
    let bytes: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
    let hex = "0xdeadbeef";

    // encode → decode
    assert_eq!(bytes_to_hex(&bytes), hex);
    assert_eq!(hex_to_bytes(hex).expect("decode"), bytes);
    assert_eq!(hex_to_bytes("deadbeef").expect("no prefix"), bytes);

    // normalize
    assert_eq!(normalize_hex("deadbeef"), hex);
    assert_eq!(normalize_hex(hex), hex);

    // BE hex ↔ LE bytes (tree encoding)
    let le: [u8; 4] = [0xef, 0xbe, 0xad, 0xde];
    assert_eq!(hex_to_bytes_for_tree(hex).expect("tree"), le);
    assert_eq!(field_to_hex(&le), hex);

    // errors
    assert!(hex_to_bytes("0xZZ").is_err());
    assert!(hex_to_bytes("abc").is_err());
}

#[test]
fn ledgers_to_duration_formatting() {
    assert_eq!(ledgers_to_duration(LEDGERS_7D), "7d");
    assert_eq!(ledgers_to_duration(18_000), "1d 1h");
    assert_eq!(ledgers_to_duration(840), "1h 10m");
    assert_eq!(ledgers_to_duration(720), "1h");
    assert_eq!(ledgers_to_duration(360), "30m");
}
