//! Integration tests for the `public-key-store` crate.

use public_key_store::PublicKeyStore;
use storage::Storage;

const ADDR_A: &str = "GABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQ";
const ADDR_B: &str = "GBCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQR";
const ENC_KEY: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
const NOTE_KEY: &str = "0x2222222222222222222222222222222222222222222222222222222222222222";
const LEGACY_KEY: &str = "0x3333333333333333333333333333333333333333333333333333333333333333";
const TS: &str = "2026-03-26T12:00:00Z";

const LEDGER_A: u32 = 50_000_100;
const LEDGER_B: u32 = 50_000_200;

fn open() -> PublicKeyStore {
    let db = Storage::open_in_memory().expect("open storage");
    PublicKeyStore::open(db)
}

#[test]
fn empty_store() {
    let store = open();
    assert_eq!(store.count().expect("count"), 0);
    assert!(store.get_by_address(ADDR_A).expect("get").is_none());
}

#[test]
fn store_and_retrieve_registration() {
    let store = open();
    store
        .store_registration(ADDR_A, ENC_KEY, NOTE_KEY, LEDGER_A, TS)
        .expect("store");

    let entry = store
        .get_by_address(ADDR_A)
        .expect("get")
        .expect("should exist");
    assert_eq!(entry.address, ADDR_A);
    assert_eq!(entry.encryption_key, ENC_KEY);
    assert_eq!(entry.note_key, NOTE_KEY);
    assert_eq!(entry.public_key, ENC_KEY); // legacy alias
    assert_eq!(entry.ledger, LEDGER_A);
    assert_eq!(store.count().expect("count"), 1);
}

#[test]
fn legacy_registration_sets_both_keys() {
    let store = open();
    store
        .store_legacy_registration(ADDR_A, LEGACY_KEY, LEDGER_A, TS)
        .expect("store legacy");

    let entry = store
        .get_by_address(ADDR_A)
        .expect("get")
        .expect("should exist");
    assert_eq!(entry.encryption_key, LEGACY_KEY);
    assert_eq!(entry.note_key, LEGACY_KEY);
    assert_eq!(entry.public_key, LEGACY_KEY);
}

#[test]
fn get_all_returns_descending_ledger_order() {
    let store = open();
    store
        .store_registration(ADDR_A, ENC_KEY, NOTE_KEY, LEDGER_A, TS)
        .expect("store A");
    store
        .store_registration(ADDR_B, ENC_KEY, NOTE_KEY, LEDGER_B, TS)
        .expect("store B");

    let all = store.get_all().expect("get_all");
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].ledger, LEDGER_B); // most recent first
    assert_eq!(all[1].ledger, LEDGER_A);
}

#[test]
fn upsert_overwrites_existing() {
    let store = open();
    store
        .store_registration(ADDR_A, ENC_KEY, NOTE_KEY, LEDGER_A, TS)
        .expect("store first");
    store
        .store_registration(ADDR_A, LEGACY_KEY, LEGACY_KEY, LEDGER_B, TS)
        .expect("store update");

    assert_eq!(store.count().expect("count"), 1);
    let entry = store
        .get_by_address(ADDR_A)
        .expect("get")
        .expect("should exist");
    assert_eq!(entry.encryption_key, LEGACY_KEY);
    assert_eq!(entry.ledger, LEDGER_B);
}

#[test]
fn clear_removes_all() {
    let store = open();
    store
        .store_registration(ADDR_A, ENC_KEY, NOTE_KEY, LEDGER_A, TS)
        .expect("store");
    store.clear().expect("clear");

    assert_eq!(store.count().expect("count"), 0);
    assert!(store.get_by_address(ADDR_A).expect("get").is_none());
}
