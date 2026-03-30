//! Integration tests for the `public-key-store` crate.

use public_key_store::PublicKeyStore;
use std::rc::Rc;
use storage::Storage;

const ADDR_A: &str = "GABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQ";
const ADDR_B: &str = "GBCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQR";
const ENC_KEY: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
const NOTE_KEY: &str = "0x2222222222222222222222222222222222222222222222222222222222222222";
const TS: &str = "2026-03-26T12:00:00Z";
const LEDGER_A: u32 = 50_000_100;
const LEDGER_B: u32 = 50_000_200;

fn open() -> PublicKeyStore {
    let db = Rc::new(Storage::open_in_memory().expect("open storage"));
    PublicKeyStore::open(db)
}

#[test]
fn store_and_retrieve() {
    let store = open();
    assert_eq!(store.count().expect("count"), 0);

    store
        .store_registration(ADDR_A, ENC_KEY, NOTE_KEY, LEDGER_A, TS)
        .expect("store");
    let entry = store.get_by_address(ADDR_A).expect("get").expect("exists");
    assert_eq!(entry.encryption_key, ENC_KEY);
    assert_eq!(entry.note_key, NOTE_KEY);
    assert_eq!(entry.public_key, ENC_KEY); // legacy alias
    assert_eq!(store.count().expect("count"), 1);
}

#[test]
fn get_all_descending_order() {
    let store = open();
    store
        .store_registration(ADDR_A, ENC_KEY, NOTE_KEY, LEDGER_A, TS)
        .expect("A");
    store
        .store_registration(ADDR_B, ENC_KEY, NOTE_KEY, LEDGER_B, TS)
        .expect("B");

    let all = store.get_all().expect("get_all");
    assert_eq!(all[0].ledger, LEDGER_B);
    assert_eq!(all[1].ledger, LEDGER_A);
}

#[test]
fn upsert_overwrites() {
    let store = open();
    store
        .store_registration(ADDR_A, ENC_KEY, NOTE_KEY, LEDGER_A, TS)
        .expect("first");
    store
        .store_registration(ADDR_A, NOTE_KEY, NOTE_KEY, LEDGER_B, TS)
        .expect("update");

    assert_eq!(store.count().expect("count"), 1);
    let entry = store.get_by_address(ADDR_A).expect("get").expect("exists");
    assert_eq!(entry.encryption_key, NOTE_KEY);
}

#[test]
fn clear() {
    let store = open();
    store
        .store_registration(ADDR_A, ENC_KEY, NOTE_KEY, LEDGER_A, TS)
        .expect("store");
    store.clear().expect("clear");
    assert_eq!(store.count().expect("count"), 0);
}
