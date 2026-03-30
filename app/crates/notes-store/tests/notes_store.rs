//! Integration tests for the `notes-store` crate.

use notes_store::{NewNote, NotesStore};
use std::rc::Rc;
use storage::Storage;

const OWNER: &str = "GABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQ";
const COMMIT_A: &str = "0xAAAA000000000000000000000000000000000000000000000000000000000001";
const COMMIT_B: &str = "0xbbbb000000000000000000000000000000000000000000000000000000000002";
const PRIV_KEY: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
const BLINDING: &str = "0x2222222222222222222222222222222222222222222222222222222222222222";
const TS: &str = "2026-03-26T12:00:00Z";
const LEDGER: u32 = 50_000_100;

fn open() -> NotesStore {
    let db = Rc::new(Storage::open_in_memory().expect("open storage"));
    NotesStore::open(db)
}

fn note<'a>(commitment: &'a str, amount: &'a str, index: u32) -> NewNote<'a> {
    NewNote {
        commitment,
        owner: OWNER,
        private_key: PRIV_KEY,
        blinding: BLINDING,
        amount,
        leaf_index: Some(index),
        ledger: LEDGER,
        created_at: TS,
        is_received: false,
    }
}

#[test]
fn save_retrieve_and_normalize() {
    let store = open();
    assert_eq!(store.get_balance(OWNER).expect("bal"), 0);

    // COMMIT_A is uppercase; lookup with lowercase should work.
    let saved = store.save_note(&note(COMMIT_A, "1000", 0)).expect("save");
    assert_eq!(saved.id, COMMIT_A.to_lowercase());
    assert!(!saved.spent);

    let lower = COMMIT_A.to_lowercase();
    assert!(store.get_by_commitment(&lower).expect("get").is_some());
}

#[test]
fn mark_spent() {
    let store = open();
    store.save_note(&note(COMMIT_A, "500", 0)).expect("save");

    assert!(store.mark_spent(COMMIT_A, LEDGER).expect("mark"));
    let n = store
        .get_by_commitment(COMMIT_A)
        .expect("get")
        .expect("exists");
    assert!(n.spent);
    assert_eq!(n.spent_at_ledger, Some(LEDGER));
}

#[test]
fn unspent_and_balance() {
    let store = open();
    store.save_note(&note(COMMIT_A, "100", 0)).expect("A");
    store.save_note(&note(COMMIT_B, "250", 1)).expect("B");
    store.mark_spent(COMMIT_A, LEDGER).expect("spend");

    let unspent = store.get_unspent(OWNER).expect("unspent");
    assert_eq!(unspent.len(), 1);
    assert_eq!(unspent[0].amount, "250");
    assert_eq!(store.get_balance(OWNER).expect("bal"), 250);
}

#[test]
fn delete_and_clear() {
    let store = open();
    store.save_note(&note(COMMIT_A, "100", 0)).expect("A");
    store.save_note(&note(COMMIT_B, "200", 1)).expect("B");

    store.delete(COMMIT_A).expect("delete");
    assert!(store.get_by_commitment(COMMIT_A).expect("get").is_none());

    store.clear().expect("clear");
    assert!(store.get_all().expect("all").is_empty());
}
