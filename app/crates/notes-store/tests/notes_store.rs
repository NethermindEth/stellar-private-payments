//! Integration tests for the `notes-store` crate.

use notes_store::{NewNote, NotesStore};
use storage::Storage;

const OWNER: &str = "GABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQ";
const COMMIT_A: &str = "0xaaaa000000000000000000000000000000000000000000000000000000000001";
const COMMIT_B: &str = "0xbbbb000000000000000000000000000000000000000000000000000000000002";
const PRIV_KEY: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
const BLINDING: &str = "0x2222222222222222222222222222222222222222222222222222222222222222";
const TS: &str = "2026-03-26T12:00:00Z";
const LEDGER: u32 = 50_000_100;

fn open() -> NotesStore {
    let db = Storage::open_in_memory().expect("open storage");
    NotesStore::open(db)
}

fn note_a(amount: &str, is_received: bool) -> NewNote<'_> {
    NewNote {
        commitment: COMMIT_A,
        owner: OWNER,
        private_key: PRIV_KEY,
        blinding: BLINDING,
        amount,
        leaf_index: Some(0),
        ledger: LEDGER,
        created_at: TS,
        is_received,
    }
}

fn note_b(amount: &str) -> NewNote<'_> {
    NewNote {
        commitment: COMMIT_B,
        owner: OWNER,
        private_key: PRIV_KEY,
        blinding: BLINDING,
        amount,
        leaf_index: Some(1),
        ledger: LEDGER,
        created_at: TS,
        is_received: false,
    }
}

#[test]
fn empty_store() {
    let store = open();
    assert!(store.get_by_commitment(COMMIT_A).expect("get").is_none());
    assert_eq!(store.get_balance(OWNER).expect("balance"), 0);
}

#[test]
fn save_and_retrieve_note() {
    let store = open();
    let note = store.save_note(&note_a("1000", false)).expect("save");

    assert_eq!(note.id, COMMIT_A.to_lowercase());
    assert!(!note.spent);
    assert!(!note.is_received);

    let fetched = store
        .get_by_commitment(COMMIT_A)
        .expect("get")
        .expect("should exist");
    assert_eq!(fetched.amount, "1000");
    assert_eq!(fetched.owner, OWNER);
}

#[test]
fn mark_spent() {
    let store = open();
    store.save_note(&note_a("500", false)).expect("save");

    assert!(store.mark_spent(COMMIT_A, LEDGER).expect("mark"));
    let note = store
        .get_by_commitment(COMMIT_A)
        .expect("get")
        .expect("exists");
    assert!(note.spent);
    assert_eq!(note.spent_at_ledger, Some(LEDGER));
}

#[test]
fn mark_spent_returns_false_for_missing() {
    let store = open();
    assert!(!store.mark_spent(COMMIT_A, LEDGER).expect("mark missing"));
}

#[test]
fn get_unspent_filters_spent() {
    let store = open();
    store.save_note(&note_a("100", false)).expect("save A");
    store.save_note(&note_b("200")).expect("save B");
    store.mark_spent(COMMIT_A, LEDGER).expect("mark spent");

    let unspent = store.get_unspent(OWNER).expect("unspent");
    assert_eq!(unspent.len(), 1);
    assert_eq!(unspent[0].amount, "200");
}

#[test]
fn balance_sums_unspent() {
    let store = open();
    store.save_note(&note_a("100", false)).expect("save A");
    store.save_note(&note_b("250")).expect("save B");
    store.mark_spent(COMMIT_A, LEDGER).expect("mark spent");

    assert_eq!(store.get_balance(OWNER).expect("balance"), 250);
}

#[test]
fn delete_and_clear() {
    let store = open();
    store.save_note(&note_a("100", false)).expect("save A");
    store.save_note(&note_b("200")).expect("save B");

    store.delete(COMMIT_A).expect("delete A");
    assert!(store.get_by_commitment(COMMIT_A).expect("get").is_none());

    store.clear().expect("clear");
    assert!(store.get_all().expect("get_all").is_empty());
}

#[test]
fn commitment_normalized_case_insensitive() {
    let store = open();
    let upper = "0xAAAA000000000000000000000000000000000000000000000000000000000001";
    store
        .save_note(&NewNote {
            commitment: upper,
            owner: OWNER,
            private_key: PRIV_KEY,
            blinding: BLINDING,
            amount: "100",
            leaf_index: Some(0),
            ledger: LEDGER,
            created_at: TS,
            is_received: false,
        })
        .expect("save");

    let lower = "0xaaaa000000000000000000000000000000000000000000000000000000000001";
    assert!(store.get_by_commitment(lower).expect("get").is_some());
}
