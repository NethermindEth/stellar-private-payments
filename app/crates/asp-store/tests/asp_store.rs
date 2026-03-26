//! Integration tests for the `asp-store` crate.

use asp_store::AspStore;
use storage::Storage;

const LEAF_A: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
const LEAF_B: &str = "0x2222222222222222222222222222222222222222222222222222222222222222";
const ROOT: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

const LEDGER_A: u32 = 50_000_100;
const LEDGER_B: u32 = 50_000_200;

fn open() -> AspStore {
    let db = Storage::open_in_memory().expect("Failed to open storage");
    AspStore::open(db).expect("Failed to open asp store")
}

#[test]
fn empty_store_has_zero_next_index() {
    let store = open();
    assert_eq!(store.next_index(), 0);
    assert_eq!(store.leaf_count().expect("leaf_count"), 0);
}

#[test]
fn leaf_added_persists_and_advances_index() {
    let mut store = open();
    store
        .process_leaf_added(LEAF_A, 0, ROOT, LEDGER_A)
        .expect("Failed to process leaf A");

    assert_eq!(store.next_index(), 1);
    assert_eq!(store.leaf_count().expect("leaf_count"), 1);

    let proof = store.get_proof(0).expect("Failed to get proof");
    assert_eq!(proof.root, store.root());
}

#[test]
fn out_of_order_insertion_is_rejected() {
    let mut store = open();
    // index 1 before index 0 — must fail
    let err = store
        .process_leaf_added(LEAF_A, 1, ROOT, LEDGER_A)
        .unwrap_err();
    assert!(err.to_string().contains("out-of-order"));
}

#[test]
fn find_leaf_by_hash_works() {
    let mut store = open();
    store
        .process_leaf_added(LEAF_A, 0, ROOT, LEDGER_A)
        .expect("Failed to process leaf");

    let found = store
        .find_leaf_by_hash(LEAF_A)
        .expect("DB error")
        .expect("Expected leaf");
    assert_eq!(found.index, 0);
    assert_eq!(found.root, ROOT);

    assert!(store.find_leaf_by_hash(LEAF_B).expect("DB error").is_none());
}

#[test]
fn rebuild_tree_restores_root() {
    let mut store = open();
    store
        .process_leaf_added(LEAF_A, 0, ROOT, LEDGER_A)
        .expect("Failed to process leaf A");
    store
        .process_leaf_added(LEAF_B, 1, ROOT, LEDGER_B)
        .expect("Failed to process leaf B");
    let root_before = store.root();

    store.rebuild_tree().expect("Failed to rebuild");
    assert_eq!(store.root(), root_before);
}

#[test]
fn clear_resets_all_state() {
    let mut store = open();
    store
        .process_leaf_added(LEAF_A, 0, ROOT, LEDGER_A)
        .expect("Failed to process leaf");

    store.clear().expect("Failed to clear");

    assert_eq!(store.next_index(), 0);
    assert_eq!(store.leaf_count().expect("leaf_count after clear"), 0);
    assert!(store.find_leaf_by_hash(LEAF_A).expect("DB error").is_none());
}
