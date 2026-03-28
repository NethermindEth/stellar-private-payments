//! Integration tests for the `asp-store` crate.

use asp_store::AspStore;
use std::rc::Rc;
use storage::Storage;

const LEAF_A: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
const LEAF_B: &str = "0x2222222222222222222222222222222222222222222222222222222222222222";
const ROOT: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const LEDGER: u32 = 50_000_100;

fn open() -> AspStore {
    let db = Rc::new(Storage::open_in_memory().expect("open storage"));
    AspStore::open(db).expect("open asp store")
}

#[test]
fn leaf_lifecycle() {
    let mut store = open();
    assert_eq!(store.next_index(), 0);

    store
        .process_leaf_added(LEAF_A, 0, ROOT, LEDGER)
        .expect("add A");
    assert_eq!(store.next_index(), 1);
    assert_eq!(store.leaf_count().expect("count"), 1);

    let proof = store.get_proof(0).expect("proof");
    assert_eq!(proof.root, store.root());

    let found = store
        .find_leaf_by_hash(LEAF_A)
        .expect("find")
        .expect("exists");
    assert_eq!(found.index, 0);
    assert!(store.find_leaf_by_hash(LEAF_B).expect("find").is_none());
}

#[test]
fn out_of_order_insertion_rejected() {
    let mut store = open();
    let err = store
        .process_leaf_added(LEAF_A, 1, ROOT, LEDGER)
        .expect_err("should fail");
    assert!(err.to_string().contains("out-of-order"));
}

#[test]
fn rebuild_tree_restores_root() {
    let mut store = open();
    store
        .process_leaf_added(LEAF_A, 0, ROOT, LEDGER)
        .expect("A");
    store
        .process_leaf_added(LEAF_B, 1, ROOT, LEDGER)
        .expect("B");
    let root_before = store.root();

    store.rebuild_tree().expect("rebuild");
    assert_eq!(store.root(), root_before);
}

#[test]
fn clear_resets_all() {
    let mut store = open();
    store
        .process_leaf_added(LEAF_A, 0, ROOT, LEDGER)
        .expect("add");
    store.clear().expect("clear");

    assert_eq!(store.next_index(), 0);
    assert!(store.find_leaf_by_hash(LEAF_A).expect("find").is_none());
}
