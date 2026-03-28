//! Integration tests for the `pool-store` crate.

use pool_store::PoolStore;
use std::rc::Rc;
use storage::Storage;

const COMMITMENT_A: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
const COMMITMENT_B: &str = "0x2222222222222222222222222222222222222222222222222222222222222222";
const NULLIFIER_A: &str = "0xdeadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe";
const ENC_OUT: &str = "0xabcd";
const LEDGER: u32 = 50_000_100;

fn open() -> PoolStore {
    let db = Rc::new(Storage::open_in_memory().expect("open storage"));
    PoolStore::open(db).expect("open pool store")
}

#[test]
fn commitment_lifecycle() {
    let mut store = open();
    assert_eq!(store.next_index(), 0);

    store
        .process_new_commitment(COMMITMENT_A, 0, ENC_OUT, LEDGER)
        .expect("commit A");
    assert_eq!(store.next_index(), 1);
    assert_eq!(store.leaf_count().expect("count"), 1);

    let proof = store.get_proof(0).expect("proof");
    assert_eq!(proof.root, store.root());
}

#[test]
fn nullifier_tracking() {
    let store = open();
    assert!(store.get_nullifier(NULLIFIER_A).expect("get").is_none());
    store
        .process_new_nullifier(NULLIFIER_A, LEDGER)
        .expect("put");
    assert!(store.get_nullifier(NULLIFIER_A).expect("get").is_some());
}

#[test]
fn rebuild_tree_restores_root() {
    let mut store = open();
    store
        .process_new_commitment(COMMITMENT_A, 0, ENC_OUT, LEDGER)
        .expect("A");
    store
        .process_new_commitment(COMMITMENT_B, 1, ENC_OUT, LEDGER)
        .expect("B");
    let root_before = store.root();

    store.rebuild_tree().expect("rebuild");
    assert_eq!(store.root(), root_before);
}

#[test]
fn clear_resets_all() {
    let mut store = open();
    store
        .process_new_commitment(COMMITMENT_A, 0, ENC_OUT, LEDGER)
        .expect("commit");
    store
        .process_new_nullifier(NULLIFIER_A, LEDGER)
        .expect("null");

    store.clear().expect("clear");
    assert_eq!(store.next_index(), 0);
    assert!(store.get_nullifier(NULLIFIER_A).expect("get").is_none());
    assert!(store.get_encrypted_outputs(None).expect("enc").is_empty());
}
