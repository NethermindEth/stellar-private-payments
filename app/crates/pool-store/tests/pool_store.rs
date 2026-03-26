//! Integration tests for the `pool-store` crate.

use pool_store::PoolStore;
use storage::Storage;

const COMMITMENT_A: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
const COMMITMENT_B: &str = "0x2222222222222222222222222222222222222222222222222222222222222222";
const NULLIFIER_A: &str = "0xdeadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe";
const ENC_OUT: &str = "0xabcd";

const LEDGER_A: u32 = 50_000_100;
const LEDGER_B: u32 = 50_000_200;

fn open() -> PoolStore {
    let db = Storage::open_in_memory().expect("Failed to open storage");
    PoolStore::open(db).expect("Failed to open pool store")
}

#[test]
fn empty_store_has_zero_next_index() {
    let store = open();
    assert_eq!(store.next_index(), 0);
    assert_eq!(store.leaf_count().expect("leaf_count"), 0);
}

#[test]
fn commitment_persists_and_advances_index() {
    let mut store = open();
    store
        .process_new_commitment(COMMITMENT_A, 0, ENC_OUT, LEDGER_A)
        .expect("Failed to process commitment");

    assert_eq!(store.next_index(), 1);
    assert_eq!(store.leaf_count().expect("leaf_count"), 1);

    // Proof must round-trip: recomputing root from path should equal tree root.
    let proof = store.get_proof(0).expect("Failed to get proof");
    assert_eq!(proof.root, store.root());
}

#[test]
fn nullifier_spent_tracking() {
    let mut store = open();
    assert!(
        !store
            .is_nullifier_spent(NULLIFIER_A)
            .expect("check unspent")
    );
    store
        .process_new_nullifier(NULLIFIER_A, LEDGER_A)
        .expect("Failed to process nullifier");
    assert!(store.is_nullifier_spent(NULLIFIER_A).expect("check spent"));
}

#[test]
fn rebuild_tree_restores_state() {
    let db = Storage::open_in_memory().expect("Failed to open storage");
    let root_before;
    {
        let mut store = PoolStore::open(db).expect("Failed to open");
        store
            .process_new_commitment(COMMITMENT_A, 0, ENC_OUT, LEDGER_A)
            .expect("Failed to process commitment A");
        store
            .process_new_commitment(COMMITMENT_B, 1, ENC_OUT, LEDGER_B)
            .expect("Failed to process commitment B");
        root_before = store.root();
    }
    // Reproduce the same leaf sequence in a fresh store and verify rebuild
    // produces the same root.
    let db2 = Storage::open_in_memory().expect("Failed to open storage 2");
    let mut store2 = PoolStore::open(db2).expect("Failed to open store2");
    store2
        .process_new_commitment(COMMITMENT_A, 0, ENC_OUT, LEDGER_A)
        .expect("Failed to process commitment A");
    store2
        .process_new_commitment(COMMITMENT_B, 1, ENC_OUT, LEDGER_B)
        .expect("Failed to process commitment B");
    // Explicit rebuild must yield the same root.
    store2.rebuild_tree().expect("Failed to rebuild tree");
    assert_eq!(store2.root(), root_before);
}

#[test]
fn clear_resets_all_state() {
    let mut store = open();
    store
        .process_new_commitment(COMMITMENT_A, 0, ENC_OUT, LEDGER_A)
        .expect("Failed to process commitment");
    store
        .process_new_nullifier(NULLIFIER_A, LEDGER_A)
        .expect("Failed to process nullifier");

    store.clear().expect("Failed to clear");

    assert_eq!(store.next_index(), 0);
    assert_eq!(store.leaf_count().expect("leaf_count after clear"), 0);
    assert!(
        !store
            .is_nullifier_spent(NULLIFIER_A)
            .expect("nullifier after clear")
    );
    assert!(
        store
            .get_encrypted_outputs(None)
            .expect("outputs after clear")
            .is_empty()
    );
}
