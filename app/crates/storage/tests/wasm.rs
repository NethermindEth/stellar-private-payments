//! WASM integration tests for the storage crate.

#![cfg(target_arch = "wasm32")]

use storage::{types::PoolLeaf, Storage};
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn open_in_memory_and_roundtrip() {
    let db = Storage::open_in_memory().expect("open_in_memory");
    db.put_pool_leaf(&PoolLeaf { index: 0, commitment: "0xabc".into(), ledger: 1 })
        .expect("put_pool_leaf");
    assert_eq!(db.count_pool_leaves().expect("count"), 1);
}
