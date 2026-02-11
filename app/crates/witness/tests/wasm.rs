//! Minimal WASM integration tests for the witness crate.

#![cfg(target_arch = "wasm32")]

use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn test_version() {
    let v = witness::version();
    assert!(!v.is_empty(), "version string should not be empty");
}
