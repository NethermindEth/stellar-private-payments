//! App logic

#![no_std]
extern crate alloc;

/// An example module to wrap the prover
pub mod prover;

use crate::prover::Prover;
use wasm_bindgen::{JsValue, prelude::*};
use anyhow::Result;
use alloc::vec::Vec;

/// An initialization function 
/// - to print panics in the console
/// - to initialize the prover
#[wasm_bindgen(js_name = init)]
pub async fn init(circuit: Vec<u8>) -> Result<Prover, JsValue> {
    console_error_panic_hook::set_once();
    let prover = Prover::new(circuit);
    Ok(prover)
}
