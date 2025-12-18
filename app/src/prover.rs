
// You should use alloc:: crate
use alloc::{
    vec::Vec,
};
use anyhow::Result;
use wasm_bindgen::{JsValue, prelude::*};

/// Wrapper atop proving functionality
#[wasm_bindgen]
pub struct Prover {}


impl Prover {
    /// Prover initialization - if not exposed to JS
    /// can be without #[wasm_bindgen]
    pub fn new(_circuit: Vec<u8>) -> Self {
        Self {}
    }
}

/// Methods to be available in JS marked with 
#[wasm_bindgen]
impl Prover {

    /// Methods to be available in JS should return JsValue
    /// for the complex structs use serde serialization to json with 
    /// serde_wasm_bindgen::to_value(&data)?
    /// Many Rust types can be returned directly like Vec<T>
    pub fn prove(&self) -> Result<Vec<u8>, JsValue> {
        let data = Vec::from(b"hello stellar");
        Ok(data)
    }
}