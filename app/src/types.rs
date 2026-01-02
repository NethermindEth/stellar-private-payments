//! Common types used across the prover module

use alloc::{collections::BTreeMap, string::String, vec::Vec};

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// Field element size in bytes (BN254 scalar field)
pub const FIELD_SIZE: usize = 32;

/// Groth16 proof structure for serialization to JS
#[derive(Clone, Debug, Serialize, Deserialize)]
#[wasm_bindgen]
pub struct Groth16Proof {
    /// Proof point A (G1)
    #[wasm_bindgen(skip)]
    pub a: Vec<u8>,
    /// Proof point B (G2)
    #[wasm_bindgen(skip)]
    pub b: Vec<u8>,
    /// Proof point C (G1)
    #[wasm_bindgen(skip)]
    pub c: Vec<u8>,
}

#[wasm_bindgen]
impl Groth16Proof {
    /// Get proof point A as bytes
    #[wasm_bindgen(getter)]
    pub fn a(&self) -> Vec<u8> {
        self.a.clone()
    }

    /// Get proof point B as bytes
    #[wasm_bindgen(getter)]
    pub fn b(&self) -> Vec<u8> {
        self.b.clone()
    }

    /// Get proof point C as bytes
    #[wasm_bindgen(getter)]
    pub fn c(&self) -> Vec<u8> {
        self.c.clone()
    }

    /// Get the full proof as concatenated bytes [A || B || C]
    #[wasm_bindgen]
    pub fn to_bytes(&self) -> Vec<u8> {
        let capacity = self
            .a
            .len()
            .saturating_add(self.b.len())
            .saturating_add(self.c.len());
        let mut bytes = Vec::with_capacity(capacity);
        bytes.extend_from_slice(&self.a);
        bytes.extend_from_slice(&self.b);
        bytes.extend_from_slice(&self.c);
        bytes
    }
}

/// Circuit input builder for preparing witness inputs
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CircuitInputs {
    /// Input signals as name -> value(s) mapping
    /// Values are stored as hex strings for BigInt compatibility
    #[serde(flatten)]
    pub signals: BTreeMap<String, InputValue>,
}

/// Input value - either a single field element or an array
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum InputValue {
    /// Single field element as hex string
    Single(String),
    /// Array of field elements as hex strings
    Array(Vec<String>),
}

impl CircuitInputs {
    /// Create new empty inputs
    pub fn new() -> Self {
        Self {
            signals: BTreeMap::new(),
        }
    }

    /// Set a single value input
    pub fn set_single(&mut self, name: &str, value: &str) {
        self.signals
            .insert(String::from(name), InputValue::Single(String::from(value)));
    }

    /// Set an array value input
    pub fn set_array(&mut self, name: &str, values: Vec<String>) {
        self.signals
            .insert(String::from(name), InputValue::Array(values));
    }
}
