//! Witness Generation WASM Module
//!
//! Uses ark-circom to compute witnesses for Circom circuits in the browser.
//! Outputs witness bytes compatible with the prover module.

extern crate alloc;

use alloc::{format, string::String, vec::Vec};
use ark_bn254::Fr;
use ark_circom::circom::R1CSFile;
use ark_circom::WitnessCalculator as ArkWitnessCalculator;
use num_bigint::BigInt;
use std::collections::HashMap;
use std::io::Cursor;
use wasm_bindgen::prelude::*;
use wasmer::{Module, Store};

/// Initialize the WASM module
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

/// Get module version
#[wasm_bindgen]
pub fn version() -> String {
    String::from(env!("CARGO_PKG_VERSION"))
}

/// Witness calculator instance
#[wasm_bindgen]
pub struct WitnessCalculator {
    /// Wasmer store for the circuit WASM instance
    store: Store,
    /// Internal ark-circom witness calculator
    calculator: ArkWitnessCalculator,
    /// Number of variables in the witness
    witness_size: u32,
    /// Number of public inputs
    num_public: u32,
}

#[wasm_bindgen]
impl WitnessCalculator {
    /// Create a new WitnessCalculator from circuit WASM and R1CS bytes
    ///
    /// # Arguments
    /// * `circuit_wasm` - The compiled circuit WASM bytes
    /// * `r1cs_bytes` - The R1CS constraint system bytes
    #[wasm_bindgen(constructor)]
    pub fn new(circuit_wasm: &[u8], r1cs_bytes: &[u8]) -> Result<WitnessCalculator, JsValue> {
        // Parse R1CS from bytes
        let cursor = Cursor::new(r1cs_bytes);
        let r1cs_file: R1CSFile<Fr> = R1CSFile::new(cursor)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse R1CS: {}", e)))?;

        let witness_size = r1cs_file.header.n_wires as u32;
        let num_public = r1cs_file.header.n_pub_in as u32;

        // Create wasmer store and load circuit module from bytes
        let mut store = Store::default();
        let module = Module::new(&store, circuit_wasm)
            .map_err(|e| JsValue::from_str(&format!("Failed to load circuit WASM: {}", e)))?;

        // Create witness calculator from module
        let calculator = ArkWitnessCalculator::from_module(&mut store, module)
            .map_err(|e| JsValue::from_str(&format!("Failed to init witness calc: {}", e)))?;

        Ok(WitnessCalculator {
            store,
            calculator,
            witness_size,
            num_public,
        })
    }

    /// Compute witness from JSON inputs
    ///
    /// # Arguments
    /// * `inputs_json` - JSON string with circuit inputs
    ///
    /// # Returns
    /// * Witness as Little-Endian bytes (32 bytes per field element)
    #[wasm_bindgen]
    pub fn compute_witness(&mut self, inputs_json: &str) -> Result<Vec<u8>, JsValue> {
        use serde_json::Value;

        // Parse JSON inputs
        let inputs: Value = serde_json::from_str(inputs_json)
            .map_err(|e| JsValue::from_str(&format!("Invalid JSON: {}", e)))?;

        let inputs_map = inputs
            .as_object()
            .ok_or_else(|| JsValue::from_str("Inputs must be a JSON object"))?;

        // Convert to HashMap<String, Vec<BigInt>> by flattening nested structures
        let mut inputs_hashmap: HashMap<String, Vec<BigInt>> = HashMap::new();

        for (key, value) in inputs_map {
            flatten_input(key, value, &mut inputs_hashmap)?;
        }

        // Calculate witness
        let witness = self
            .calculator
            .calculate_witness(&mut self.store, inputs_hashmap, true)
            .map_err(|e| JsValue::from_str(&format!("Witness calculation failed: {}", e)))?;

        // Convert to Little-Endian bytes
        Ok(witness_to_bytes(&witness))
    }

    /// Get the witness size (number of field elements)
    #[wasm_bindgen(getter)]
    pub fn witness_size(&self) -> u32 {
        self.witness_size
    }

    /// Get the number of public inputs
    #[wasm_bindgen(getter)]
    pub fn num_public_inputs(&self) -> u32 {
        self.num_public
    }
}

/// Check, recursively, if a JSON value is an array that contains only primitives.
/// This determines if the array should be flattened to a single key to match Circom convention.
fn is_pure_array(value: &serde_json::Value) -> bool {
    use serde_json::Value;
    match value {
        Value::Number(_) | Value::String(_) | Value::Bool(_) | Value::Null => true,
        Value::Array(arr) => arr.iter().all(is_pure_array),
        Value::Object(_) => false,
    }
}

/// Flatten a JSON value into the inputs hashmap
/// 
/// For Circom circuits:
/// - Multi-dimensional arrays of primitives are flattened to a single key in row-major order
/// - Arrays containing objects use indexed keys with dot notation for fields
fn flatten_input(
    key: &str,
    value: &serde_json::Value,
    inputs: &mut HashMap<String, Vec<BigInt>>,
) -> Result<(), JsValue> {
    use serde_json::Value;

    match value {
        Value::Number(n) => {
            let bi = if let Some(i) = n.as_u64() {
                BigInt::from(i)
            } else if let Some(i) = n.as_i64() {
                BigInt::from(i)
            } else {
                return Err(JsValue::from_str(&format!("Invalid number for {}", key)));
            };
            inputs.entry(key.to_string()).or_default().push(bi);
        }
        Value::String(s) => {
            // Handle decimal or hex strings
            let bi = if let Some(hex) = s.strip_prefix("0x") {
                BigInt::parse_bytes(hex.as_bytes(), 16)
            } else {
                BigInt::parse_bytes(s.as_bytes(), 10)
            };
            let bi = bi
                .ok_or_else(|| JsValue::from_str(&format!("Invalid bigint for {}: {}", key, s)))?;
            inputs.entry(key.to_string()).or_default().push(bi);
        }
        Value::Array(arr) => {
            // Check if this is a "pure" array (only primitives, possibly nested)
            // Pure arrays get flattened to a single key (Circom convention for multi-dim arrays)
            if is_pure_array(value) {
                // Flatten all values to the same key in row-major order
                flatten_pure_array(key, value, inputs)?;
            } else {
                // Array contains objects - use indexed keys with field access
                for (idx, item) in arr.iter().enumerate() {
                    let indexed_key = format!("{}[{}]", key, idx);
                    flatten_input(&indexed_key, item, inputs)?;
                }
            }
        }
        Value::Object(obj) => {
            // Flatten object fields with dot notation
            for (field, val) in obj {
                let nested_key = format!("{}.{}", key, field);
                flatten_input(&nested_key, val, inputs)?;
            }
        }
        Value::Bool(b) => {
            let bi = if *b { BigInt::from(1) } else { BigInt::from(0) };
            inputs.entry(key.to_string()).or_default().push(bi);
        }
        Value::Null => {
            // Treat null as 0
            inputs
                .entry(key.to_string())
                .or_default()
                .push(BigInt::from(0));
        }
    }
    Ok(())
}

/// Recursively flatten a pure array to a single key
fn flatten_pure_array(
    key: &str,
    value: &serde_json::Value,
    inputs: &mut HashMap<String, Vec<BigInt>>,
) -> Result<(), JsValue> {
    use serde_json::Value;

    match value {
        Value::Number(n) => {
            let bi = if let Some(i) = n.as_u64() {
                BigInt::from(i)
            } else if let Some(i) = n.as_i64() {
                BigInt::from(i)
            } else {
                return Err(JsValue::from_str(&format!("Invalid number for {}", key)));
            };
            inputs.entry(key.to_string()).or_default().push(bi);
        }
        Value::String(s) => {
            let bi = if let Some(hex) = s.strip_prefix("0x") {
                BigInt::parse_bytes(hex.as_bytes(), 16)
            } else {
                BigInt::parse_bytes(s.as_bytes(), 10)
            };
            let bi = bi
                .ok_or_else(|| JsValue::from_str(&format!("Invalid bigint for {}: {}", key, s)))?;
            inputs.entry(key.to_string()).or_default().push(bi);
        }
        Value::Array(arr) => {
            // Recursively flatten in row-major order
            for item in arr {
                flatten_pure_array(key, item, inputs)?;
            }
        }
        Value::Bool(b) => {
            let bi = if *b { BigInt::from(1) } else { BigInt::from(0) };
            inputs.entry(key.to_string()).or_default().push(bi);
        }
        Value::Null => {
            inputs
                .entry(key.to_string())
                .or_default()
                .push(BigInt::from(0));
        }
        Value::Object(_) => {
            // Should not happen for pure arrays
            return Err(JsValue::from_str(&format!(
                "Unexpected object in pure array: {}",
                key
            )));
        }
    }
    Ok(())
}

/// Convert witness to Little-Endian bytes (32 bytes per element)
fn witness_to_bytes(witness: &[BigInt]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(witness.len() * 32);

    for bi in witness {
        // Convert BigInt to 32 LE bytes
        let (sign, mut be_bytes) = bi.to_bytes_be();

        // Handle negative numbers (should not happen in valid circuits)
        if sign == num_bigint::Sign::Minus {
            // For field elements this shouldn't happen, but pad to 32 anyway
            be_bytes = vec![0u8; 32];
        }

        // Pad to 32 bytes (big-endian)
        let mut padded = vec![0u8; 32];
        let offset = 32usize.saturating_sub(be_bytes.len());
        padded[offset..].copy_from_slice(&be_bytes[..be_bytes.len().min(32)]);

        // Convert to little-endian
        padded.reverse();
        bytes.extend_from_slice(&padded);
    }

    bytes
}
