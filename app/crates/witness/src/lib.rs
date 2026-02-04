//! Witness Generation WASM Module
//!
//! Uses ark-circom to compute witnesses for Circom circuits in the browser.
//! Outputs witness bytes compatible with the prover module.

use ark_bn254::Fr;
use ark_circom::{WitnessCalculator as ArkWitnessCalculator, circom::R1CSFile};
use num_bigint::{BigInt, Sign};
// These are part of the reduced STD that is browser compatible
use std::{collections::HashMap, io::Cursor, string::String, vec::Vec};
use wasm_bindgen::prelude::*;
use wasmer::{Module, Store};

/// BN254 scalar field modulus
const BN254_FIELD_MODULUS: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

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
    /// Number of public inputs (does not include public outputs or the constant
    /// signal 1)
    num_public_inputs: u32,
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

        let witness_size = r1cs_file.header.n_wires;
        let num_public_inputs = r1cs_file.header.n_pub_in;

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
            num_public_inputs,
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
            .calculate_witness(&mut self.store, inputs_hashmap, false)
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
        self.num_public_inputs
    }
}

/// Convert a BigInt to its field element representation.
/// Negative numbers are converted to p - |value| where p is the field modulus.
/// Relevant for ZK proof computation. For on-chain token transfer
/// we use a I256 passed to the contract.
fn to_field_element(bi: BigInt) -> BigInt {
    let modulus =
        BigInt::parse_bytes(BN254_FIELD_MODULUS.as_bytes(), 10).expect("Invalid field modulus");

    if bi.sign() == Sign::Minus {
        let abs_value = bi
            .checked_mul(&BigInt::from(-1))
            .expect("Overflow in getting the abs value"); // Get absolute value

        // Check absolute value must be less than the field modulus
        assert!(
            abs_value < modulus,
            "Negative value {} exceeds field modulus",
            bi
        );

        // For negative n: field_element = p - |n|
        modulus
            .checked_sub(&abs_value)
            .expect("Overflow in field element computation")
    } else {
        // Validate: positive value must be less than the field modulus
        assert!(bi < modulus, "Value {} exceeds field modulus", bi);
        bi
    }
}

/// Check if a JSON value is an array containing only primitives.
fn is_pure_array(value: &serde_json::Value) -> bool {
    use serde_json::Value;

    let mut stack: Vec<&Value> = vec![value];

    while let Some(current) = stack.pop() {
        match current {
            Value::Number(_) | Value::String(_) | Value::Bool(_) | Value::Null => {}
            Value::Array(arr) => {
                for item in arr {
                    stack.push(item);
                }
            }
            Value::Object(_) => return false,
        }
    }
    true
}

/// Flatten a JSON value into the inputs hashmap.
///
/// For Circom circuits:
/// - Multi-dimensional arrays of primitives are flattened to a single key in
///   row-major order
/// - Arrays containing objects use indexed keys with dot notation for fields
fn flatten_input(
    key: &str,
    value: &serde_json::Value,
    inputs: &mut HashMap<String, Vec<BigInt>>,
) -> Result<(), JsValue> {
    use serde_json::Value;

    // (key, value) pairs to iterate over.
    let mut stack: Vec<(String, &Value)> = vec![(key.to_string(), value)];

    while let Some((current_key, current_value)) = stack.pop() {
        match current_value {
            Value::Number(n) => {
                let bi = if let Some(i) = n.as_u64() {
                    BigInt::from(i)
                } else if let Some(i) = n.as_i64() {
                    BigInt::from(i)
                } else {
                    return Err(JsValue::from_str(&format!(
                        "Invalid number for {}",
                        current_key
                    )));
                };
                // Convert to field element (handles negative numbers)
                inputs
                    .entry(current_key)
                    .or_default()
                    .push(to_field_element(bi));
            }
            Value::String(s) => {
                let bi = if let Some(hex) = s.strip_prefix("0x") {
                    BigInt::parse_bytes(hex.as_bytes(), 16)
                } else {
                    BigInt::parse_bytes(s.as_bytes(), 10)
                };
                let bi = bi.ok_or_else(|| {
                    JsValue::from_str(&format!("Invalid bigint for {}: {}", current_key, s))
                })?;
                // Convert to field element (handles negative numbers)
                inputs
                    .entry(current_key)
                    .or_default()
                    .push(to_field_element(bi));
            }
            Value::Array(arr) => {
                // Pure arrays get flattened to a single key as in
                if is_pure_array(current_value) {
                    flatten_pure_array(&current_key, current_value, inputs)?;
                } else {
                    //  If the array contains objects, we push indexed items in reverse order
                    // to maintain the original order when popping
                    for (idx, item) in arr.iter().enumerate().rev() {
                        let indexed_key = format!("{}[{}]", current_key, idx);
                        stack.push((indexed_key, item));
                    }
                }
            }
            Value::Object(obj) => {
                // Push object fields
                for (field, val) in obj {
                    let nested_key = format!("{}.{}", current_key, field);
                    stack.push((nested_key, val));
                }
            }
            Value::Bool(b) => {
                let bi = if *b { BigInt::from(1) } else { BigInt::from(0) };
                inputs.entry(current_key).or_default().push(bi);
            }
            Value::Null => {
                inputs.entry(current_key).or_default().push(BigInt::from(0));
            }
        }
    }
    Ok(())
}

/// Flatten a pure array to a single key in row-major order.
fn flatten_pure_array(
    key: &str,
    value: &serde_json::Value,
    inputs: &mut HashMap<String, Vec<BigInt>>,
) -> Result<(), JsValue> {
    use serde_json::Value;

    // We use indices to maintain row-major order:
    // each item is (array_ref, next_index_to_process).
    // For non-array values, we process them immediately.
    enum WorkItem<'a> {
        Value(&'a Value),
        ArrayIter { arr: &'a [Value], idx: usize },
    }

    let mut stack: Vec<WorkItem<'_>> = vec![WorkItem::Value(value)];

    while let Some(item) = stack.pop() {
        match item {
            WorkItem::Value(v) => match v {
                Value::Number(n) => {
                    let bi = if let Some(i) = n.as_u64() {
                        BigInt::from(i)
                    } else if let Some(i) = n.as_i64() {
                        BigInt::from(i)
                    } else {
                        return Err(JsValue::from_str(&format!("Invalid number for {}", key)));
                    };
                    inputs
                        .entry(key.to_string())
                        .or_default()
                        .push(to_field_element(bi));
                }
                Value::String(s) => {
                    let bi = if let Some(hex) = s.strip_prefix("0x") {
                        BigInt::parse_bytes(hex.as_bytes(), 16)
                    } else {
                        BigInt::parse_bytes(s.as_bytes(), 10)
                    };
                    let bi = bi.ok_or_else(|| {
                        JsValue::from_str(&format!("Invalid bigint for {}: {}", key, s))
                    })?;
                    inputs
                        .entry(key.to_string())
                        .or_default()
                        .push(to_field_element(bi));
                }
                Value::Array(arr) => {
                    if !arr.is_empty() {
                        stack.push(WorkItem::ArrayIter { arr, idx: 0 });
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
                    return Err(JsValue::from_str(&format!(
                        "Unexpected object in pure array: {}",
                        key
                    )));
                }
            },
            WorkItem::ArrayIter { arr, idx } => {
                // Push continuation for remaining elements first
                let next_idx = idx.saturating_add(1);
                if next_idx < arr.len() {
                    stack.push(WorkItem::ArrayIter { arr, idx: next_idx });
                }
                // Then push current element
                stack.push(WorkItem::Value(&arr[idx]));
            }
        }
    }
    Ok(())
}

/// Convert witness to Little-Endian bytes (32 bytes per element)
fn witness_to_bytes(witness: &[BigInt]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        witness
            .len()
            .checked_mul(32)
            .expect("Overflow in witness size"),
    );

    for bi in witness {
        // Convert BigInt to 32 LE bytes
        let (sign, be_bytes) = bi.to_bytes_be();

        // Check it fits in 32 bytes
        assert!(
            be_bytes.len() <= 32,
            "Field element exceeds 32 bytes in witness"
        );

        // Negative numbers should not occur in witness output since inputs
        // are converted to field elements. Assert this invariant.
        assert!(
            sign != Sign::Minus,
            "Negative number in witness output - inputs should be field elements"
        );

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
