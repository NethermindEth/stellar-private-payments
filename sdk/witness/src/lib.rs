//! Witness Generation WASM Module
//!
//! Uses ark-circom to compute witnesses for Circom circuits in the browser.
//! Outputs witness bytes compatible with the prover module.

use anyhow::{Context as _, Result};
use ark_bn254::Fr;
use ark_circom::{WitnessCalculator as ArkWitnessCalculator, circom::R1CSFile};
use num_bigint::{BigInt, Sign};
// These are part of the reduced STD that is browser compatible
use std::{collections::HashMap, io::Cursor, string::String, vec::Vec};
use wasmer::{Module, Store};

/// BN254 scalar field modulus
const BN254_FIELD_MODULUS: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

/// Get module version
pub fn version() -> String {
    String::from(env!("CARGO_PKG_VERSION"))
}

/// Witness calculator instance
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

impl WitnessCalculator {
    /// Create a new WitnessCalculator from circuit WASM and R1CS bytes
    ///
    /// # Arguments
    /// * `circuit_wasm` - The compiled circuit WASM bytes
    /// * `r1cs_bytes` - The R1CS constraint system bytes
    pub fn new(circuit_wasm: &[u8], r1cs_bytes: &[u8]) -> Result<WitnessCalculator> {
        // Parse R1CS from bytes
        let cursor = Cursor::new(r1cs_bytes);
        let r1cs_file: R1CSFile<Fr> = R1CSFile::new(cursor).context("Failed to parse R1CS")?;

        let witness_size = r1cs_file.header.n_wires;
        let num_public_inputs = r1cs_file.header.n_pub_in;

        // Create wasmer store and load circuit module from bytes
        let mut store = Store::default();
        let module = Module::new(&store, circuit_wasm).context("Failed to load circuit WASM")?;

        // Create witness calculator from module
        let calculator = ArkWitnessCalculator::from_module(&mut store, module)
            .map_err(|e| anyhow::anyhow!("Failed to init witness calc: {e}"))?;

        Ok(WitnessCalculator {
            store,
            calculator,
            witness_size,
            num_public_inputs,
        })
    }

    // TODO it should be simplified
    /// Compute witness from JSON inputs
    ///
    /// # Arguments
    /// * `inputs_json` - JSON string with circuit inputs
    ///
    /// # Returns
    /// * Witness as Little-Endian bytes (32 bytes per field element)
    pub fn compute_witness(&mut self, inputs_json: &str) -> Result<Vec<u8>> {
        use serde_json::Value;

        // Parse JSON inputs
        let inputs: Value = serde_json::from_str(inputs_json).context("Invalid JSON")?;

        let inputs_map = inputs.as_object().context("Inputs must be a JSON object")?;

        // Convert to HashMap<String, Vec<BigInt>> by flattening nested structures
        let mut inputs_hashmap: HashMap<String, Vec<BigInt>> = HashMap::new();

        for (key, value) in inputs_map {
            flatten_input(key, value, &mut inputs_hashmap)?;
        }

        // Calculate witness
        let witness = self
            .calculator
            .calculate_witness(&mut self.store, inputs_hashmap, false)
            .map_err(|e| anyhow::anyhow!("Witness calculation failed: {e}"))?;

        // Convert to Little-Endian bytes
        Ok(witness_to_bytes(&witness))
    }

    /// Get the witness size (number of field elements)
    pub fn witness_size(&self) -> u32 {
        self.witness_size
    }

    /// Get the number of public inputs
    pub fn num_public_inputs(&self) -> u32 {
        self.num_public_inputs
    }
}

/// Convert a BigInt to its field element representation.
/// Negative numbers are converted to p - |value| where p is the field modulus.
/// Relevant for ZK proof computation. For on-chain token transfer
/// we use a I256 passed to the contract.
///
/// # Errors
/// Returns an error if the value (or its absolute value, for negatives) is not
/// less than the BN254 scalar field modulus.
fn to_field_element(bi: BigInt) -> Result<BigInt> {
    let modulus =
        BigInt::parse_bytes(BN254_FIELD_MODULUS.as_bytes(), 10).expect("Invalid field modulus");

    if bi.sign() == Sign::Minus {
        let abs_value = bi
            .checked_mul(&BigInt::from(-1))
            .expect("Overflow in getting the abs value"); // Get absolute value

        // Check absolute value must be less than the field modulus
        anyhow::ensure!(
            abs_value < modulus,
            "Negative value {} exceeds field modulus",
            bi
        );

        // For negative n: field_element = p - |n|
        Ok(modulus
            .checked_sub(&abs_value)
            .expect("Overflow in field element computation"))
    } else {
        // Validate: positive value must be less than the field modulus
        anyhow::ensure!(bi < modulus, "Value {} exceeds field modulus", bi);
        Ok(bi)
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
) -> Result<()> {
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
                    anyhow::bail!("Invalid number for {current_key}");
                };
                // Convert to field element (handles negative numbers)
                inputs
                    .entry(current_key)
                    .or_default()
                    .push(to_field_element(bi)?);
            }
            Value::String(s) => {
                let bi = if let Some(hex) = s.strip_prefix("0x") {
                    BigInt::parse_bytes(hex.as_bytes(), 16)
                } else {
                    BigInt::parse_bytes(s.as_bytes(), 10)
                };
                let bi = bi.context(format!("Invalid bigint for {current_key}: {s}"))?;
                // Convert to field element (handles negative numbers)
                inputs
                    .entry(current_key)
                    .or_default()
                    .push(to_field_element(bi)?);
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
) -> Result<()> {
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
                        anyhow::bail!("Invalid number for {key}");
                    };
                    inputs
                        .entry(key.to_string())
                        .or_default()
                        .push(to_field_element(bi)?);
                }
                Value::String(s) => {
                    let bi = if let Some(hex) = s.strip_prefix("0x") {
                        BigInt::parse_bytes(hex.as_bytes(), 16)
                    } else {
                        BigInt::parse_bytes(s.as_bytes(), 10)
                    };
                    let bi = bi.context(format!("Invalid bigint for {key}: {s}"))?;
                    inputs
                        .entry(key.to_string())
                        .or_default()
                        .push(to_field_element(bi)?);
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
                    anyhow::bail!("Unexpected object in pure array: {key}");
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Parse the BN254 scalar field modulus the same way production code does.
    fn modulus() -> BigInt {
        BigInt::parse_bytes(BN254_FIELD_MODULUS.as_bytes(), 10).expect("Invalid field modulus")
    }

    /// Flatten a single JSON value under the key "root".
    fn flatten(value: serde_json::Value) -> Result<HashMap<String, Vec<BigInt>>> {
        let mut inputs = HashMap::new();
        flatten_input("root", &value, &mut inputs)?;
        Ok(inputs)
    }

    // --- to_field_element: boundary values ---

    #[test]
    fn to_field_element_accepts_modulus_minus_one() {
        let p = modulus();
        let result = to_field_element(p.clone() - 1).expect("p - 1 must be accepted");
        assert_eq!(result, p - 1);
    }

    #[test]
    fn to_field_element_rejects_exact_modulus() {
        let err = to_field_element(modulus()).expect_err("p must be rejected");
        assert!(err.to_string().contains("exceeds field modulus"));
    }

    #[test]
    fn to_field_element_rejects_modulus_plus_one() {
        let err = to_field_element(modulus() + 1).expect_err("p + 1 must be rejected");
        assert!(err.to_string().contains("exceeds field modulus"));
    }

    // --- to_field_element: negative encoding ---

    #[test]
    fn to_field_element_maps_minus_one_to_modulus_minus_one() {
        let p = modulus();
        let result = to_field_element(BigInt::from(-1)).expect("-1 must be accepted");
        assert_eq!(result, p - 1);
    }

    #[test]
    fn to_field_element_maps_negated_modulus_minus_one_to_one() {
        let p = modulus();
        let result = to_field_element(-(p - BigInt::from(1))).expect("-(p - 1) must be accepted");
        assert_eq!(result, BigInt::from(1));
    }

    #[test]
    fn to_field_element_rejects_negative_modulus() {
        let err = to_field_element(-modulus()).expect_err("-p must be rejected");
        assert!(err.to_string().contains("Negative value"));
        assert!(err.to_string().contains("exceeds field modulus"));
    }

    #[test]
    fn to_field_element_accepts_zero() {
        let result = to_field_element(BigInt::from(0)).expect("0 must be accepted");
        assert_eq!(result, BigInt::from(0));
    }

    // --- flatten_input: structure flattening ---

    #[test]
    fn flatten_input_flattens_nested_pure_arrays_row_major() {
        let inputs = flatten(json!([[1, 2], [3, 4]])).expect("flattening must succeed");
        assert_eq!(
            inputs["root"],
            vec![
                BigInt::from(1),
                BigInt::from(2),
                BigInt::from(3),
                BigInt::from(4)
            ]
        );
    }

    #[test]
    fn flatten_input_uses_indexed_keys_for_arrays_of_objects() {
        let inputs = flatten(json!([{"x": 1}, {"x": 2}])).expect("flattening must succeed");
        assert_eq!(inputs["root[0].x"], vec![BigInt::from(1)]);
        assert_eq!(inputs["root[1].x"], vec![BigInt::from(2)]);
    }

    #[test]
    fn flatten_input_uses_dotted_keys_for_objects() {
        let inputs = flatten(json!({"a": {"b": 5}})).expect("flattening must succeed");
        assert_eq!(inputs["root.a.b"], vec![BigInt::from(5)]);
    }

    // --- flatten_input: scalar coercion and string parsing ---

    #[test]
    fn flatten_input_parses_decimal_strings() {
        let inputs = flatten(json!("123")).expect("decimal string must parse");
        assert_eq!(inputs["root"], vec![BigInt::from(123)]);
    }

    #[test]
    fn flatten_input_parses_hex_strings() {
        let inputs = flatten(json!("0x10")).expect("hex string must parse");
        assert_eq!(inputs["root"], vec![BigInt::from(16)]);
    }

    #[test]
    fn flatten_input_rejects_malformed_strings() {
        flatten(json!("not_a_number")).expect_err("malformed string must error");
    }

    #[test]
    fn flatten_input_coerces_bools_and_null() {
        let inputs = flatten(json!([true, false, null])).expect("coercion must succeed");
        assert_eq!(
            inputs["root"],
            vec![BigInt::from(1), BigInt::from(0), BigInt::from(0)]
        );
    }

    #[test]
    fn flatten_input_accepts_large_u64_numbers() {
        let inputs = flatten(json!(u64::MAX)).expect("u64::MAX fits in the field");
        assert_eq!(inputs["root"], vec![BigInt::from(u64::MAX)]);
    }

    // --- flatten_input / flatten_pure_array: out-of-range returns Err, never
    // panics ---

    #[test]
    fn flatten_input_out_of_range_string_returns_err() {
        let err =
            flatten(json!(modulus().to_string())).expect_err("p as a string must be rejected");
        assert!(err.to_string().contains("exceeds field modulus"));
    }

    #[test]
    fn flatten_input_out_of_range_negative_string_returns_err() {
        let err =
            flatten(json!(format!("-{}", modulus()))).expect_err("-p as a string must be rejected");
        assert!(err.to_string().contains("exceeds field modulus"));
    }

    #[test]
    fn flatten_pure_array_out_of_range_returns_err() {
        let err = flatten(json!([1, modulus().to_string()]))
            .expect_err("p inside a pure array must be rejected");
        assert!(err.to_string().contains("exceeds field modulus"));
    }

    // --- is_pure_array ---

    #[test]
    fn is_pure_array_accepts_nested_primitive_arrays() {
        assert!(is_pure_array(&json!([1, "two", [true, null]])));
    }

    #[test]
    fn is_pure_array_rejects_arrays_containing_objects() {
        assert!(!is_pure_array(&json!([1, {"a": 2}])));
        assert!(!is_pure_array(&json!([1, [{"a": 2}]])));
    }

    // --- witness_to_bytes: little-endian 32-byte encoding ---

    #[test]
    fn witness_to_bytes_encodes_zero_as_all_zeroes() {
        let bytes = witness_to_bytes(&[BigInt::from(0)]);
        assert_eq!(bytes, vec![0u8; 32]);
    }

    #[test]
    fn witness_to_bytes_encodes_one_in_least_significant_byte() {
        // Little-endian: the value 1 lands in the first byte, the rest are zero.
        let bytes = witness_to_bytes(&[BigInt::from(1)]);
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[0], 1);
        assert!(bytes[1..].iter().all(|&b| b == 0));
    }

    #[test]
    fn witness_to_bytes_encodes_256_across_two_bytes_little_endian() {
        // 256 == 0x0100; little-endian => byte[0] = 0x00, byte[1] = 0x01.
        let bytes = witness_to_bytes(&[BigInt::from(256)]);
        assert_eq!(bytes[0], 0);
        assert_eq!(bytes[1], 1);
        assert!(bytes[2..].iter().all(|&b| b == 0));
    }

    #[test]
    fn witness_to_bytes_emits_one_32_byte_chunk_per_element() {
        let witness = vec![BigInt::from(1), BigInt::from(2), BigInt::from(3)];
        let bytes = witness_to_bytes(&witness);
        assert_eq!(bytes.len(), 3 * 32);
        // Each element occupies its own little-endian 32-byte chunk, in order.
        assert_eq!(bytes[0], 1);
        assert_eq!(bytes[32], 2);
        assert_eq!(bytes[64], 3);
    }

    #[test]
    fn witness_to_bytes_roundtrips_full_width_modulus_minus_one() {
        // p - 1 is the largest valid field element and fills all 32 bytes.
        let value = modulus() - BigInt::from(1);
        let bytes = witness_to_bytes(std::slice::from_ref(&value));
        assert_eq!(bytes.len(), 32);
        // Reinterpreting the little-endian bytes must recover the original value.
        let recovered = BigInt::from_bytes_le(Sign::Plus, &bytes);
        assert_eq!(recovered, value);
    }

    #[test]
    fn witness_to_bytes_of_empty_witness_is_empty() {
        let empty: [BigInt; 0] = [];
        assert!(witness_to_bytes(&empty).is_empty());
    }

    // --- proptest: to_field_element properties (audit task T15) ---

    mod props {
        // BigInt arithmetic in property strategies/assertions cannot overflow.
        #![allow(clippy::arithmetic_side_effects)]

        use super::*;
        use proptest::prelude::*;

        /// Arbitrary BigInt in [0, p).
        fn arb_below_modulus() -> impl Strategy<Value = BigInt> {
            prop::collection::vec(any::<u64>(), 1..=4).prop_map(|limbs| {
                let mut v = BigInt::from(0);
                for limb in limbs {
                    v = (v << 64) + BigInt::from(limb);
                }
                v % modulus()
            })
        }

        /// Arbitrary BigInt in [1, p).
        fn arb_below_modulus_nonzero() -> impl Strategy<Value = BigInt> {
            arb_below_modulus().prop_filter_map("zero", |v| {
                if v == BigInt::from(0) { None } else { Some(v) }
            })
        }

        proptest! {
            /// Any v in [0, p) is already a field element: conversion is identity.
            #[test]
            fn prop_in_range_values_convert_to_themselves(v in arb_below_modulus()) {
                let result = to_field_element(v.clone()).expect("in-range value must convert");
                prop_assert_eq!(result, v);
            }

            /// Any negative v with |v| < p maps to p - |v|, landing in [1, p - 1].
            #[test]
            fn prop_negative_in_range_maps_to_modulus_minus_abs(v in arb_below_modulus_nonzero()) {
                let p = modulus();
                let result = to_field_element(-v.clone()).expect("in-range negative must convert");
                prop_assert_eq!(result.clone(), &p - &v);
                prop_assert!(result >= BigInt::from(1));
                prop_assert!(result < p);
            }

            /// Any |v| >= p errors instead of panicking, for both signs.
            #[test]
            fn prop_out_of_range_errors_instead_of_panicking(
                v in arb_below_modulus(),
                k in 1u32..=4,
            ) {
                let p = modulus();
                let over = &v + &p * BigInt::from(k);
                prop_assert!(to_field_element(over.clone()).is_err());
                prop_assert!(to_field_element(-over).is_err());
            }
        }
    }
}
