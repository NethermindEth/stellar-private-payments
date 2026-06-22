use anyhow::{Context as _, Result, anyhow};
use num_bigint::BigInt;
use std::{collections::HashMap, string::String, vec::Vec};

use crate::field::to_field_element;

/// Flatten a JSON value into the inputs hashmap.
///
/// For Circom circuits:
/// - Multi-dimensional arrays of primitives are flattened to a single key in
///   row-major order.
/// - Arrays containing objects use indexed keys with dot notation for fields.
pub(crate) fn flatten_input(
    key: &str,
    value: &serde_json::Value,
    inputs: &mut HashMap<String, Vec<BigInt>>,
) -> Result<()> {
    use serde_json::Value;

    let mut stack: Vec<(String, &Value)> = vec![(key.to_string(), value)];

    while let Some((current_key, current_value)) = stack.pop() {
        match current_value {
            Value::Number(n) => {
                let bi = json_number_to_bigint(n, &current_key)?;
                let field_element = to_field_element(bi)
                    .with_context(|| format!("Invalid field element for {current_key}"))?;
                inputs.entry(current_key).or_default().push(field_element);
            }
            Value::String(s) => {
                let bi = string_to_bigint(s, &current_key)?;
                let field_element = to_field_element(bi)
                    .with_context(|| format!("Invalid field element for {current_key}"))?;
                inputs.entry(current_key).or_default().push(field_element);
            }
            Value::Array(arr) => {
                if is_pure_array(current_value) {
                    flatten_pure_array(&current_key, current_value, inputs)?;
                } else {
                    for (idx, item) in arr.iter().enumerate().rev() {
                        let indexed_key = format!("{}[{}]", current_key, idx);
                        stack.push((indexed_key, item));
                    }
                }
            }
            Value::Object(obj) => {
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

fn json_number_to_bigint(n: &serde_json::Number, key: &str) -> Result<BigInt> {
    if let Some(i) = n.as_u64() {
        Ok(BigInt::from(i))
    } else if let Some(i) = n.as_i64() {
        Ok(BigInt::from(i))
    } else {
        anyhow::bail!("Invalid number for {key}");
    }
}

fn string_to_bigint(s: &str, key: &str) -> Result<BigInt> {
    let bi = if let Some(hex) = s.strip_prefix("0x") {
        BigInt::parse_bytes(hex.as_bytes(), 16)
    } else {
        BigInt::parse_bytes(s.as_bytes(), 10)
    };
    bi.context(format!("Invalid bigint for {key}: {s}"))
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

/// Flatten a pure array to a single key in row-major order.
fn flatten_pure_array(
    key: &str,
    value: &serde_json::Value,
    inputs: &mut HashMap<String, Vec<BigInt>>,
) -> Result<()> {
    use serde_json::Value;

    enum WorkItem<'a> {
        Value(&'a Value),
        ArrayIter { arr: &'a [Value], idx: usize },
    }

    let mut stack: Vec<WorkItem<'_>> = vec![WorkItem::Value(value)];

    while let Some(item) = stack.pop() {
        match item {
            WorkItem::Value(v) => match v {
                Value::Number(n) => {
                    let bi = json_number_to_bigint(n, key)?;
                    inputs.entry(key.to_string()).or_default().push(
                        to_field_element(bi)
                            .with_context(|| format!("Invalid field element for {key}"))?,
                    );
                }
                Value::String(s) => {
                    let bi = string_to_bigint(s, key)?;
                    inputs.entry(key.to_string()).or_default().push(
                        to_field_element(bi)
                            .with_context(|| format!("Invalid field element for {key}"))?,
                    );
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
                let next_idx = idx.saturating_add(1);
                if next_idx < arr.len() {
                    stack.push(WorkItem::ArrayIter { arr, idx: next_idx });
                }
                stack.push(WorkItem::Value(&arr[idx]));
            }
        }
    }
    Ok(())
}
