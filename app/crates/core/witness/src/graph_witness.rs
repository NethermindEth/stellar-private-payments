//! Graph-based witness generation.
//!
//! Computes witnesses by evaluating a pre-computed `circom-witness-rs`
//! operation graph. The runtime evaluator is pure Rust and compiles to
//! `wasm32-unknown-unknown`.

use anyhow::{Context as _, Result, bail, ensure};
// circom-witness-rs black-box hint functions operate on its arkworks 0.5 `Fr`.
use ark_bn254_05::Fr as BbfFr;
use ark_ff_05::{BigInteger as _, Field as _, PrimeField as _};
use circom_witness_rs::{BlackBoxFunction, Graph, M, calculate_witness, init_graph};
use ruint::aliases::U256;
use std::{collections::HashMap, string::String, sync::Arc, vec::Vec};

/// Witness calculator backed by a `circom-witness-rs` operation graph.
pub struct GraphWitnessCalculator {
    graph: Graph,
    bbfs: HashMap<String, BlackBoxFunction>,
}

impl GraphWitnessCalculator {
    /// Build a calculator from a serialized operation-graph blob.
    pub fn from_graph(graph_bytes: &[u8]) -> Result<GraphWitnessCalculator> {
        let graph = init_graph(graph_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to load witness graph: {e}"))?;
        Ok(GraphWitnessCalculator {
            graph,
            bbfs: circomlib_black_box_functions(),
        })
    }

    /// Compute the witness from JSON inputs, returning little-endian bytes
    /// (32 bytes per field element) compatible with the prover module.
    pub fn compute_witness(&self, inputs_json: &str) -> Result<Vec<u8>> {
        let inputs = parse_inputs(inputs_json)?;
        let witness = calculate_witness(inputs, &self.graph, Some(&self.bbfs))
            .map_err(|e| anyhow::anyhow!("Witness calculation failed: {e}"))?;
        Ok(witness_to_bytes(&witness))
    }

    /// Number of field elements in the computed witness.
    pub fn witness_size(&self) -> usize {
        self.graph.signals.len()
    }
}

/// Black-box hint functions bound at graph-evaluation time, mirroring the
/// `bbf_*` hints injected into circomlib during graph generation
/// (`tools/witness-graph/generate-policy-graph.sh`). These implement the
/// non-quadratic (`<--`) assignments the graph cannot express directly.
fn circomlib_black_box_functions() -> HashMap<String, BlackBoxFunction> {
    let mut bbfs: HashMap<String, BlackBoxFunction> = HashMap::new();

    // `bbf_inv(in) = in != 0 ? 1/in : 0` — circomlib `IsZero`.
    let bbf_inv: BlackBoxFunction =
        Arc::new(|params: &[BbfFr]| params[0].inverse().unwrap_or_else(|| BbfFr::from(0u64)));
    bbfs.insert(String::from("bbf_inv"), bbf_inv);

    // `bbf_bit(in, bit) = (in >> bit) & 1` — circomlib `Num2Bits`.
    let bbf_bit: BlackBoxFunction = Arc::new(|params: &[BbfFr]| {
        let value = params[0].into_bigint();
        let bit_index = usize::try_from(params[1].into_bigint().as_ref()[0])
            .expect("bbf_bit index fits in usize");
        BbfFr::from(u64::from(value.get_bit(bit_index)))
    });
    bbfs.insert(String::from("bbf_bit"), bbf_bit);

    bbfs
}

/// Parse JSON inputs into the `HashMap<String, Vec<U256>>` shape
/// `circom-witness-rs` expects.
///
/// The prover already emits each signal flat — a hex string or a flat array of
/// hex strings (`prover::types::InputValue`) — so we parse straight into field
/// elements without the multi-dimensional flattening the wasm path performs.
fn parse_inputs(inputs_json: &str) -> Result<HashMap<String, Vec<U256>>> {
    use serde_json::Value;

    let value: Value = serde_json::from_str(inputs_json).context("Invalid JSON")?;
    let obj = value.as_object().context("Inputs must be a JSON object")?;

    let mut out = HashMap::with_capacity(obj.len());
    for (key, val) in obj {
        let values = match val {
            Value::String(s) => vec![parse_field(s)?],
            Value::Array(items) => items
                .iter()
                .map(|item| match item {
                    Value::String(s) => parse_field(s),
                    other => bail!("signal {key} has a non-string element: {other}"),
                })
                .collect::<Result<Vec<_>>>()?,
            other => bail!("signal {key} must be a hex string or array, got: {other}"),
        };
        out.insert(key.clone(), values);
    }
    Ok(out)
}

/// Parse one field element from a decimal or `0x`-prefixed hex string,
/// rejecting anything outside the BN254 scalar field.
fn parse_field(s: &str) -> Result<U256> {
    let s = s.trim();
    let value = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => U256::from_str_radix(hex, 16),
        None => U256::from_str_radix(s, 10),
    }
    .map_err(|e| anyhow::anyhow!("invalid field element {s:?}: {e}"))?;
    ensure!(value < M, "witness input exceeds BN254 field modulus");
    Ok(value)
}

/// Encode witness field elements as little-endian bytes (32 bytes each).
fn witness_to_bytes(witness: &[U256]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        witness
            .len()
            .checked_mul(32)
            .expect("Overflow in witness size"),
    );
    for value in witness {
        bytes.extend_from_slice(&value.to_le_bytes::<32>());
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BN254 scalar field modulus, decimal.
    const MODULUS_DEC: &str =
        "21888242871839275222246405745257275088548364400416034343698204186575808495617";
    /// `MODULUS - 1`, the largest valid field element.
    const MODULUS_MINUS_ONE_DEC: &str =
        "21888242871839275222246405745257275088548364400416034343698204186575808495616";

    #[test]
    fn encodes_field_elements_little_endian() {
        // 1 -> first byte set, rest zero.
        let bytes = witness_to_bytes(&[U256::from(1u64)]);
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[0], 1);
        assert!(bytes[1..].iter().all(|&b| b == 0));

        // 0x0102 -> little-endian [0x02, 0x01, 0, ...].
        let bytes = witness_to_bytes(&[U256::from(0x0102u64)]);
        assert_eq!(&bytes[0..2], &[0x02, 0x01]);
    }

    #[test]
    fn encodes_multiple_elements_contiguously() {
        let bytes = witness_to_bytes(&[U256::from(1u64), U256::from(2u64)]);
        assert_eq!(bytes.len(), 64);
        assert_eq!(bytes[0], 1);
        assert_eq!(bytes[32], 2);
    }

    #[test]
    fn parse_field_rejects_value_at_or_above_modulus() {
        // p is not a valid field element; p - 1 is the largest valid one.
        assert!(parse_field(MODULUS_DEC).is_err());
        assert!(parse_field(MODULUS_MINUS_ONE_DEC).is_ok());
    }

    #[test]
    fn parse_field_accepts_decimal_and_hex() {
        assert_eq!(parse_field("255").expect("decimal"), U256::from(255u64));
        assert_eq!(parse_field("0xff").expect("hex"), U256::from(255u64));
        assert!(parse_field("-1").is_err());
        assert!(parse_field("0xnope").is_err());
    }

    #[test]
    fn parse_inputs_handles_single_and_flat_array_signals() {
        // Matches the prover's InputValue: Single(hex) and Array(Vec<hex>).
        let parsed = parse_inputs("{\"root\": \"0x05\", \"inAmount\": [\"0x01\", \"2\"]}")
            .expect("valid inputs");
        assert_eq!(parsed["root"], vec![U256::from(5u64)]);
        assert_eq!(parsed["inAmount"], vec![U256::from(1u64), U256::from(2u64)]);
    }

    #[test]
    fn parse_inputs_rejects_nested_arrays() {
        // The prover never emits nested arrays; reject rather than silently flatten.
        assert!(parse_inputs("{\"m\": [[1, 2], [3, 4]]}").is_err());
    }

    #[test]
    fn parse_inputs_rejects_non_object() {
        assert!(parse_inputs("[1, 2, 3]").is_err());
    }

    #[test]
    fn bbf_inv_matches_circom_semantics() {
        let bbfs = circomlib_black_box_functions();
        let inv = &bbfs["bbf_inv"];

        // Non-zero inputs map to the field inverse.
        let x = BbfFr::from(7u64);
        let expected = x.inverse().expect("7 is invertible in the field");
        assert_eq!(inv(&[x]), expected);

        // 0 maps to 0 (circom's `in != 0 ? 1/in : 0`).
        assert_eq!(inv(&[BbfFr::from(0u64)]), BbfFr::from(0u64));
    }

    #[test]
    fn bbf_bit_extracts_bits_lsb_first() {
        let bbfs = circomlib_black_box_functions();
        let bit = &bbfs["bbf_bit"];

        // 5 = 0b101 -> bit0=1, bit1=0, bit2=1, bit3=0.
        let value = BbfFr::from(5u64);
        let one = BbfFr::from(1u64);
        let zero = BbfFr::from(0u64);
        assert_eq!(bit(&[value, BbfFr::from(0u64)]), one);
        assert_eq!(bit(&[value, BbfFr::from(1u64)]), zero);
        assert_eq!(bit(&[value, BbfFr::from(2u64)]), one);
        assert_eq!(bit(&[value, BbfFr::from(3u64)]), zero);
    }
}
