//! Witness Generation Module
//!
//! Computes witnesses for Circom circuits by evaluating a pre-computed
//! `circom-witness-rs` operation graph (see [`WitnessCalculator`]). The
//! runtime evaluator is pure Rust and builds for both native and
//! `wasm32-unknown-unknown`.
//!
//! ## Input JSON Grammar Specification
//!
//! The [`WitnessCalculator::compute_witness`] method accepts a JSON object
//! mapping input signal names to signal values. The accepted grammar enforces:
//!
//! - **Signal Values**: Must be string scalars (e.g. `"123"`) or 1D arrays of
//!   string scalars.
//! - **Number Representation**:
//!   - Decimal strings: `"12345"`
//!   - Hexadecimal strings: `"0x1a2b"` or `"0X1A2B"` (prefixed with `0x`/`0X`)
//! - **Field Constraints**: Values are parsed into BN254 scalar field elements
//!   `[0, p)`. Values exceeding field modulus `p =
//!   21888242871839275222246405745257275088548364400416034343698204186575808495617`
//!   or negative values (e.g. `"-123"`) are strictly rejected.
//! - **Disallowed Formats**: Raw JSON numbers, booleans, nulls, nested objects,
//!   or negative values are rejected.
//! - **Signal Array Bounds**: Array inputs must not exceed the declared
//!   `signalsize` in the circuit graph.
//!
//! ## API Changes & Migration Notes
//!
//! - `WitnessCalculator::from_graph(graph_bytes: &[u8])`: Replaces
//!   `WitnessCalculator::new` for initializing from binary operation graphs.
//! - `witness_size()`: Returns `usize` (formerly `u32`).
//! - `num_public_inputs()`: Removed; public input counts are derived directly
//!   from the circuit verifying key or graph mapping.
//! - `circuit_graph`: Replaces `circuit_wasm` across SDK artifact loading
//!   functions.

use anyhow::{Context as _, Result, bail, ensure};
use ark_bn254::Fr as BbfFr;
use ark_ff::{BigInteger as _, Field as _, PrimeField as _};
use circom_witness_rs::{BlackBoxFunction, Graph, M, calculate_witness, init_graph};
use ruint::aliases::U256;
use std::{
    collections::{HashMap, HashSet},
    string::String,
    sync::Arc,
    vec::Vec,
};
use types::correlation_id_or_new;
use web_time::Instant;

/// Witness calculator backed by a `circom-witness-rs` operation graph.
///
/// On malformed graph data or evaluator faults, lower-level evaluation panics.
/// In release builds (`panic = "abort"` in `Cargo.toml`), a panic will abort
/// the calling thread or worker process. Primary mitigations are input signal
/// validation (unknown signal rejection, per-signal array length validation)
/// and upstream artifact hash verification (`fetch_circuit_file_verified`).
/// Panic catching is intentionally omitted because it is inert in release
/// builds (`panic = "abort"`) and on `wasm32-unknown-unknown` targets.
pub struct WitnessCalculator {
    graph: Graph,
    bbfs: HashMap<String, BlackBoxFunction>,
    /// fnv1a hashes of the graph's known input signal names.
    input_hashes: HashSet<u64>,
    /// Map from fnv1a hash of signal name to declared signalsize.
    input_sizes: HashMap<u64, usize>,
}

#[inline]
fn elapsed_ms(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

impl WitnessCalculator {
    /// Build a calculator from a serialized operation-graph blob.
    ///
    /// Malformed graph data that fails deserialization returns an `Err`.
    /// Evaluator faults panic (aborting the thread/worker in release builds).
    #[tracing::instrument(
        skip_all,
        fields(
            correlation_id = %correlation_id_or_new(),
            graph_len = graph_bytes.len()
        )
    )]
    pub fn from_graph(graph_bytes: &[u8]) -> Result<WitnessCalculator> {
        let start = Instant::now();
        let graph = init_graph(graph_bytes).map_err(|e| {
            tracing::debug!(elapsed_ms = elapsed_ms(start), error = %e, "graph load failed");
            anyhow::anyhow!("Failed to load witness graph: {e}")
        })?;
        let mut input_hashes = HashSet::with_capacity(graph.input_mapping.len());
        let mut input_sizes = HashMap::with_capacity(graph.input_mapping.len());
        for info in &graph.input_mapping {
            input_hashes.insert(info.hash);
            input_sizes.insert(
                info.hash,
                usize::try_from(info.signalsize).unwrap_or(usize::MAX),
            );
        }
        tracing::debug!(
            elapsed_ms = elapsed_ms(start),
            signals_count = graph.input_mapping.len(),
            "graph load succeeded"
        );
        Ok(WitnessCalculator {
            graph,
            bbfs: circomlib_black_box_functions(),
            input_hashes,
            input_sizes,
        })
    }

    /// Compute the witness from JSON inputs, returning little-endian bytes
    /// (32 bytes per field element) compatible with the prover module.
    ///
    /// Rejects any input signal name the graph does not declare or array inputs
    /// exceeding declared signal sizes. On evaluator faults, panics (aborting
    /// the thread/worker in release builds).
    #[tracing::instrument(
        skip(self, inputs_json),
        fields(
            correlation_id = %correlation_id_or_new(),
            json_len = inputs_json.len(),
            signals_count = self.graph.signals.len()
        )
    )]
    pub fn compute_witness(&self, inputs_json: &str) -> Result<Vec<u8>> {
        let start = Instant::now();
        let inputs = parse_inputs(inputs_json).map_err(|e| {
            tracing::debug!(elapsed_ms = elapsed_ms(start), error = %e, "calc failed during json parsing");
            e
        })?;
        let mut unknown: Vec<&str> = inputs
            .keys()
            .filter(|key| !self.input_hashes.contains(&fnv1a(key)))
            .map(String::as_str)
            .collect();
        unknown.sort_unstable();
        if !unknown.is_empty() {
            let msg = format!("unknown circuit input signal(s): {}", unknown.join(", "));
            tracing::debug!(elapsed_ms = elapsed_ms(start), error = %msg, "calc rejected unknown signal");
            bail!("{msg}");
        }
        for (key, values) in &inputs {
            let hash = fnv1a(key);
            if let Some(&expected_size) = self.input_sizes.get(&hash) {
                #[allow(clippy::collapsible_if)]
                if values.len() > expected_size {
                    let msg = format!(
                        "input signal '{key}' length {} exceeds declared size {}",
                        values.len(),
                        expected_size
                    );
                    tracing::debug!(elapsed_ms = elapsed_ms(start), error = %msg, "calc rejected overlong signal");
                    bail!("{msg}");
                }
            }
        }
        let witness = calculate_witness(inputs, &self.graph, Some(&self.bbfs)).map_err(|e| {
            tracing::debug!(elapsed_ms = elapsed_ms(start), error = %e, "calc evaluator failed");
            anyhow::anyhow!("Witness calculation failed: {e}")
        })?;
        let out_bytes = witness_to_bytes(&witness);
        tracing::debug!(
            elapsed_ms = elapsed_ms(start),
            elements_count = witness.len(),
            out_len = out_bytes.len(),
            "calc succeeded"
        );
        Ok(out_bytes)
    }

    /// Number of field elements in the computed witness.
    pub fn witness_size(&self) -> usize {
        self.graph.signals.len()
    }
}

/// Black-box hint functions bound at graph-evaluation time, mirroring the
/// `bbf_*` hints injected into circomlib during graph generation
/// (`inject_black_box_hints` in `circuits/build.rs`). These implement the
/// non-quadratic (`<--`) assignments the graph cannot express directly.
fn circomlib_black_box_functions() -> HashMap<String, BlackBoxFunction> {
    let mut bbfs: HashMap<String, BlackBoxFunction> = HashMap::new();

    // `bbf_inv(in) = in != 0 ? 1/in : 0` — circomlib `IsZero`.
    let bbf_inv: BlackBoxFunction = Arc::new(|params: &[BbfFr]| {
        params
            .first()
            .and_then(|p| p.inverse())
            .unwrap_or_else(|| BbfFr::from(0u64))
    });
    bbfs.insert(String::from("bbf_inv"), bbf_inv);

    // `bbf_bit(in, bit) = (in >> bit) & 1` — circomlib `Num2Bits`.
    let bbf_bit: BlackBoxFunction = Arc::new(|params: &[BbfFr]| {
        let value = match params.first() {
            Some(v) => v.into_bigint(),
            None => return BbfFr::from(0u64),
        };
        let bit_index = match params.get(1) {
            Some(p) => usize::try_from(p.into_bigint().as_ref()[0]).unwrap_or(usize::MAX),
            None => return BbfFr::from(0u64),
        };
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

/// FNV-1a hash of a signal name, matching `circom-witness-rs`'s input mapping
/// (`init_graph`/`get_input_mapping`).
fn fnv1a(s: &str) -> u64 {
    let mut hash: u64 = 0xCBF2_9CE4_8422_2325;
    for byte in s.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    hash
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

    use proptest::prelude::*;

    /// Any BN254 scalar field element: 32 random bytes reduced mod p.
    #[allow(clippy::arithmetic_side_effects)] // U256 rem cannot overflow
    fn arb_field_element() -> impl Strategy<Value = U256> {
        proptest::array::uniform32(any::<u8>()).prop_map(|bytes| U256::from_le_bytes(bytes) % M)
    }

    proptest! {
        #[test]
        fn parse_field_valid_values_in_range(val in arb_field_element()) {
            let dec = val.to_string();
            let parsed_dec = parse_field(&dec).expect("valid decimal");
            prop_assert_eq!(parsed_dec, val);

            let hex = format!("0x{val:x}");
            let parsed_hex = parse_field(&hex).expect("valid hex");
            prop_assert_eq!(parsed_hex, val);
        }

        #[test]
        fn parse_field_rejects_negative_inputs(val in 1u64..1_000_000u64) {
            let neg_dec = format!("-{val}");
            prop_assert!(parse_field(&neg_dec).is_err());
        }

        #[test]
        #[allow(clippy::arithmetic_side_effects)]
        fn parse_field_rejects_values_at_or_above_modulus(offset in 0u64..100u64) {
            let p = ruint::aliases::U256::from_str_radix(MODULUS_DEC, 10)
                .expect("valid modulus dec string");
            let invalid_val = p + ruint::aliases::U256::from(offset);
            let dec = invalid_val.to_string();
            prop_assert!(parse_field(&dec).is_err());
        }
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

        // Empty slice maps to 0 instead of panicking.
        assert_eq!(inv(&[]), BbfFr::from(0u64));
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

    #[test]
    fn bbf_bit_handles_missing_args_and_large_index() {
        let bbfs = circomlib_black_box_functions();
        let bit = &bbfs["bbf_bit"];
        let zero = BbfFr::from(0u64);

        // Zero-arg and one-arg invocations return 0 without panicking.
        assert_eq!(bit(&[]), zero);
        assert_eq!(bit(&[BbfFr::from(5u64)]), zero);

        // Out-of-range / large index returns 0 without panicking.
        let large_idx = BbfFr::from(u64::MAX);
        assert_eq!(bit(&[BbfFr::from(5u64), large_idx]), zero);
    }

    #[test]
    fn compute_witness_rejects_unknown_signal() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deployments/testnet/circuit_keys/policy_tx_2_2.graph.bin"
        );
        let bytes = std::fs::read(path).expect("committed policy_tx_2_2.graph.bin");
        let calc = WitnessCalculator::from_graph(&bytes).expect("init graph");
        let err = calc
            .compute_witness(r#"{"notARealSignal":"0x01"}"#)
            .expect_err("unknown signal must fail");
        assert!(
            err.to_string().contains("unknown circuit input signal"),
            "unexpected error: {err:#}"
        );
        assert!(
            err.to_string().contains("notARealSignal"),
            "error should name the unknown signal: {err:#}"
        );
    }

    #[test]
    fn compute_witness_rejects_overlong_input_length() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deployments/testnet/circuit_keys/policy_tx_2_2.graph.bin"
        );
        let bytes = std::fs::read(path).expect("committed policy_tx_2_2.graph.bin");
        let calc = WitnessCalculator::from_graph(&bytes).expect("init graph");
        let overlong_json = r#"{"root": ["0x01", "0x02", "0x03", "0x04", "0x05", "0x06", "0x07", "0x08", "0x09", "0x0a"]}"#;
        let err = calc
            .compute_witness(overlong_json)
            .expect_err("overlong input array must fail");
        assert!(
            err.to_string().contains("root"),
            "error should name the signal: {err:#}"
        );
        assert!(
            err.to_string().contains("exceeds declared size"),
            "error should mention exceeds declared size: {err:#}"
        );
    }

    /// Reference witness test vector for `selectiveDisclosure_1.graph.bin`.
    ///
    /// The reference witness is calculated from valid constraint-satisfying
    /// inputs using `snarkjs` (snarkjs wtns calculate
    /// selectiveDisclosure_1.wasm) as external ground truth.
    ///
    /// External Reference Provenance:
    /// - Tool: `snarkjs` wtns calculate (snarkjs@0.7.6 / node v26.4.0)
    /// - Circuit: `circuits/src/selectiveDisclosure_1.circom`
    /// - Output: 3,228 32-byte LE field elements (103,296 bytes)
    /// - SHA-256 ground truth:
    ///   `ee2a40e2cce9b56b1b014e258c5efd677f3ad50ee9cf415861ed057f5a72e090`
    #[test]
    fn reference_witness_matches_ground_truth() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deployments/testnet/circuit_keys/selectiveDisclosure_1.graph.bin"
        );
        let bytes = std::fs::read(path).expect("committed selectiveDisclosure_1.graph.bin");
        let calc = WitnessCalculator::from_graph(&bytes).expect("init graph");

        let inputs = r#"{
            "roots": ["8354550786058549577976434124637202567688980534334896811369086748982792901019"],
            "noteCommitments": ["9540031368943096744527080580267672673373745734987132695948350990118182674826"],
            "extContextHash": "12648430",
            "expectedNullifier": ["21300932880541958794316078866515582323866393176870003513921255047755321240688"],
            "inAmount": ["17"],
            "inPrivateKey": ["4242"],
            "inBlinding": ["5151"],
            "inPathIndices": ["7"],
            "inPathElements": [
                "0",
                "15621590199821056450610068202457788725601603091791048810523422053872049975191",
                "15180302612178352054084191513289999058431498575847349863917170755410077436260",
                "20846426933296943402289409165716903143674406371782261099735847433924593192150",
                "19570709311100149041770094415303300085749902031216638721752284824736726831172",
                "14201048120832820422645397150259296061869248997405945838054224275764817194235",
                "5660625903017311559247887778345076230162700318455150332536064787955339261993",
                "16880971202363039595590868515002077894930588104218910176798056929150619690754",
                "20229828059295599926294334104246210291337504066030123008674073000566234311595",
                "19924958690577568862874010439501980682014655592783754133068981766267897515793"
            ]
        }"#;

        let witness_bytes = calc.compute_witness(inputs).expect("compute witness");
        assert_eq!(
            witness_bytes.len(),
            103_296,
            "expected 3228 field elements (32 bytes each)"
        );

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&witness_bytes);
        let digest = hex::encode(hasher.finalize());
        assert_eq!(
            digest, "ee2a40e2cce9b56b1b014e258c5efd677f3ad50ee9cf415861ed057f5a72e090",
            "witness bytes do not match external snarkjs ground truth"
        );
    }

    #[test]
    fn from_graph_rejects_corrupt_bytes() {
        let invalid_bytes = b"not a valid graph file";
        let res = WitnessCalculator::from_graph(invalid_bytes);
        assert!(res.is_err(), "corrupt/invalid graph bytes must return Err");
    }

    /// Smoke: every `.graph.bin` must deserialize and report a
    /// non-trivial witness size.
    #[test]
    fn loads_all_committed_graphs() {
        let dir = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deployments/testnet/circuit_keys"
        );

        let mut loaded = 0usize;
        for entry in std::fs::read_dir(dir).expect("circuit_keys") {
            let path = entry.expect("dir entry").path();
            if !path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".graph.bin"))
            {
                continue;
            }

            let calc = WitnessCalculator::from_graph(&std::fs::read(&path).expect("read graph"))
                .unwrap_or_else(|e| panic!("init {}: {e}", path.display()));
            assert!(calc.witness_size() > 1, "{}: empty witness", path.display());
            loaded += 1;
        }
        assert!(loaded > 0, "no *.graph.bin under {dir}");
    }
}
