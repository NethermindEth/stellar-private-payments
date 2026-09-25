//! Witness Generation Module
//!
//! Computes witnesses for Circom circuits by evaluating a pre-computed
//! `circom-witness-rs` operation graph (see [`WitnessCalculator`]). The
//! runtime evaluator is pure Rust and builds for both native and
//! `wasm32-unknown-unknown`.

use anyhow::{Context as _, Result, bail, ensure};
use ark_bn254::Fr as BbfFr;
use ark_ff::{BigInteger as _, Field as _, PrimeField as _};
use circom_witness_rs::{BlackBoxFunction, Graph, M, calculate_witness, init_graph};
use ruint::aliases::U256;
use std::{
    collections::{BTreeMap, HashMap},
    string::String,
    sync::Arc,
    vec::Vec,
};

/// Witness calculator backed by a `circom-witness-rs` operation graph.
pub struct WitnessCalculator {
    graph: Graph,
    bbfs: HashMap<String, BlackBoxFunction>,
    /// Every input name the graph declares, by fnv1a hash.
    ///
    /// A bus input is declared under several names that cover the same
    /// signals: the whole bus (`p`, all of its fields) and each of its
    /// qualified leaves (`p.x`, `p.y`, `ps[1].path`). Either form can be used,
    /// so presence and double assignment are checked per signal, not per name.
    inputs: HashMap<u64, InputSpan>,
    /// One past the last input signal id.
    inputs_end: usize,
}

/// The input signals `start..end` one declared name assigns.
#[derive(Clone, Copy)]
struct InputSpan {
    start: usize,
    end: usize,
}

impl InputSpan {
    fn size(self) -> usize {
        self.end.saturating_sub(self.start)
    }

    fn strictly_contains(self, other: InputSpan) -> bool {
        self.start <= other.start && other.end <= self.end && self.size() > other.size()
    }
}

impl WitnessCalculator {
    /// Build a calculator from a serialized operation-graph blob.
    pub fn from_graph(graph_bytes: &[u8]) -> Result<WitnessCalculator> {
        let graph = init_graph(graph_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to load witness graph: {e}"))?;
        // `input_mapping` is circom's open-addressing hash table. A slot is
        // empty when its signal id is 0, the same test circom's own
        // `getInputSignalHashPosition` uses (id 0 is the constant one).
        let inputs = graph
            .input_mapping
            .iter()
            .filter(|info| info.signalid != 0)
            .map(|info| {
                let start = usize::try_from(info.signalid)?;
                let end = usize::try_from(info.signalsize)?
                    .checked_add(start)
                    .context("input signal span overflows usize")?;
                Ok((info.hash, InputSpan { start, end }))
            })
            .collect::<Result<HashMap<_, _>>>()?;
        let inputs_end = inputs.values().map(|span| span.end).max().unwrap_or(0);
        Ok(WitnessCalculator {
            graph,
            bbfs: circomlib_black_box_functions(),
            inputs,
            inputs_end,
        })
    }

    /// Compute the witness from JSON inputs, returning little-endian bytes
    /// (32 bytes per field element) compatible with the prover module.
    ///
    /// The inputs must assign every input signal of the circuit exactly once.
    /// See [`WitnessCalculator::check_inputs`].
    pub fn compute_witness(&self, inputs_json: &str) -> Result<Vec<u8>> {
        let inputs = parse_inputs(inputs_json)?;
        self.check_inputs(&inputs)?;
        let witness = calculate_witness(inputs, &self.graph, Some(&self.bbfs))
            .map_err(|e| anyhow::anyhow!("Witness calculation failed: {e}"))?;
        Ok(witness_to_bytes(&witness))
    }

    /// Reject inputs that circom-witness-rs would not report itself: names
    /// the graph does not declare (it panics on those), values of the wrong
    /// length, signals assigned under two names (the result would depend on
    /// map iteration order) and signals left unassigned (they would be
    /// zero-padded and only surface later as a failed proof).
    ///
    /// Each check runs on its own and every problem found goes into one
    /// error, so the result does not depend on the order of the checks.
    fn check_inputs(&self, inputs: &HashMap<String, Vec<U256>>) -> Result<()> {
        let mut unknown = Vec::new();
        let mut wrong_size = Vec::new();
        let mut known = Vec::new();
        for (name, values) in inputs {
            match self.inputs.get(&fnv1a(name)) {
                None => unknown.push(name.as_str()),
                Some(&span) => {
                    if values.len() != span.size() {
                        wrong_size.push(format!(
                            "{name} (expected {}, got {})",
                            span.size(),
                            values.len()
                        ));
                    }
                    known.push((name.as_str(), span));
                }
            }
        }

        // How many of the given names assign each input signal.
        let mut assigned = vec![0u32; self.inputs_end];
        for (_, span) in &known {
            for count in assigned.get_mut(span.start..span.end).into_iter().flatten() {
                *count = count.saturating_add(1);
            }
        }
        let signals = |span: InputSpan| assigned.get(span.start..span.end).unwrap_or_default();

        let mut twice: Vec<&str> = known
            .iter()
            .filter(|(_, span)| signals(*span).iter().any(|&n| n > 1))
            .map(|(name, _)| *name)
            .collect();

        let missing = self.unassigned(&assigned);

        unknown.sort_unstable();
        wrong_size.sort_unstable();
        twice.sort_unstable();
        let mut problems = Vec::new();
        if !unknown.is_empty() {
            problems.push(format!(
                "unknown circuit input signal(s): {}",
                unknown.join(", ")
            ));
        }
        if !wrong_size.is_empty() {
            problems.push(format!(
                "circuit input signal(s) of the wrong size: {}",
                wrong_size.join(", ")
            ));
        }
        if !twice.is_empty() {
            problems.push(format!(
                "circuit input signal(s) assigned more than once: {}",
                twice.join(", ")
            ));
        }
        if !missing.is_empty() {
            problems.push(format!(
                "missing circuit input signal(s): {}",
                missing.join(", ")
            ));
        }
        ensure!(
            problems.is_empty(),
            "invalid circuit inputs: {}",
            problems.join("; ")
        );
        Ok(())
    }

    /// Describe every declared name with an input signal nobody assigned.
    ///
    /// Only the innermost such names are listed, so a missing bus leaf is not
    /// reported a second time through the whole bus that contains it. The
    /// graph keeps only the fnv1a hash of each name, so a name nobody passed
    /// can only be pointed at by its signals and its hash.
    fn unassigned(&self, assigned: &[u32]) -> Vec<String> {
        let incomplete = |span: InputSpan| {
            assigned
                .get(span.start..span.end)
                .is_none_or(|counts| counts.contains(&0))
        };
        let spans: Vec<InputSpan> = self
            .inputs
            .values()
            .copied()
            .filter(|&span| incomplete(span))
            .collect();
        let mut missing: BTreeMap<(usize, usize), Vec<u64>> = BTreeMap::new();
        for (&hash, &span) in &self.inputs {
            if incomplete(span) && !spans.iter().any(|&inner| span.strictly_contains(inner)) {
                missing
                    .entry((span.start, span.end))
                    .or_default()
                    .push(hash);
            }
        }
        missing
            .into_iter()
            .map(|((start, end), mut hashes)| {
                hashes.sort_unstable();
                let hashes: Vec<String> = hashes.iter().map(|h| format!("{h:#018x}")).collect();
                format!("signals {start}..{end} (name hash {})", hashes.join(" or "))
            })
            .collect()
    }

    /// Number of field elements in the computed witness.
    pub fn witness_size(&self) -> usize {
        self.graph.signals.len()
    }
}

/// Black-box hint functions bound at graph-evaluation time, mirroring the
/// `bbf_*` hints injected into circomlib during graph generation
/// (`inject_black_box_hints` in `tools/circuit-compiler`). These implement the
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
        // The prover never emits nested arrays; reject rather than silently
        // flatten.
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

    /// Serialize `(name, values)` pairs as the flat JSON object
    /// `compute_witness` takes.
    fn inputs_json(inputs: &[(&str, Vec<u64>)]) -> String {
        let obj: serde_json::Map<String, serde_json::Value> = inputs
            .iter()
            .map(|(name, values)| {
                let values = values
                    .iter()
                    .map(|v| serde_json::Value::String(format!("{v:#x}")))
                    .collect();
                (String::from(*name), serde_json::Value::Array(values))
            })
            .collect();
        serde_json::Value::Object(obj).to_string()
    }

    fn name_hash(name: &str) -> String {
        format!("{:#018x}", fnv1a(name))
    }

    fn load_graph(path: &str) -> WitnessCalculator {
        let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        WitnessCalculator::from_graph(&bytes).expect("init graph")
    }

    /// Every input signal of `selectiveDisclosure_1`, sized from the graph
    /// itself so the fixture stays correct if the circuit's tree depth moves.
    const DISCLOSURE_SIGNALS: [&str; 9] = [
        "roots",
        "noteCommitments",
        "extContextHash",
        "expectedNullifier",
        "inAmount",
        "inPrivateKey",
        "inBlinding",
        "inPathIndices",
        "inPathElements",
    ];

    fn disclosure_calculator() -> WitnessCalculator {
        load_graph(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deployments/testnet/circuit_keys/selectiveDisclosure_1.graph.bin"
        ))
    }

    /// Build a complete, correctly sized input set, optionally dropping one
    /// signal or truncating one by a single element.
    fn disclosure_inputs(
        calc: &WitnessCalculator,
        drop: Option<&str>,
        short: Option<&str>,
    ) -> String {
        let inputs: Vec<(&str, Vec<u64>)> = DISCLOSURE_SIGNALS
            .into_iter()
            .filter(|name| drop != Some(*name))
            .map(|name| {
                let mut size = calc
                    .inputs
                    .get(&fnv1a(name))
                    .unwrap_or_else(|| panic!("{name} is declared by the graph"))
                    .size();
                if short == Some(name) {
                    size = size.saturating_sub(1);
                }
                let size = u64::try_from(size).expect("size fits in u64");
                (name, (1..=size).collect())
            })
            .collect();
        inputs_json(&inputs)
    }

    #[test]
    fn compute_witness_rejects_missing_signal() {
        let calc = disclosure_calculator();
        let err = calc
            .compute_witness(&disclosure_inputs(&calc, Some("inBlinding"), None))
            .expect_err("a missing signal must fail instead of being zero-padded");
        assert!(
            err.to_string().contains("missing circuit input signal"),
            "unexpected error: {err:#}"
        );
        assert!(
            err.to_string().contains(&name_hash("inBlinding")),
            "error should point at the missing signal: {err:#}"
        );
    }

    #[test]
    fn compute_witness_rejects_short_signal() {
        let calc = disclosure_calculator();
        let err = calc
            .compute_witness(&disclosure_inputs(&calc, None, Some("inPathElements")))
            .expect_err("a short signal must fail instead of being zero-padded");
        assert!(
            err.to_string()
                .contains("circuit input signal(s) of the wrong size: inPathElements"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn compute_witness_accepts_complete_inputs() {
        let calc = disclosure_calculator();
        let bytes = calc
            .compute_witness(&disclosure_inputs(&calc, None, None))
            .expect("a complete, correctly sized input set still builds a witness");
        assert_eq!(bytes.len(), calc.witness_size() * 32);
    }

    #[test]
    fn compute_witness_reports_unknown_and_missing_together() {
        // The missing check must find the absent signal on its own, not rely
        // on the unknown check having filtered the input first.
        let calc = disclosure_calculator();
        let mut inputs: serde_json::Value =
            serde_json::from_str(&disclosure_inputs(&calc, Some("inAmount"), None))
                .expect("fixture is JSON");
        inputs["notARealSignal"] = serde_json::Value::String(String::from("0x01"));
        let err = calc
            .compute_witness(&inputs.to_string())
            .expect_err("unknown and missing signals must fail");
        let err = err.to_string();
        assert!(
            err.contains("unknown circuit input signal(s): notARealSignal"),
            "unexpected error: {err}"
        );
        assert!(
            err.contains("missing circuit input signal") && err.contains(&name_hash("inAmount")),
            "the missing signal should be reported too: {err}"
        );
    }

    /// Graph of `circuits/src/test/circuits/bus_input_test.circom`: a plain
    /// input `a`, a bus array `leaves[2][1]` of `Leaf { value, path[2] }` and
    /// a nested bus `pair` of `Pair { left: Leaf, right: Leaf }`.
    fn bus_calculator() -> WitnessCalculator {
        load_graph(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/zk/witness/testdata/bus_input_test.graph.bin"
        ))
    }

    /// The bus inputs passed field by field, with values 2..=13 in the
    /// circuit's signal order.
    fn bus_fields() -> Vec<(&'static str, Vec<u64>)> {
        vec![
            ("a", vec![1]),
            ("leaves[0][0].value", vec![2]),
            ("leaves[0][0].path", vec![3, 4]),
            ("leaves[1][0].value", vec![5]),
            ("leaves[1][0].path", vec![6, 7]),
            ("pair.left.value", vec![8]),
            ("pair.left.path", vec![9, 10]),
            ("pair.right.value", vec![11]),
            ("pair.right.path", vec![12, 13]),
        ]
    }

    /// The same values with each bus passed whole.
    fn bus_whole() -> Vec<(&'static str, Vec<u64>)> {
        vec![
            ("a", vec![1]),
            ("leaves", (2..=7).collect()),
            ("pair", (8..=13).collect()),
        ]
    }

    #[test]
    fn bus_input_accepts_fields_or_whole_bus() {
        let calc = bus_calculator();
        let by_field = calc
            .compute_witness(&inputs_json(&bus_fields()))
            .expect("every bus field given");
        let whole = calc
            .compute_witness(&inputs_json(&bus_whole()))
            .expect("every bus given whole");
        assert_eq!(by_field, whole, "both forms assign the same signals");

        // out = a * (2 + 3 + ... + 13), and it sits right after the constant.
        let out = U256::from_le_slice(&by_field[32..64]);
        assert_eq!(out, U256::from((2..=13u64).sum::<u64>()));
    }

    #[test]
    fn bus_input_rejects_missing_bus() {
        let calc = bus_calculator();
        let inputs: Vec<_> = bus_fields()
            .into_iter()
            .filter(|(name, _)| !name.starts_with("pair."))
            .collect();
        let err = calc
            .compute_witness(&inputs_json(&inputs))
            .expect_err("a missing bus must fail instead of being zero-padded");
        let err = err.to_string();
        assert!(
            err.contains("missing circuit input signal"),
            "unexpected error: {err}"
        );
        for field in [
            "pair.left.value",
            "pair.left.path",
            "pair.right.value",
            "pair.right.path",
        ] {
            assert!(
                err.contains(&name_hash(field)),
                "{field} should be reported: {err}"
            );
        }

        let whole: Vec<_> = bus_whole()
            .into_iter()
            .filter(|(name, _)| *name != "leaves")
            .collect();
        let err = calc
            .compute_witness(&inputs_json(&whole))
            .expect_err("a missing whole bus must fail too");
        assert!(
            err.to_string().contains(&name_hash("leaves[1][0].path")),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn bus_input_rejects_missing_bus_field() {
        let calc = bus_calculator();
        let inputs: Vec<_> = bus_fields()
            .into_iter()
            .filter(|(name, _)| *name != "leaves[1][0].path")
            .collect();
        let err = calc
            .compute_witness(&inputs_json(&inputs))
            .expect_err("a missing bus field must fail");
        let err = err.to_string();
        assert!(
            err.contains(&format!(
                "missing circuit input signal(s): signals 7..9 (name hash {})",
                name_hash("leaves[1][0].path")
            )),
            "only the missing field should be reported: {err}"
        );
        assert!(
            !err.contains(&name_hash("leaves")),
            "the partly given bus is not missing as a whole: {err}"
        );
    }

    #[test]
    fn bus_input_rejects_short_bus() {
        let calc = bus_calculator();
        let mut whole = bus_whole();
        whole[1].1.pop();
        let err = calc
            .compute_witness(&inputs_json(&whole))
            .expect_err("a short bus must fail instead of being zero-padded");
        assert!(
            err.to_string()
                .contains("circuit input signal(s) of the wrong size: leaves (expected 6, got 5)"),
            "unexpected error: {err:#}"
        );

        let mut fields = bus_fields();
        fields[8].1.pop();
        let err = calc
            .compute_witness(&inputs_json(&fields))
            .expect_err("a short bus field must fail");
        assert!(
            err.to_string().contains(
                "circuit input signal(s) of the wrong size: pair.right.path (expected 2, got 1)"
            ),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn bus_input_rejects_field_given_twice() {
        // `pair` and `pair.left.value` both assign signal 8; which one wins
        // would depend on map iteration order.
        let calc = bus_calculator();
        let mut inputs = bus_whole();
        inputs.push(("pair.left.value", vec![99]));
        let err = calc
            .compute_witness(&inputs_json(&inputs))
            .expect_err("a signal assigned twice must fail");
        assert!(
            err.to_string()
                .contains("circuit input signal(s) assigned more than once: pair, pair.left.value"),
            "unexpected error: {err:#}"
        );
    }
}
