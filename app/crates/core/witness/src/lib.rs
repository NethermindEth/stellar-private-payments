//! Circom witness generation.
//!
//! Browser builds use `ark-circom` and Wasmer. Native builds use a
//! pre-generated `circom-witness-rs` graph while preserving the JSON input
//! format and witness byte layout consumed by the prover.

use anyhow::{Context as _, Result, anyhow};
#[cfg(target_arch = "wasm32")]
use ark_circom::WitnessCalculator as ArkWitnessCalculator;
#[cfg(not(target_arch = "wasm32"))]
use ark_ff_05::{AdditiveGroup as _, BigInteger as _, Field as _, PrimeField as _};
#[cfg(not(target_arch = "wasm32"))]
use circom_witness_rs::{Graph, HashSignalInfo};
use num_bigint::{BigInt, Sign};
#[cfg(not(target_arch = "wasm32"))]
use ruint::aliases::U256;
// These are part of the reduced STD that is browser compatible
#[cfg(not(target_arch = "wasm32"))]
use std::collections::HashSet;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::Arc;
use std::{collections::HashMap, string::String, vec::Vec};
#[cfg(target_arch = "wasm32")]
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
    backend: WitnessBackend,
    /// Number of variables in the witness
    witness_size: u32,
    /// Number of public inputs (does not include public outputs or the constant
    /// signal 1)
    num_public_inputs: u32,
}

enum WitnessBackend {
    #[cfg(target_arch = "wasm32")]
    Wasmer {
        store: Store,
        calculator: ArkWitnessCalculator,
    },
    #[cfg(not(target_arch = "wasm32"))]
    Graph(Graph),
}

impl WitnessCalculator {
    /// Create a browser witness calculator from circuit WASM and R1CS bytes
    ///
    /// # Arguments
    /// * `circuit_wasm` - The compiled circuit WASM bytes
    /// * `r1cs_bytes` - The R1CS constraint system bytes
    #[cfg(target_arch = "wasm32")]
    pub fn new(circuit_wasm: &[u8], r1cs_bytes: &[u8]) -> Result<WitnessCalculator> {
        let circuit_shape = parse_circuit_shape(r1cs_bytes)?;

        // Create wasmer store and load circuit module from bytes
        let mut store = Store::default();
        let module = Module::new(&store, circuit_wasm).context("Failed to load circuit WASM")?;

        // Create witness calculator from module
        let calculator = ArkWitnessCalculator::from_module(&mut store, module)
            .map_err(|e| anyhow::anyhow!("Failed to init witness calc: {e}"))?;

        Ok(Self {
            backend: WitnessBackend::Wasmer { store, calculator },
            witness_size: circuit_shape.witness_size,
            num_public_inputs: circuit_shape.num_public_inputs,
        })
    }

    /// Create a native witness calculator from graph and R1CS bytes.
    ///
    /// Native callers pass the generated `*.graph.bin` artifact as the witness
    /// program. Browser callers pass the Circom WASM to the `wasm32`
    /// constructor above.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn new(graph_bytes: &[u8], r1cs_bytes: &[u8]) -> Result<WitnessCalculator> {
        Self::from_graph(graph_bytes, r1cs_bytes)
    }

    /// Create a native witness calculator from a serialized witness graph and
    /// matching R1CS bytes.
    ///
    /// The graph supplies the execution plan; the R1CS supplies the witness and
    /// public-input sizing expected by the prover.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_graph(graph_bytes: &[u8], r1cs_bytes: &[u8]) -> Result<Self> {
        let circuit_shape = parse_circuit_shape(r1cs_bytes)?;
        let graph = circom_witness_rs::init_graph(graph_bytes)
            .map_err(|e| anyhow!("Failed to parse witness graph: {e}"))?;
        validate_graph_shape(&graph, circuit_shape.witness_size)?;

        Ok(Self {
            backend: WitnessBackend::Graph(graph),
            witness_size: circuit_shape.witness_size,
            num_public_inputs: circuit_shape.num_public_inputs,
        })
    }

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

        match &mut self.backend {
            #[cfg(target_arch = "wasm32")]
            WitnessBackend::Wasmer { store, calculator } => {
                let witness = calculator
                    .calculate_witness(store, inputs_hashmap, false)
                    .map_err(|e| anyhow::anyhow!("Witness calculation failed: {e}"))?;

                Ok(witness_to_bytes(&witness))
            }
            #[cfg(not(target_arch = "wasm32"))]
            WitnessBackend::Graph(graph) => {
                let witness_inputs = inputs_hashmap_to_u256(inputs_hashmap)?;
                validate_graph_inputs(&witness_inputs, graph)?;
                let witness = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    circom_witness_rs::calculate_witness(
                        witness_inputs,
                        graph,
                        Some(&native_black_box_functions()),
                    )
                }))
                .map_err(|_| anyhow!("Witness graph calculation panicked after input validation"))?
                .map_err(|e| anyhow!("Witness graph calculation failed: {e}"))?;
                ensure_witness_len(&witness, self.witness_size)?;

                Ok(witness_u256_to_bytes(&witness))
            }
        }
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

#[derive(Debug)]
struct CircuitShape {
    witness_size: u32,
    num_public_inputs: u32,
}

fn parse_circuit_shape(r1cs_bytes: &[u8]) -> Result<CircuitShape> {
    let mut cursor = R1csCursor::new(r1cs_bytes);
    let magic = cursor.read_bytes(4)?;
    if magic != b"r1cs" {
        anyhow::bail!("Invalid R1CS magic number");
    }

    let version = cursor.read_u32_le()?;
    if version != 1 {
        anyhow::bail!("Unsupported R1CS version: {version}");
    }

    let num_sections = cursor.read_u32_le()?;
    for _ in 0..num_sections {
        let section_type = cursor.read_u32_le()?;
        let section_size = cursor.read_u64_le()?;
        let section_size =
            usize::try_from(section_size).context("R1CS section size does not fit usize")?;

        if section_type == 1 {
            let section_start = cursor.position;
            let field_size = cursor.read_u32_le()?;
            if field_size != 32 {
                anyhow::bail!("Unsupported R1CS field size: {field_size} (expected 32)");
            }
            let field_size = usize::try_from(field_size).expect("field size is fixed");
            let modulus = cursor.read_bytes(field_size)?;
            if modulus != bn254_field_modulus_le_bytes().as_slice() {
                anyhow::bail!("R1CS field modulus is not BN254");
            }

            let witness_size = cursor.read_u32_le()?;
            cursor.read_u32_le()?; // public outputs
            let num_public_inputs = cursor.read_u32_le()?;
            cursor.read_u32_le()?; // private inputs

            let consumed = cursor
                .position
                .checked_sub(section_start)
                .ok_or_else(|| anyhow!("Invalid R1CS cursor position"))?;
            let remaining = section_size
                .checked_sub(consumed)
                .ok_or_else(|| anyhow!("R1CS header exceeds section size"))?;
            cursor.skip(remaining)?;

            return Ok(CircuitShape {
                witness_size,
                num_public_inputs,
            });
        }

        cursor.skip(section_size)?;
    }

    anyhow::bail!("Missing R1CS header section")
}

struct R1csCursor<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> R1csCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(len)
            .ok_or_else(|| anyhow!("Overflow in R1CS cursor position"))?;
        if end > self.data.len() {
            anyhow::bail!("Unexpected end of R1CS data");
        }
        let bytes = &self.data[self.position..end];
        self.position = end;
        Ok(bytes)
    }

    fn read_u32_le(&mut self) -> Result<u32> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64_le(&mut self) -> Result<u64> {
        let bytes = self.read_bytes(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn skip(&mut self, len: usize) -> Result<()> {
        self.read_bytes(len).map(|_| ())
    }
}

/// Convert a BigInt to its field element representation.
/// Negative numbers are converted to p - |value| where p is the field modulus.
/// Relevant for ZK proof computation. For on-chain token transfer
/// we use a I256 passed to the contract.
fn to_field_element(bi: BigInt) -> Result<BigInt> {
    let modulus = bn254_field_modulus();

    if bi.sign() == Sign::Minus {
        let abs_value = bi
            .checked_mul(&BigInt::from(-1))
            .expect("Overflow in getting the abs value"); // Get absolute value

        if abs_value >= modulus {
            anyhow::bail!("Negative value {bi} exceeds field modulus");
        }

        // For negative n: field_element = p - |n|
        Ok(modulus
            .checked_sub(&abs_value)
            .expect("Overflow in field element computation"))
    } else {
        if bi >= modulus {
            anyhow::bail!("Value {bi} exceeds field modulus");
        }
        Ok(bi)
    }
}

fn bn254_field_modulus() -> BigInt {
    BigInt::parse_bytes(BN254_FIELD_MODULUS.as_bytes(), 10).expect("Invalid field modulus")
}

fn bn254_field_modulus_le_bytes() -> [u8; 32] {
    let bytes = bn254_field_modulus().to_bytes_le().1;
    let mut padded = [0u8; 32];
    padded[..bytes.len()].copy_from_slice(&bytes);
    padded
}

#[cfg(not(target_arch = "wasm32"))]
fn inputs_hashmap_to_u256(
    inputs: HashMap<String, Vec<BigInt>>,
) -> Result<HashMap<String, Vec<U256>>> {
    inputs
        .into_iter()
        .map(|(key, values)| {
            let converted = values
                .into_iter()
                .map(bigint_to_u256)
                .collect::<Result<Vec<_>>>()
                .with_context(|| format!("Invalid field element for {key}"))?;
            Ok((key, converted))
        })
        .collect()
}

#[cfg(not(target_arch = "wasm32"))]
fn bigint_to_u256(value: BigInt) -> Result<U256> {
    if value.sign() == Sign::Minus {
        anyhow::bail!("field element is negative");
    }

    let modulus = bn254_field_modulus();
    if value >= modulus {
        anyhow::bail!("field element is outside the BN254 scalar field");
    }

    let bytes = value.to_bytes_le().1;
    if bytes.len() > 32 {
        anyhow::bail!("field element exceeds 32 bytes");
    }

    let mut padded = [0u8; 32];
    padded[..bytes.len()].copy_from_slice(&bytes);
    Ok(U256::from_le_bytes(padded))
}

#[cfg(not(target_arch = "wasm32"))]
fn validate_graph_shape(graph: &Graph, expected_witness_size: u32) -> Result<()> {
    let expected_witness_size =
        usize::try_from(expected_witness_size).context("R1CS witness size does not fit usize")?;
    if graph.signals.len() != expected_witness_size {
        anyhow::bail!(
            "Witness graph output size {} does not match R1CS witness size {}",
            graph.signals.len(),
            expected_witness_size
        );
    }

    let inputs_size = circom_witness_rs::get_inputs_size(graph);
    let mut seen_hashes = HashMap::new();
    for input in &graph.input_mapping {
        let start = usize::try_from(input.signalid)
            .context("Witness graph input signal index does not fit usize")?;
        let width = usize::try_from(input.signalsize)
            .context("Witness graph input width does not fit usize")?;
        let end = start
            .checked_add(width)
            .ok_or_else(|| anyhow!("Witness graph input range overflows usize"))?;
        if end > inputs_size {
            anyhow::bail!(
                "Witness graph input range [{start}, {end}) exceeds input buffer size {inputs_size}"
            );
        }

        if let Some(previous) = seen_hashes.insert(input.hash, input) {
            anyhow::bail!(
                "Witness graph contains duplicate input hash {} for signal IDs {} and {}",
                input.hash,
                previous.signalid,
                input.signalid
            );
        }
    }

    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
fn validate_graph_inputs(inputs: &HashMap<String, Vec<U256>>, graph: &Graph) -> Result<()> {
    let metadata_by_hash: HashMap<u64, &HashSignalInfo> = graph
        .input_mapping
        .iter()
        .map(|input| (input.hash, input))
        .collect();
    let mut provided_hashes = HashSet::with_capacity(inputs.len());

    for (name, values) in inputs {
        let input_hash = fnv1a(name);
        let input = metadata_by_hash
            .get(&input_hash)
            .with_context(|| format!("Unknown circuit input `{name}`"))?;
        provided_hashes.insert(input_hash);

        let expected_len = usize::try_from(input.signalsize)
            .context("Witness graph input width does not fit usize")?;
        if values.len() != expected_len {
            anyhow::bail!(
                "Input `{name}` has {} value(s), expected {}",
                values.len(),
                expected_len
            );
        }
    }

    for input in &graph.input_mapping {
        if !provided_hashes.contains(&input.hash) {
            anyhow::bail!(
                "Missing circuit input with witness graph hash {}",
                input.hash
            );
        }
    }

    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
fn ensure_witness_len(witness: &[U256], expected_witness_size: u32) -> Result<()> {
    let expected_witness_size =
        usize::try_from(expected_witness_size).context("R1CS witness size does not fit usize")?;
    if witness.len() != expected_witness_size {
        anyhow::bail!(
            "Witness graph produced {} field element(s), expected {}",
            witness.len(),
            expected_witness_size
        );
    }

    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
fn fnv1a(input: &str) -> u64 {
    let mut hash: u64 = 0xCBF29CE484222325;
    for byte in input.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001B3);
    }
    hash
}

#[cfg(not(target_arch = "wasm32"))]
fn native_black_box_functions() -> HashMap<String, circom_witness_rs::BlackBoxFunction> {
    let mut bbfs: HashMap<String, circom_witness_rs::BlackBoxFunction> = HashMap::new();
    bbfs.insert(
        "bbf_inv".to_string(),
        Arc::new(|args| args[0].inverse().unwrap_or(ark_bn254_05::Fr::ZERO)),
    );
    bbfs.insert(
        "bbf_bit".to_string(),
        Arc::new(|args| {
            let value = fr_to_u256(args[0]);
            let bit = fr_to_u256(args[1]).try_into().unwrap_or(usize::MAX);
            if bit < 256 && value.bit(bit) {
                ark_bn254_05::Fr::from(1u64)
            } else {
                ark_bn254_05::Fr::ZERO
            }
        }),
    );
    bbfs
}

#[cfg(not(target_arch = "wasm32"))]
fn fr_to_u256(value: ark_bn254_05::Fr) -> U256 {
    let bytes = value.into_bigint().to_bytes_le();
    let mut padded = [0u8; 32];
    padded[..bytes.len()].copy_from_slice(&bytes);
    U256::from_le_bytes(padded)
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
                let field_element = to_field_element(bi)
                    .with_context(|| format!("Invalid field element for {current_key}"))?;
                inputs.entry(current_key).or_default().push(field_element);
            }
            Value::String(s) => {
                let bi = if let Some(hex) = s.strip_prefix("0x") {
                    BigInt::parse_bytes(hex.as_bytes(), 16)
                } else {
                    BigInt::parse_bytes(s.as_bytes(), 10)
                };
                let bi = bi.context(format!("Invalid bigint for {current_key}: {s}"))?;
                // Convert to field element (handles negative numbers)
                let field_element = to_field_element(bi)
                    .with_context(|| format!("Invalid field element for {current_key}"))?;
                inputs.entry(current_key).or_default().push(field_element);
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
                    inputs.entry(key.to_string()).or_default().push(
                        to_field_element(bi)
                            .with_context(|| format!("Invalid field element for {key}"))?,
                    );
                }
                Value::String(s) => {
                    let bi = if let Some(hex) = s.strip_prefix("0x") {
                        BigInt::parse_bytes(hex.as_bytes(), 16)
                    } else {
                        BigInt::parse_bytes(s.as_bytes(), 10)
                    };
                    let bi = bi.context(format!("Invalid bigint for {key}: {s}"))?;
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
#[cfg(any(test, target_arch = "wasm32"))]
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

#[cfg(not(target_arch = "wasm32"))]
fn witness_u256_to_bytes(witness: &[U256]) -> Vec<u8> {
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

    #[test]
    fn r1cs_shape_parser_reads_header_without_wasmer_dependencies() {
        let shape = parse_circuit_shape(&r1cs_header_bytes(3, 1))
            .expect("minimal R1CS header should parse");

        assert_eq!(shape.witness_size, 3);
        assert_eq!(shape.num_public_inputs, 1);
    }

    #[test]
    fn r1cs_shape_parser_rejects_non_bn254_field_modulus() {
        let mut r1cs = r1cs_header_bytes(3, 1);
        r1cs[28] ^= 1;

        let err = parse_circuit_shape(&r1cs).expect_err("non-BN254 R1CS must fail");

        assert!(
            err.to_string().contains("R1CS field modulus is not BN254"),
            "{err:#}"
        );
    }

    #[test]
    fn field_element_normalization_rejects_positive_modulus_instead_of_panicking() {
        let err = to_field_element(bn254_field_modulus())
            .expect_err("field modulus itself is not a canonical field element");

        assert!(err.to_string().contains("exceeds field modulus"), "{err:#}");
    }

    #[test]
    fn field_element_normalization_rejects_negative_modulus_instead_of_panicking() {
        let err = to_field_element(-bn254_field_modulus())
            .expect_err("negative modulus magnitude is not a field element");

        assert!(err.to_string().contains("exceeds field modulus"), "{err:#}");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn graph_witness_bytes_match_existing_little_endian_layout() {
        let graph_witness = vec![U256::from(1), U256::from(0x1234_u64)];
        let wasmer_witness = vec![BigInt::from(1), BigInt::from(0x1234_u64)];

        assert_eq!(
            witness_u256_to_bytes(&graph_witness),
            witness_to_bytes(&wasmer_witness)
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn graph_inputs_reject_unknown_names_before_runtime_population() {
        let graph = graph_with_amount_input();
        let mut inputs = HashMap::new();
        inputs.insert("unknown".to_string(), vec![U256::from(7)]);

        let err = validate_graph_inputs(&inputs, &graph)
            .expect_err("unknown graph input must fail before runtime population");

        assert!(err.to_string().contains("Unknown circuit input `unknown`"));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn graph_inputs_reject_wrong_signal_width_before_runtime_population() {
        let graph = graph_with_amount_input();
        let mut inputs = HashMap::new();
        inputs.insert("amount".to_string(), vec![U256::from(7), U256::from(8)]);

        let err = validate_graph_inputs(&inputs, &graph)
            .expect_err("wrong graph input width must fail before runtime population");

        assert!(
            err.to_string()
                .contains("Input `amount` has 2 value(s), expected 1"),
            "{err:#}"
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn graph_inputs_reject_missing_names_before_zero_filling() {
        let graph = graph_with_amount_input();
        let inputs = HashMap::new();

        let err = validate_graph_inputs(&inputs, &graph)
            .expect_err("missing graph input must not be silently zero-filled");

        assert!(
            err.to_string()
                .contains("Missing circuit input with witness graph hash"),
            "{err:#}"
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn graph_shape_must_match_r1cs_witness_size() {
        let graph = graph_with_amount_input();
        let err = validate_graph_shape(&graph, 2)
            .expect_err("graph/R1CS witness-size mismatch must fail at construction");

        assert!(
            err.to_string()
                .contains("Witness graph output size 1 does not match R1CS witness size 2"),
            "{err:#}"
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn graph_field_conversion_rejects_values_outside_bn254_scalar_field() {
        let modulus =
            BigInt::parse_bytes(BN254_FIELD_MODULUS.as_bytes(), 10).expect("valid modulus");
        let err = bigint_to_u256(modulus)
            .expect_err("canonical graph inputs must stay inside the scalar field");

        assert!(
            err.to_string()
                .contains("field element is outside the BN254 scalar field"),
            "{err:#}"
        );
    }

    fn r1cs_header_bytes(num_wires: u32, num_pub_in: u32) -> Vec<u8> {
        const HEADER_SIZE: u64 = 64;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"r1cs");
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&HEADER_SIZE.to_le_bytes());
        bytes.extend_from_slice(&32u32.to_le_bytes());
        bytes.extend_from_slice(&bn254_field_modulus_le_bytes());
        bytes.extend_from_slice(&num_wires.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&num_pub_in.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn graph_with_amount_input() -> Graph {
        Graph {
            nodes: vec![circom_witness_rs::graph::Node::Input(0)],
            signals: vec![0],
            input_mapping: vec![HashSignalInfo {
                hash: fnv1a("amount"),
                signalid: 0,
                signalsize: 1,
            }],
        }
    }
}
