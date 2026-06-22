//! Circom witness generation.
//!
//! Browser and native builds use a pre-generated `circom-witness-rs` graph for
//! witness calculation while preserving the JSON input format and witness byte
//! layout consumed by the prover.

mod field;
mod graph_runtime;
mod input_flatten;
mod r1cs_shape;
mod witness_bytes;

use anyhow::{Context as _, Result, anyhow};
use ark_bn254::Fr;
use ark_circom::{WitnessCalculator as ArkWitnessCalculator, circom::R1CSFile};
use circom_witness_rs::Graph;
use num_bigint::BigInt;
use std::{collections::HashMap, io::Cursor, string::String, vec::Vec};
use wasmer::{Module, Store};

use graph_runtime::{compute_graph_witness_bytes, validate_graph_shape};
use input_flatten::flatten_input;
use r1cs_shape::parse_circuit_shape;
use witness_bytes::witness_to_bytes;

/// Get module version.
pub fn version() -> String {
    String::from(env!("CARGO_PKG_VERSION"))
}

/// Witness calculator instance.
pub struct WitnessCalculator {
    backend: WitnessBackend,
    /// Number of variables in the witness.
    witness_size: u32,
    /// Number of R1CS public inputs (does not include public outputs or the
    /// constant signal 1).
    num_public_inputs: u32,
}

enum WitnessBackend {
    Graph(Graph),
    Wasm {
        store: Store,
        calculator: ArkWitnessCalculator,
    },
}

impl WitnessCalculator {
    /// Create a witness calculator from a graph or Circom WASM artifact.
    ///
    /// Policy transaction proving uses a generated graph artifact. Selective
    /// disclosure currently still uses the legacy Circom WASM witness artifact,
    /// so this constructor dispatches by artifact magic for compatibility.
    pub fn new(artifact_bytes: &[u8], r1cs_bytes: &[u8]) -> Result<WitnessCalculator> {
        if artifact_bytes.starts_with(b"\0asm") {
            Self::from_wasm(artifact_bytes, r1cs_bytes)
        } else {
            Self::from_graph(artifact_bytes, r1cs_bytes)
        }
    }

    /// Create a witness calculator from a serialized witness graph and
    /// matching R1CS bytes.
    ///
    /// The graph supplies the execution plan; the R1CS supplies witness sizing
    /// and public-input metadata for compatibility with the existing API.
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

    /// Create a witness calculator from a Circom WASM artifact and matching
    /// R1CS bytes.
    pub fn from_wasm(circuit_wasm: &[u8], r1cs_bytes: &[u8]) -> Result<Self> {
        let cursor = Cursor::new(r1cs_bytes);
        let r1cs_file: R1CSFile<Fr> = R1CSFile::new(cursor).context("Failed to parse R1CS")?;

        let witness_size = r1cs_file.header.n_wires;
        let num_public_inputs = r1cs_file.header.n_pub_in;

        let mut store = Store::default();
        let module = Module::new(&store, circuit_wasm).context("Failed to load circuit WASM")?;
        let calculator = ArkWitnessCalculator::from_module(&mut store, module)
            .map_err(|e| anyhow!("Failed to init witness calc: {e}"))?;

        Ok(Self {
            backend: WitnessBackend::Wasm { store, calculator },
            witness_size,
            num_public_inputs,
        })
    }

    /// Compute witness from JSON inputs.
    ///
    /// # Arguments
    /// * `inputs_json` - JSON string with circuit inputs.
    ///
    /// # Returns
    /// * Witness as Little-Endian bytes (32 bytes per field element).
    pub fn compute_witness(&mut self, inputs_json: &str) -> Result<Vec<u8>> {
        use serde_json::Value;

        let inputs: Value = serde_json::from_str(inputs_json).context("Invalid JSON")?;
        let inputs_map = inputs.as_object().context("Inputs must be a JSON object")?;
        let mut inputs_hashmap: HashMap<String, Vec<BigInt>> = HashMap::new();

        for (key, value) in inputs_map {
            flatten_input(key, value, &mut inputs_hashmap)?;
        }

        match &mut self.backend {
            WitnessBackend::Graph(graph) => {
                compute_graph_witness_bytes(inputs_hashmap, graph, self.witness_size)
            }
            WitnessBackend::Wasm { store, calculator } => {
                let witness = calculator
                    .calculate_witness(store, inputs_hashmap, false)
                    .map_err(|e| anyhow!("Witness calculation failed: {e}"))?;
                Ok(witness_to_bytes(&witness))
            }
        }
    }

    /// Get the witness size (number of field elements).
    pub fn witness_size(&self) -> u32 {
        self.witness_size
    }

    /// Get the R1CS public input count.
    ///
    /// This excludes public outputs and the constant signal. The prover's
    /// verification input vector uses the R1CS total public count
    /// (outputs + inputs).
    pub fn num_public_inputs(&self) -> u32 {
        self.num_public_inputs
    }
}
