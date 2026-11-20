//! The part of `arkworks-rs/circom-compat` the circuit tools and tests use,
//! without its `wasmer` WASM runtime: R1CS reader, Circom circuit and QAP
//! reduction, plus witnesses calculated by Node (`witness`) and read from
//! snarkjs `.wtns` files (`wtns`).
//!
//! Upstream: <https://github.com/arkworks-rs/circom-compat> at commit `09e92d4` (see each file's header).

// Vendored code keeps its upstream style.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_errors_doc
)]

mod circuit;
mod qap;
pub mod r1cs_reader;
pub mod witness;
pub mod wtns;

use anyhow::{Context, Result};
use ark_bn254::Fr;
use std::{fs::File, io::BufReader, path::Path};

pub use circuit::CircomCircuit;
pub use qap::CircomReduction;
pub use r1cs_reader::{R1CS, R1CSFile};

/// Reads a Circom `.r1cs` file.
pub fn read_r1cs(path: impl AsRef<Path>) -> Result<R1CS<Fr>> {
    let path = path.as_ref();
    let reader =
        BufReader::new(File::open(path).with_context(|| format!("open {}", path.display()))?);
    Ok(R1CSFile::new(reader)
        .map_err(|e| anyhow::anyhow!("read {}: {e}", path.display()))?
        .into())
}

/// An empty circuit for Groth16 setup, without a witness.
///
/// Like `CircomBuilder::setup`, it disables the wire mapping.
pub fn setup_circuit(mut r1cs: R1CS<Fr>) -> CircomCircuit<Fr> {
    r1cs.wire_mapping = None;
    CircomCircuit {
        r1cs,
        witness: None,
    }
}

/// A circuit with the witness (indexed by wire) a witness calculator produced.
///
/// Like `CircomBuilder::build`, it disables the wire mapping.
pub fn circuit_with_witness(r1cs: R1CS<Fr>, witness: Vec<Fr>) -> CircomCircuit<Fr> {
    let mut circuit = setup_circuit(r1cs);
    circuit.witness = Some(witness);
    circuit
}
