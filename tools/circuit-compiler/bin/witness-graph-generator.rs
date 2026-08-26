//! Single-circuit witness graph generator.
//!
//! circom-witness-rs 0.3 selects the circuit at build time through
//! `WITNESS_CPP`, so the compiler rebuilds and invokes this binary once per
//! production circuit.

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "circuit-witness-graph-generator",
    about = "Generate the witness graph baked into circom-witness-rs"
)]
struct Cli {
    /// Circom package directory (`src/`, lockfiles)
    #[arg(long, default_value = concat!(env!("CARGO_MANIFEST_DIR"), "/../../circuits"))]
    circuits: PathBuf,
    /// Directory for published `*.graph.bin` files
    #[arg(long, default_value = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/circuits-artifacts"))]
    out: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    circuit_compiler::generate_witness_graph(&cli.circuits, &cli.out)
}
