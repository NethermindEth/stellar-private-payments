//! Circuit artifact compiler CLI.

use anyhow::Result;
use circuit_compiler::CompileOptions;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "circuit-compiler",
    about = "Compile Circom circuit artifacts (R1CS, WASM, keys, graphs)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Compile circuits
    Compile {
        /// Circom package directory (`src/`, lockfiles)
        #[arg(long, default_value = concat!(env!("CARGO_MANIFEST_DIR"), "/../../circuits"))]
        circuits: PathBuf,
        /// Directory for published R1CS/WASM/graphs
        #[arg(long, default_value = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/circuits-artifacts"))]
        out: PathBuf,
        /// Include circuits under directories named `test`
        #[arg(long)]
        tests: bool,
        /// Force Groth16 key regeneration even if keys already exist
        #[arg(long)]
        regen_keys: bool,
        /// Regenerate witness graphs after compilation
        #[arg(long)]
        graphs: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Compile {
            circuits,
            out,
            tests,
            regen_keys,
            graphs,
        } => circuit_compiler::run(CompileOptions {
            circuits,
            out,
            tests,
            regen_keys,
            graphs,
        }),
    }
}
