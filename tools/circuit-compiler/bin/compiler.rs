//! Circuit artifact compiler CLI.

use anyhow::Result;
use clap::{Parser, Subcommand};

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
    Compile,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Compile => circuit_compiler::run(),
    }
}
