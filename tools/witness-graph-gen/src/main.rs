//! Regenerates one `circom-witness-rs` operation graph.
//!
//! `circom-witness-rs` compiles the circuit named by `WITNESS_CPP` inside its
//! own build script, so this binary handles exactly one stem per invocation,
//! and the circomlib patch has to be applied before cargo runs. Drive it
//! through `scripts/witness-graphs.sh`, which handles both.

use anyhow::{Context, Result, anyhow, bail, ensure};
use clap::Parser;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Parser)]
#[command(name = "witness-graph-gen", about, version)]
struct Cli {
    /// Directory that receives `<stem>.graph.bin`.
    #[arg(long, value_name = "DIR")]
    keys_dir: PathBuf,

    /// Circom version lock file to check the `circom` CLI against.
    #[arg(long, value_name = "FILE", default_value = "circuits/circom.lock")]
    circom_lock: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let witness_cpp = env::var("WITNESS_CPP")
        .map_err(|_| anyhow!("WITNESS_CPP must name the circuit to build"))?;
    let stem = Path::new(witness_cpp.trim())
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow!("invalid WITNESS_CPP circuit path: {witness_cpp}"))?
        .to_owned();

    check_circom_cli(&cli.circom_lock)?;

    eprintln!("Regenerating witness graph for {stem}...");
    generate()?;

    // `build_witness` writes `graph.bin` into the current directory.
    let src = env::current_dir()?.join("graph.bin");
    ensure!(
        src.is_file(),
        "expected circom-witness-rs to write {}; not found",
        src.display()
    );

    fs::create_dir_all(&cli.keys_dir)
        .with_context(|| format!("create {}", cli.keys_dir.display()))?;
    let dst = cli.keys_dir.join(format!("{stem}.graph.bin"));
    fs::rename(&src, &dst)
        .with_context(|| format!("move {} to {}", src.display(), dst.display()))?;

    eprintln!("Wrote {}", dst.display());
    Ok(())
}

/// The circom CLI must match the release the Rust circom crates are pinned to,
/// otherwise the graph disagrees with the R1CS.
fn check_circom_cli(lock: &Path) -> Result<()> {
    let expected = fs::read_to_string(lock)
        .with_context(|| format!("read {}", lock.display()))?
        .trim()
        .to_owned();

    let out = Command::new("circom")
        .arg("--version")
        .output()
        .context("run `circom --version` (is Circom on PATH?)")?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    if !out.status.success() || !text.contains(&expected) {
        bail!(
            "circom CLI must be {expected} ({}); got:\n{text}",
            lock.display()
        );
    }
    Ok(())
}

#[cfg(feature = "build-witness")]
fn generate() -> Result<()> {
    circom_witness_rs::generate::build_witness()
        .map_err(|e| anyhow!("witness graph generation failed: {e}"))
}

#[cfg(not(feature = "build-witness"))]
fn generate() -> Result<()> {
    bail!(
        "witness-graph-gen was built without the `build-witness` feature; \
         run it through `make witness-graphs`"
    )
}
