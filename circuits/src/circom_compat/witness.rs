//! Witnesses calculated by the JavaScript calculator `circom` writes next to
//! each compiled circuit (`<name>_js/generate_witness.js`), run with Node.
//!
//! The compiler leaves that folder under `<artifacts>/out/wasm/<name>_js/`,
//! while the published `<artifacts>/<name>.wasm` is a copy of the module inside
//! it.
//!
//! Circuit inputs are the flat JSON object of `Inputs::to_witness_json`: the
//! calculator keeps keys such as `membershipProofs[0][0].leaf` as they are.

use super::wtns::parse_wtns;
use anyhow::{Context, Result, bail};
use ark_bn254::Fr;
use std::{
    path::{Path, PathBuf},
    process::Command,
};

/// Calculates the witness of the circuit compiled to `wasm`
/// (`<name>_js/<name>.wasm`).
///
/// Fails, with Node's error, when the inputs break an assertion of the circuit.
pub fn calculate_witness(wasm: &Path, inputs_json: &str) -> Result<Vec<Fr>> {
    let script = calculator_script(wasm)?;
    let work = tempfile::tempdir().context("create a temporary directory")?;
    let input = work.path().join("input.json");
    let output = work.path().join("witness.wtns");
    std::fs::write(&input, inputs_json).context("write circuit inputs")?;

    let result = Command::new("node")
        .arg(&script)
        .arg(wasm)
        .arg(&input)
        .arg(&output)
        .output()
        .context("run `node` (is Node.js installed?)")?;
    if !result.status.success() {
        bail!(
            "witness calculation failed: {}",
            String::from_utf8_lossy(&result.stderr).trim()
        );
    }
    parse_wtns(&std::fs::read(&output).context("read the witness file")?)
}

/// The `generate_witness.js` of the circuit whose module is `wasm`: next to it
/// when it is the compiler's `<name>_js/<name>.wasm`, or in the compiler's
/// output folder when it is the published copy `<artifacts>/<name>.wasm`.
fn calculator_script(wasm: &Path) -> Result<PathBuf> {
    let dir = wasm
        .parent()
        .with_context(|| format!("{} has no directory", wasm.display()))?;
    let stem = wasm
        .file_stem()
        .with_context(|| format!("{} has no file name", wasm.display()))?;
    let beside = dir.join("generate_witness.js");
    let compiled = dir
        .join("out")
        .join("wasm")
        .join(format!("{}_js", stem.to_string_lossy()))
        .join("generate_witness.js");
    [beside, compiled]
        .into_iter()
        .find(|script| script.exists())
        .with_context(|| {
            format!(
                "no generate_witness.js for {}; build the circuits with `make circuits TESTS=1`",
                wasm.display()
            )
        })
}
