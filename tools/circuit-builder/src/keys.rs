//! Groth16 proving/verifying key generation.
//!
//! Regenerating a key pair invalidates every proof made against the previous
//! one and requires redeploying the matching on-chain verifier. Generation is
//! therefore opt-in: it happens only when key files are absent, or when
//! `--force` is passed.

use anyhow::{Context, Result, anyhow, bail};
use ark_bn254::Bn254;
use ark_circom::{CircomBuilder, CircomConfig, CircomReduction};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_std::rand::thread_rng;
use std::{fs, path::Path};

use crate::compile;

/// Key files written for one circuit stem.
struct KeyPaths {
    proving_key: std::path::PathBuf,
    vk: std::path::PathBuf,
    vk_soroban: std::path::PathBuf,
    vk_const: std::path::PathBuf,
}

impl KeyPaths {
    fn new(keys_dir: &Path, stem: &str) -> Self {
        Self {
            proving_key: keys_dir.join(format!("{stem}_proving_key.bin")),
            vk: keys_dir.join(format!("{stem}_vk.json")),
            vk_soroban: keys_dir.join(format!("{stem}_vk_soroban.bin")),
            vk_const: keys_dir.join(format!("{stem}_vk_const.rs")),
        }
    }

    /// The three files needed for proving and verification.
    fn missing_essential(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if !self.proving_key.exists() {
            missing.push("proving_key.bin");
        }
        if !self.vk.exists() {
            missing.push("vk.json");
        }
        if !self.vk_soroban.exists() {
            missing.push("vk_soroban.bin");
        }
        missing
    }
}

/// Generate the key pair for `stem` if it is absent or `force` is set.
///
/// Returns `Ok(true)` when keys were written, `Ok(false)` when the existing
/// ones were kept.
pub fn generate(work_dir: &Path, keys_dir: &Path, stem: &str, force: bool) -> Result<bool> {
    fs::create_dir_all(keys_dir).with_context(|| format!("create {}", keys_dir.display()))?;

    let paths = KeyPaths::new(keys_dir, stem);
    let artifacts = compile::artifact_paths(work_dir, stem);

    let missing = paths.missing_essential();
    if missing.is_empty() && !force {
        // Whether these keys still match the circuit is a question about bytes,
        // not file dates: `circuit-builder verify` answers it against the R1CS
        // digest recorded when they were generated.
        eprintln!("  {stem}: keys present, skipping (pass --force to regenerate)");
        return Ok(false);
    }

    if force {
        eprintln!("  {stem}: --force set, regenerating keys");
        eprintln!("  WARNING: redeploy the matching on-chain verifier with the new VK");
    } else {
        eprintln!("  {stem}: missing key files ({})", missing.join(", "));
    }

    if !artifacts.r1cs.exists() {
        bail!(
            "{stem}: R1CS not found at {} - run `circuit-builder compile` first",
            artifacts.r1cs.display()
        );
    }
    if !artifacts.wasm.exists() {
        bail!(
            "{stem}: WASM not found at {} - run `circuit-builder compile` first",
            artifacts.wasm.display()
        );
    }

    eprintln!("  {stem}: running Groth16 setup...");
    let cfg = CircomConfig::new(&artifacts.wasm, &artifacts.r1cs)
        .map_err(|e| anyhow!("{stem}: CircomConfig: {e}"))?;
    let builder = CircomBuilder::new(cfg);
    let mut rng = thread_rng();
    let (pk, vk) =
        Groth16::<Bn254, CircomReduction>::circuit_specific_setup(builder.setup(), &mut rng)
            .map_err(|e| anyhow!("{stem}: circuit_specific_setup failed: {e}"))?;

    circuit_keys::write_proving_key_bin(&pk, &paths.proving_key)
        .with_context(|| format!("write {}", paths.proving_key.display()))?;
    circuit_keys::write_vk_snarkjs_json(&vk, &paths.vk)
        .with_context(|| format!("write {}", paths.vk.display()))?;
    circuit_keys::write_vk_soroban_bin(&vk, &paths.vk_soroban)
        .with_context(|| format!("write {}", paths.vk_soroban.display()))?;
    circuit_keys::write_vk_rust_const(&vk, &paths.vk_const)
        .with_context(|| format!("write {}", paths.vk_const.display()))?;

    eprintln!(
        "  {stem}: wrote keys to {} ({} public inputs)",
        keys_dir.display(),
        vk.gamma_abc_g1.len().saturating_sub(1)
    );
    Ok(true)
}
