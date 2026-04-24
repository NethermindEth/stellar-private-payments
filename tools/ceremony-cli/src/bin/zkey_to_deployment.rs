//! Convert a final snarkjs zkey into the deployment artifacts used by this
//! repo.
//!
//! The binary reads the final snarkjs `.zkey` directly into an arkworks
//! [`ProvingKey`] via [`ark_circom::read_zkey`] and emits the four artifacts
//! consumed by this repo:
//!
//! - `<basename>_proving_key.bin` — `CanonicalSerialize::serialize_compressed`
//!   of [`ProvingKey<Bn254>`], consumed by the app prover
//!   (see `app/crates/core/prover/src/prover.rs`).
//! - `<basename>_vk.json`         — snarkjs-compatible verification key JSON (from the trusted ceremony).
//! - `<basename>_vk_soroban.bin`  — packed VK used by the Soroban verifier.
//! - `<basename>_vk_const.rs`     — the same VK as Rust `const` byte arrays.

use anyhow::{Context, Result, anyhow, bail};
use ark_bn254::{Bn254, Fq, G1Affine, G2Affine};
use ark_circom::read_zkey;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use clap::Parser;
use num_bigint::BigUint;
use serde_json::{Value, json};
use std::{
    fs::{self, File},
    io::BufReader,
    path::{Path, PathBuf},
};

#[derive(Debug, Parser)]
#[command(
    name = "zkey-to-deployment",
    about = "Convert a final snarkjs zkey into the repo deployment key artifacts"
)]
struct Cli {
    /// Final ceremony zkey.
    #[arg(short = 'z', long = "zkey")]
    zkey: PathBuf,
    /// Output directory for generated files.
    #[arg(short = 'o', long = "out-dir")]
    out_dir: PathBuf,
    /// Basename used for output files.
    #[arg(long = "basename", default_value = "policy_tx_2_2")]
    basename: String,
    /// Overwrite existing outputs.
    #[arg(long = "force")]
    force: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    convert(cli)
}

/// Read the ceremony zkey and write all deployment artifacts.
///
/// # Errors
/// Returns an error if the zkey cannot be read, any output file cannot be
/// written, or any output already exists and `--force` was not passed.
fn convert(cli: Cli) -> Result<()> {
    assert_readable_file(&cli.zkey, "zkey")?;
    assert_dir_exists(&cli.out_dir)?;

    let pk_path = cli
        .out_dir
        .join(format!("{}_proving_key.bin", cli.basename));
    let vk_json_path = cli.out_dir.join(format!("{}_vk.json", cli.basename));
    let vk_soroban_path = cli.out_dir.join(format!("{}_vk_soroban.bin", cli.basename));
    let vk_const_path = cli.out_dir.join(format!("{}_vk_const.rs", cli.basename));

    for path in [&pk_path, &vk_json_path, &vk_soroban_path, &vk_const_path] {
        assert_output_allowed(path, cli.force)?;
    }

    let pk = load_zkey(&cli.zkey)?;

    write_proving_key(&pk, &pk_path)?;
    write_verification_key(&pk.vk, &vk_json_path)?;
    write_verification_key_soroban_bin(&pk.vk, &vk_soroban_path)?;
    write_verification_key_rust_const(&pk.vk, &vk_const_path)?;
    
    // Check for malformed points now, rather than rejecting at proving time.
    validate_written_proving_key(&pk_path)?;

    println!("Generated:");
    println!("  {}", pk_path.display());
    println!("  {}", vk_json_path.display());
    println!("  {}", vk_soroban_path.display());
    println!("  {}", vk_const_path.display());

    Ok(())
}

/// Read a snarkjs `.zkey` file directly into an arkworks
/// [`ProvingKey<Bn254>`].
///
/// Delegates to [`ark_circom::read_zkey`], which parses the binary zkey format
/// into arkworks types.
///
/// # Arguments
/// * `path` - Filesystem path to the final ceremony `.zkey`.
///
/// # Errors
/// Returns an error if the file cannot be opened or the zkey is malformed.
fn load_zkey(path: &Path) -> Result<ProvingKey<Bn254>> {
    let file = File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let (pk, _matrices) = read_zkey(&mut reader)
        .map_err(|e| anyhow!("failed to parse zkey {}: {e}", path.display()))?;
    Ok(pk)
}

/// Serialize a proving key with arkworks `CanonicalSerialize::serialize_compressed`
/// and write it to `path`. The app prover loads this file via
/// `ProvingKey::<Bn254>::deserialize_compressed_unchecked`.
fn write_proving_key(pk: &ProvingKey<Bn254>, path: &Path) -> Result<()> {
    let mut bytes = Vec::new();
    pk.serialize_compressed(&mut bytes)
        .map_err(|e| anyhow!("failed to serialize proving key: {e}"))?;
    fs::write(path, &bytes).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

/// Re-read a written `proving_key.bin` with `ProvingKey::deserialize_compressed`
/// to catch any malformed point before the key is shipped to a prover.
fn validate_written_proving_key(path: &Path) -> Result<()> {
    let file =
        File::open(path).with_context(|| format!("failed to reopen {}", path.display()))?;
    let mut reader = BufReader::new(file);
    ProvingKey::<Bn254>::deserialize_compressed(&mut reader)
        .map_err(|e| anyhow!("post-write validation of {} failed: {e}", path.display()))?;
    Ok(())
}

/// Write the verification key to `path` in snarkjs-compatible JSON format.
fn write_verification_key(vk: &VerifyingKey<Bn254>, path: &Path) -> Result<()> {
    let json_str = serde_json::to_string_pretty(&vk_to_snarkjs_json(vk))?;
    fs::write(path, json_str).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

/// Serialize an arkworks `VerifyingKey` as a snarkjs-compatible JSON value.
///
/// G2 coordinates are emitted in snarkjs' `[c1, c0]` (imaginary, real)
/// convention.
fn vk_to_snarkjs_json(vk: &VerifyingKey<Bn254>) -> Value {
    json!({
        "protocol": "groth16",
        "curve": "bn128",
        "nPublic": vk.gamma_abc_g1.len().saturating_sub(1),
        "vk_alpha_1": g1_to_snarkjs(&vk.alpha_g1),
        "vk_beta_2": g2_to_snarkjs(&vk.beta_g2),
        "vk_gamma_2": g2_to_snarkjs(&vk.gamma_g2),
        "vk_delta_2": g2_to_snarkjs(&vk.delta_g2),
        "IC": vk.gamma_abc_g1.iter().map(g1_to_snarkjs).collect::<Vec<_>>(),
    })
}

/// G1 → snarkjs `[x, y, z]` where z == "1" for affine points.
fn g1_to_snarkjs(p: &G1Affine) -> Value {
    json!([fq_to_decimal(&p.x), fq_to_decimal(&p.y), "1"])
}

/// G2 → snarkjs `[[c1, c0], [c1, c0], ["1", "0"]]` (imaginary, real).
fn g2_to_snarkjs(p: &G2Affine) -> Value {
    json!([
        [fq_to_decimal(&p.x.c1), fq_to_decimal(&p.x.c0)],
        [fq_to_decimal(&p.y.c1), fq_to_decimal(&p.y.c0)],
        ["1", "0"]
    ])
}

/// Render an `Fq` element as a decimal string (standard form, not Montgomery).
fn fq_to_decimal(f: &Fq) -> String {
    let bigint = f.into_bigint();
    let bytes = bigint.to_bytes_be();
    BigUint::from_bytes_be(&bytes).to_string()
}

/// Left-pad a big-integer's big-endian bytes to exactly 32 bytes.
///
/// Used by the Soroban verifier which consumes fixed-width 32-byte limbs.
fn bigint_to_be_32<B: BigInteger>(value: B) -> [u8; 32] {
    let bytes = value.to_bytes_be();
    let mut out = [0u8; 32];
    let start = 32usize.saturating_sub(bytes.len());
    out[start..].copy_from_slice(&bytes[..bytes.len().min(32)]);
    out
}

/// G1 → 64-byte Soroban layout: `x || y`, each 32 bytes big-endian.
fn g1_to_soroban_bytes(p: &G1Affine) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&bigint_to_be_32(p.x.into_bigint()));
    out[32..].copy_from_slice(&bigint_to_be_32(p.y.into_bigint()));
    out
}

/// G2 → 128-byte Soroban layout: `x.c1 || x.c0 || y.c1 || y.c0` (imaginary,
/// real) to match the Soroban BN254 host function expectations.
fn g2_to_soroban_bytes(p: &G2Affine) -> [u8; 128] {
    let mut out = [0u8; 128];
    out[..32].copy_from_slice(&bigint_to_be_32(p.x.c1.into_bigint()));
    out[32..64].copy_from_slice(&bigint_to_be_32(p.x.c0.into_bigint()));
    out[64..96].copy_from_slice(&bigint_to_be_32(p.y.c1.into_bigint()));
    out[96..].copy_from_slice(&bigint_to_be_32(p.y.c0.into_bigint()));
    out
}

/// Write a VK as a `#![allow(dead_code)]` Rust module exposing
/// `VK_ALPHA`, `VK_BETA`, `VK_GAMMA`, `VK_DELTA`, `VK_IC_COUNT`, and `VK_IC`
/// constants, ready to be `include!`'d into a Soroban contract.
fn write_verification_key_rust_const(vk: &VerifyingKey<Bn254>, path: &Path) -> Result<()> {
    let ic_count = vk.gamma_abc_g1.len();

    let alpha_bytes = g1_to_soroban_bytes(&vk.alpha_g1);
    let beta_bytes = g2_to_soroban_bytes(&vk.beta_g2);
    let gamma_bytes = g2_to_soroban_bytes(&vk.gamma_g2);
    let delta_bytes = g2_to_soroban_bytes(&vk.delta_g2);

    let mut content = String::new();
    content.push_str("//! Auto-generated verification key constants for Soroban contracts.\n");
    content.push_str("//! DO NOT EDIT - regenerate from the final ceremony zkey.\n\n");
    content.push_str("#![allow(dead_code)]\n\n");
    content.push_str(&format!(
        "pub const VK_ALPHA: [u8; 64] = {:?};\n\n",
        alpha_bytes
    ));
    content.push_str(&format!(
        "pub const VK_BETA: [u8; 128] = {:?};\n\n",
        beta_bytes
    ));
    content.push_str(&format!(
        "pub const VK_GAMMA: [u8; 128] = {:?};\n\n",
        gamma_bytes
    ));
    content.push_str(&format!(
        "pub const VK_DELTA: [u8; 128] = {:?};\n\n",
        delta_bytes
    ));
    content.push_str(&format!("pub const VK_IC_COUNT: usize = {};\n\n", ic_count));
    content.push_str(&format!("pub const VK_IC: [[u8; 64]; {}] = [\n", ic_count));
    for ic in &vk.gamma_abc_g1 {
        content.push_str(&format!("    {:?},\n", g1_to_soroban_bytes(ic)));
    }
    content.push_str("];\n");

    fs::write(path, content).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

/// Write a VK as the packed binary blob expected by the Soroban verifier:
///
/// `alpha(64) || beta(128) || gamma(128) || delta(128) || ic_count(4 LE) ||
///  ic_0(64) || ic_1(64) || ...`
fn write_verification_key_soroban_bin(vk: &VerifyingKey<Bn254>, path: &Path) -> Result<()> {
    const HEADER_SIZE: usize = 452;

    let ic_count = vk.gamma_abc_g1.len();
    let ic_bytes = ic_count.checked_mul(64).context("IC count overflow")?;
    let total_size = HEADER_SIZE
        .checked_add(ic_bytes)
        .context("total size overflow")?;

    let mut bytes = Vec::with_capacity(total_size);
    bytes.extend_from_slice(&g1_to_soroban_bytes(&vk.alpha_g1));
    bytes.extend_from_slice(&g2_to_soroban_bytes(&vk.beta_g2));
    bytes.extend_from_slice(&g2_to_soroban_bytes(&vk.gamma_g2));
    bytes.extend_from_slice(&g2_to_soroban_bytes(&vk.delta_g2));

    let ic_count_u32 = u32::try_from(ic_count).context("IC count exceeds u32 max")?;
    bytes.extend_from_slice(&ic_count_u32.to_le_bytes());

    for ic in &vk.gamma_abc_g1 {
        bytes.extend_from_slice(&g1_to_soroban_bytes(ic));
    }

    fs::write(path, bytes).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn assert_readable_file(path: &Path, label: &str) -> Result<()> {
    if !path.exists() {
        bail!("{label} path does not exist: {}", path.display());
    }
    if !path.is_file() {
        bail!("{label} path is not a file: {}", path.display());
    }
    Ok(())
}

fn assert_dir_exists(path: &Path) -> Result<()> {
    if !path.exists() {
        bail!("directory does not exist: {}", path.display());
    }
    if !path.is_dir() {
        bail!("path is not a directory: {}", path.display());
    }
    Ok(())
}

fn assert_output_allowed(path: &Path, force: bool) -> Result<()> {
    if path.exists() && !force {
        bail!(
            "refusing to overwrite existing output `{}`; pass --force to allow",
            path.display()
        );
    }
    Ok(())
}