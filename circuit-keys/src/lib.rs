//! Shared helpers for emitting Groth16 key material in the repo-specific
//! formats used by deployments and tests.
//!
//! This crate centralizes serialization/encoding so that `circuits/build.rs`
//! and `tools/ceremony-cli` produce identical outputs.

use anyhow::{Context, Result, anyhow};
use ark_bn254::{Bn254, Fq, Fq2, g1::G1Affine, g2::G2Affine};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_serialize::CanonicalSerialize;
use num_bigint::BigUint;
use serde_json::{Value, json};
use std::{
    fs,
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
};

#[cfg(unix)]
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("missing parent directory for {}", path.display()))?;

    let file_name = path
        .file_name()
        .with_context(|| format!("missing file name for {}", path.display()))?
        .to_string_lossy();

    let pid = std::process::id();
    let mut temp_path = parent.join(format!(".{file_name}.tmp.{pid}"));

    let mut temp_file = None;
    for attempt in 0u32..1000 {
        if attempt != 0 {
            temp_path = parent.join(format!(".{file_name}.tmp.{pid}.{attempt}"));
        }

        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
        {
            Ok(file) => {
                temp_file = Some(file);
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("failed to create temp file {}", temp_path.display())
                });
            }
        }
    }

    let result = (|| -> Result<()> {
        let mut temp_file = temp_file
            .with_context(|| format!("failed to create unique temp file for {}", path.display()))?;

        temp_file
            .write_all(bytes)
            .with_context(|| format!("failed to write temp file {}", temp_path.display()))?;
        temp_file
            .sync_all()
            .with_context(|| format!("failed to sync temp file {}", temp_path.display()))?;
        drop(temp_file);

        fs::rename(&temp_path, path).with_context(|| {
            format!(
                "failed to rename temp file {} to {}",
                temp_path.display(),
                path.display()
            )
        })?;

        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result?;

    // Ensure rename is durably recorded.
    File::open(parent)
        .with_context(|| format!("failed to open parent directory {}", parent.display()))?
        .sync_all()
        .with_context(|| format!("failed to sync parent directory {}", parent.display()))?;

    Ok(())
}

#[cfg(not(unix))]
fn atomic_write(path: &Path, _bytes: &[u8]) -> Result<()> {
    Err(anyhow!(
        "atomic writes are currently supported only on unix targets (attempted: {})",
        path.display()
    ))
}

/// Writes a Groth16 proving key as compressed arkworks bytes.
pub fn write_proving_key_bin(pk: &ProvingKey<Bn254>, path: &Path) -> Result<()> {
    let mut bytes = Vec::new();
    pk.serialize_compressed(&mut bytes)
        .map_err(|e| anyhow!("failed to serialize proving key: {e}"))?;
    atomic_write(path, &bytes).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

/// Writes a Groth16 verifying key as snarkjs-compatible JSON.
pub fn write_vk_snarkjs_json(vk: &VerifyingKey<Bn254>, path: &Path) -> Result<()> {
    let json_str = serde_json::to_string_pretty(&vk_to_snarkjs_json(vk))?;
    atomic_write(path, json_str.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

/// Converts an ark-groth16 verifying key into the snarkjs JSON format used by
/// this repo.
pub fn vk_to_snarkjs_json(vk: &VerifyingKey<Bn254>) -> Value {
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

fn g1_to_snarkjs(p: &G1Affine) -> Value {
    json!([fq_to_decimal(&p.x), fq_to_decimal(&p.y), "1"])
}

fn g2_to_snarkjs(p: &G2Affine) -> Value {
    json!([
        [fq_to_decimal(&p.x.c0), fq_to_decimal(&p.x.c1)],
        [fq_to_decimal(&p.y.c0), fq_to_decimal(&p.y.c1)],
        ["1", "0"]
    ])
}

fn fq_to_decimal(f: &Fq) -> String {
    let bigint = f.into_bigint();
    let bytes = bigint.to_bytes_be();
    BigUint::from_bytes_be(&bytes).to_string()
}

fn bigint_to_be_32<B: BigInteger>(value: B) -> [u8; 32] {
    let bytes = value.to_bytes_be();
    let mut out = [0u8; 32];
    let start = 32usize.saturating_sub(bytes.len());
    out[start..].copy_from_slice(&bytes[..bytes.len().min(32)]);
    out
}

pub fn g1_to_soroban_bytes(p: &G1Affine) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&bigint_to_be_32(p.x.into_bigint()));
    out[32..].copy_from_slice(&bigint_to_be_32(p.y.into_bigint()));
    out
}

pub fn g2_to_soroban_bytes(p: &G2Affine) -> [u8; 128] {
    let mut out = [0u8; 128];
    out[..32].copy_from_slice(&bigint_to_be_32(p.x.c1.into_bigint()));
    out[32..64].copy_from_slice(&bigint_to_be_32(p.x.c0.into_bigint()));
    out[64..96].copy_from_slice(&bigint_to_be_32(p.y.c1.into_bigint()));
    out[96..].copy_from_slice(&bigint_to_be_32(p.y.c0.into_bigint()));
    out
}

/// Writes a Soroban-friendly binary representation of the verifying key.
///
/// Layout:
/// - alpha (G1): 64 bytes
/// - beta (G2): 128 bytes
/// - gamma (G2): 128 bytes
/// - delta (G2): 128 bytes
/// - ic_count (u32 LE): 4 bytes
/// - IC points (G1): `ic_count * 64` bytes
pub fn write_vk_soroban_bin(vk: &VerifyingKey<Bn254>, path: &Path) -> Result<()> {
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

    atomic_write(path, &bytes).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

/// Writes a Rust source file containing VK constants for Soroban contracts.
pub fn write_vk_rust_const(vk: &VerifyingKey<Bn254>, path: &Path) -> Result<()> {
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

    atomic_write(path, content.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

/// Parses a decimal string into an `Fq` field element.
pub fn parse_fq_decimal(value: &str) -> Result<Fq> {
    let bigint = BigUint::parse_bytes(value.as_bytes(), 10)
        .ok_or_else(|| anyhow!("invalid decimal field element: {value}"))?;
    Ok(Fq::from_be_bytes_mod_order(&bigint.to_bytes_be()))
}

/// Parses an Fq2 element from a pair of decimal strings (c0, c1 are given
/// separately).
pub fn fq2_from_decimals(c0: &str, c1: &str) -> Result<Fq2> {
    Ok(Fq2::new(parse_fq_decimal(c0)?, parse_fq_decimal(c1)?))
}

#[cfg(all(test, unix))]
mod tests {
    use super::atomic_write;
    use anyhow::Result;
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicUsize, Ordering},
    };

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn unique_test_dir(prefix: &str) -> Result<PathBuf> {
        let mut dir = std::env::temp_dir();
        let count = COUNTER.fetch_add(1, Ordering::SeqCst);
        dir.push(format!(
            "circuit_keys_{prefix}_{}_{}",
            std::process::id(),
            count
        ));
        fs::create_dir(&dir)?;
        Ok(dir)
    }

    fn list_file_names(dir: &Path) -> Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            names.push(entry.file_name().to_string_lossy().to_string());
        }
        names.sort();
        Ok(names)
    }

    #[cfg_attr(miri, ignore = "Filesystem I/O not supported under Miri isolation")]
    #[test]
    fn atomic_write_replaces_contents_and_cleans_up_temp() -> Result<()> {
        let dir = unique_test_dir("atomic_write")?;
        let path = dir.join("vk.json");

        atomic_write(&path, b"first")?;
        atomic_write(&path, b"second")?;

        let contents = fs::read(&path)?;
        assert_eq!(contents, b"second");

        let names = list_file_names(&dir)?;
        assert_eq!(names, vec!["vk.json".to_string()]);

        fs::remove_dir_all(&dir)?;
        Ok(())
    }
}
