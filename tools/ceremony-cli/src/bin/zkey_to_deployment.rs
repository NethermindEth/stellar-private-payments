//! Convert a final snarkjs zkey into the deployment artifacts used by this repo.

use anyhow::{Context, Result, anyhow, bail};
use ark_bn254::{Bn254, Fq, Fq2, g1::G1Affine, g2::G2Affine};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use clap::Parser;
use num_bigint::BigUint;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
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

#[derive(Debug, Deserialize)]
struct ZkeyJson {
    #[serde(rename = "nPublic")]
    n_public: usize,
    #[serde(rename = "vk_alpha_1")]
    vk_alpha_1: G1PointJson,
    #[serde(rename = "vk_beta_1")]
    vk_beta_1: G1PointJson,
    #[serde(rename = "vk_beta_2")]
    vk_beta_2: G2PointJson,
    #[serde(rename = "vk_gamma_2")]
    vk_gamma_2: G2PointJson,
    #[serde(rename = "vk_delta_1")]
    vk_delta_1: G1PointJson,
    #[serde(rename = "vk_delta_2")]
    vk_delta_2: G2PointJson,
    #[serde(rename = "IC")]
    ic: Vec<G1PointJson>,
    #[serde(rename = "A")]
    a: Vec<G1PointJson>,
    #[serde(rename = "B1")]
    b1: Vec<G1PointJson>,
    #[serde(rename = "B2")]
    b2: Vec<G2PointJson>,
    #[serde(rename = "C")]
    c: Vec<Option<G1PointJson>>,
    #[serde(rename = "hExps")]
    h_exps: Vec<G1PointJson>,
}

#[derive(Clone, Debug, Deserialize)]
struct G1PointJson(String, String, String);

#[derive(Clone, Debug, Deserialize)]
struct G2PointJson([String; 2], [String; 2], [String; 2]);

fn main() -> Result<()> {
    let cli = Cli::parse();
    convert(cli)
}

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

    let exported_json_path = export_zkey_json(&cli.zkey)?;
    let zkey_json: ZkeyJson = serde_json::from_slice(
        &fs::read(&exported_json_path)
            .with_context(|| format!("failed to read {}", exported_json_path.display()))?,
    )
    .with_context(|| format!("failed to parse {}", exported_json_path.display()))?;

    let pk = proving_key_from_zkey_json(zkey_json)?;

    write_proving_key(&pk, &pk_path)?;
    write_verification_key(&pk.vk, &vk_json_path)?;
    write_verification_key_soroban_bin(&pk.vk, &vk_soroban_path)?;
    write_verification_key_rust_const(&pk.vk, &vk_const_path)?;

    // Validate the emitted proving key by round-tripping the on-disk bytes.
    let written_pk = ProvingKey::<Bn254>::deserialize_compressed_unchecked(
        &fs::read(&pk_path).with_context(|| format!("failed to read {}", pk_path.display()))?[..],
    )
    .map_err(|e| anyhow!("failed to round-trip {}: {e}", pk_path.display()))?;

    if vk_to_snarkjs_json(&written_pk.vk) != vk_to_snarkjs_json(&pk.vk) {
        bail!("round-trip validation failed: proving key contains a different verification key");
    }

    println!("Generated:");
    println!("  {}", pk_path.display());
    println!("  {}", vk_json_path.display());
    println!("  {}", vk_soroban_path.display());
    println!("  {}", vk_const_path.display());

    Ok(())
}

fn export_zkey_json(zkey_path: &Path) -> Result<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("clock before unix epoch")?
        .as_nanos();
    let out_path = std::env::temp_dir().join(format!("zkey-export-{stamp}.json"));

    let status = Command::new("snarkjs")
        .args([
            "zkey",
            "export",
            "json",
            zkey_path
                .to_str()
                .ok_or_else(|| anyhow!("zkey path is not valid UTF-8"))?,
            out_path
                .to_str()
                .ok_or_else(|| anyhow!("temp export path is not valid UTF-8"))?,
        ])
        .status()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                anyhow!("`snarkjs` not found in PATH. Install with: npm install -g snarkjs")
            } else {
                anyhow!("failed to start snarkjs zkey export json: {e}")
            }
        })?;

    if !status.success() {
        bail!("snarkjs zkey export json failed with status {status}");
    }

    Ok(out_path)
}

fn proving_key_from_zkey_json(zkey: ZkeyJson) -> Result<ProvingKey<Bn254>> {
    let vk = VerifyingKey::<Bn254> {
        alpha_g1: parse_g1(&zkey.vk_alpha_1)?,
        beta_g2: parse_g2(&zkey.vk_beta_2)?,
        gamma_g2: parse_g2(&zkey.vk_gamma_2)?,
        delta_g2: parse_g2(&zkey.vk_delta_2)?,
        gamma_abc_g1: zkey.ic.iter().map(parse_g1).collect::<Result<Vec<_>>>()?,
    };

    if vk.gamma_abc_g1.len().saturating_sub(1) != zkey.n_public {
        bail!(
            "IC/public input mismatch: IC has {} points but zkey declares {} public inputs",
            vk.gamma_abc_g1.len(),
            zkey.n_public
        );
    }

    let h_query_len = zkey.h_exps.len().saturating_sub(1);

    Ok(ProvingKey::<Bn254> {
        vk,
        beta_g1: parse_g1(&zkey.vk_beta_1)?,
        delta_g1: parse_g1(&zkey.vk_delta_1)?,
        a_query: zkey.a.iter().map(parse_g1).collect::<Result<Vec<_>>>()?,
        b_g1_query: zkey.b1.iter().map(parse_g1).collect::<Result<Vec<_>>>()?,
        b_g2_query: zkey.b2.iter().map(parse_g2).collect::<Result<Vec<_>>>()?,
        h_query: zkey
            .h_exps
            .iter()
            .take(h_query_len)
            .map(parse_g1)
            .collect::<Result<Vec<_>>>()?,
        l_query: zkey
            .c
            .into_iter()
            .flatten()
            .map(|point| parse_g1(&point))
            .collect::<Result<Vec<_>>>()?,
    })
}

fn parse_g1(point: &G1PointJson) -> Result<G1Affine> {
    if point.2 != "1" {
        return Ok(G1Affine::default());
    }

    Ok(G1Affine::new_unchecked(
        parse_fq_decimal(&point.0)?,
        parse_fq_decimal(&point.1)?,
    ))
}

fn parse_g2(point: &G2PointJson) -> Result<G2Affine> {
    if point.2 != [String::from("1"), String::from("0")] {
        return Ok(G2Affine::default());
    }

    let x = Fq2::new(
        parse_fq_decimal(&point.0[0])?,
        parse_fq_decimal(&point.0[1])?,
    );
    let y = Fq2::new(
        parse_fq_decimal(&point.1[0])?,
        parse_fq_decimal(&point.1[1])?,
    );
    Ok(G2Affine::new_unchecked(x, y))
}

fn parse_fq_decimal(value: &str) -> Result<Fq> {
    let bigint = BigUint::parse_bytes(value.as_bytes(), 10)
        .ok_or_else(|| anyhow!("invalid decimal field element: {value}"))?;
    Ok(Fq::from_be_bytes_mod_order(&bigint.to_bytes_be()))
}

fn write_proving_key(pk: &ProvingKey<Bn254>, path: &Path) -> Result<()> {
    let mut bytes = Vec::new();
    pk.serialize_compressed(&mut bytes)
        .map_err(|e| anyhow!("failed to serialize proving key: {e}"))?;
    fs::write(path, &bytes).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn write_verification_key(vk: &VerifyingKey<Bn254>, path: &Path) -> Result<()> {
    let json_str = serde_json::to_string_pretty(&vk_to_snarkjs_json(vk))?;
    fs::write(path, json_str).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

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

fn g1_to_snarkjs(p: &G1Affine) -> Value {
    json!([fq_to_decimal(&p.x), fq_to_decimal(&p.y), "1"])
}

fn g2_to_snarkjs(p: &G2Affine) -> Value {
    json!([
        [fq_to_decimal(&p.x.c1), fq_to_decimal(&p.x.c0)],
        [fq_to_decimal(&p.y.c1), fq_to_decimal(&p.y.c0)],
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

fn g1_to_soroban_bytes(p: &G1Affine) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&bigint_to_be_32(p.x.into_bigint()));
    out[32..].copy_from_slice(&bigint_to_be_32(p.y.into_bigint()));
    out
}

fn g2_to_soroban_bytes(p: &G2Affine) -> [u8; 128] {
    let mut out = [0u8; 128];
    out[..32].copy_from_slice(&bigint_to_be_32(p.x.c1.into_bigint()));
    out[32..64].copy_from_slice(&bigint_to_be_32(p.x.c0.into_bigint()));
    out[64..96].copy_from_slice(&bigint_to_be_32(p.y.c1.into_bigint()));
    out[96..].copy_from_slice(&bigint_to_be_32(p.y.c0.into_bigint()));
    out
}

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