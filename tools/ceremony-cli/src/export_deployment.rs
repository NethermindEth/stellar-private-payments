//! Deployment key export helpers.
//!
//! Converts a final snarkjs `.zkey` into the binary and JSON formats used by
//! this repository (deployments + web prover).

use crate::{CommandRunner, ExportDeploymentArgs, assert_dir_exists, assert_output_allowed, assert_readable_file};
use anyhow::{Context, Result, anyhow, bail};
use ark_bn254::{Bn254, Fq2, g1::G1Affine, g2::G2Affine};
use ark_groth16::ProvingKey;
use ark_serialize::CanonicalDeserialize;
use serde::Deserialize;
use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

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

pub(crate) fn export_deployment(args: ExportDeploymentArgs, runner: &dyn CommandRunner) -> Result<()> {
    assert_readable_file(&args.zkey, "zkey")?;
    assert_dir_exists(&args.out_dir)?;

    let pk_path = args
        .out_dir
        .join(format!("{}_proving_key.bin", args.basename));
    let vk_json_path = args.out_dir.join(format!("{}_vk.json", args.basename));
    let vk_soroban_path = args
        .out_dir
        .join(format!("{}_vk_soroban.bin", args.basename));
    let vk_const_path = args
        .out_dir
        .join(format!("{}_vk_const.rs", args.basename));

    for path in [&pk_path, &vk_json_path, &vk_soroban_path, &vk_const_path] {
        assert_output_allowed(path, args.force)?;
    }

    let exported_json_path = export_zkey_json(&args.zkey, runner)?;
    let zkey_json_bytes = fs::read(&exported_json_path)
        .with_context(|| format!("failed to read {}", exported_json_path.display()))?;
    let zkey_json: ZkeyJson = serde_json::from_slice(&zkey_json_bytes)
        .with_context(|| format!("failed to parse {}", exported_json_path.display()))?;

    // Best-effort cleanup of the temporary export file.
    let _ = fs::remove_file(&exported_json_path);

    let pk = proving_key_from_zkey_json(zkey_json)?;

    circuit_keys::write_proving_key_bin(&pk, &pk_path)?;
    circuit_keys::write_vk_snarkjs_json(&pk.vk, &vk_json_path)?;
    circuit_keys::write_vk_soroban_bin(&pk.vk, &vk_soroban_path)?;
    circuit_keys::write_vk_rust_const(&pk.vk, &vk_const_path)?;

    // Validate emitted proving key by round-tripping the on-disk bytes.
    let written_pk = ProvingKey::<Bn254>::deserialize_compressed(
        &fs::read(&pk_path).with_context(|| format!("failed to read {}", pk_path.display()))?[..],
    )
    .map_err(|e| anyhow!("failed to round-trip {}: {e}", pk_path.display()))?;

    if circuit_keys::vk_to_snarkjs_json(&written_pk.vk) != circuit_keys::vk_to_snarkjs_json(&pk.vk) {
        bail!("round-trip validation failed: proving key contains a different verification key");
    }

    println!("Generated:");
    println!("  {}", pk_path.display());
    println!("  {}", vk_json_path.display());
    println!("  {}", vk_soroban_path.display());
    println!("  {}", vk_const_path.display());

    Ok(())
}

fn export_zkey_json(zkey_path: &Path, runner: &dyn CommandRunner) -> Result<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("clock before unix epoch")?
        .as_nanos();
    let out_path = std::env::temp_dir().join(format!("zkey-export-{stamp}.json"));

    let args = vec![
        OsString::from("zkey"),
        OsString::from("export"),
        OsString::from("json"),
        zkey_path.as_os_str().to_owned(),
        out_path.as_os_str().to_owned(),
    ];
    runner.run("snarkjs", &args)?;

    Ok(out_path)
}

fn proving_key_from_zkey_json(zkey: ZkeyJson) -> Result<ProvingKey<Bn254>> {
    let vk = ark_groth16::VerifyingKey::<Bn254> {
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
        circuit_keys::parse_fq_decimal(&point.0)?,
        circuit_keys::parse_fq_decimal(&point.1)?,
    ))
}

fn parse_g2(point: &G2PointJson) -> Result<G2Affine> {
    if point.2 != [String::from("1"), String::from("0")] {
        return Ok(G2Affine::default());
    }

    let x = Fq2::new(
        circuit_keys::parse_fq_decimal(&point.0[0])?,
        circuit_keys::parse_fq_decimal(&point.0[1])?,
    );
    let y = Fq2::new(
        circuit_keys::parse_fq_decimal(&point.1[0])?,
        circuit_keys::parse_fq_decimal(&point.1[1])?,
    );
    Ok(G2Affine::new_unchecked(x, y))
}
