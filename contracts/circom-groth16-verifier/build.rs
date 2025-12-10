use anyhow::{Context, Result, anyhow, ensure};
use ark_bn254::{Fq, Fq2, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use serde::Deserialize;
use std::{
    env, fs,
    path::{Path, PathBuf},
    str::FromStr,
};

#[derive(Deserialize)]
struct CircomVerificationKeyJson {
    #[serde(rename = "nPublic")]
    _n_public: usize,
    vk_alpha_1: [String; 3],
    vk_beta_2: [[String; 2]; 3],
    vk_gamma_2: [[String; 2]; 3],
    vk_delta_2: [[String; 2]; 3],
    #[serde(rename = "IC")]
    ic: Vec<[String; 3]>,
}

struct VerificationKey {
    alpha: G1Affine,
    beta: G2Affine,
    gamma: G2Affine,
    delta: G2Affine,
    ic: Vec<G1Affine>,
}

fn main() -> Result<()> {
    let crate_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let workspace_root = crate_dir
        .parent()
        .and_then(Path::parent)
        .context("could not resolve workspace root")?;

    let vk_path = workspace_root.join("circuits/vk.json");
    println!("cargo:rerun-if-changed={}", vk_path.display());
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    fs::create_dir_all(&out_dir).context("failed to create OUT_DIR")?;
    println!("cargo:rustc-env=OUT_DIR={}", out_dir.display());

    let vk = load_verification_key(&vk_path)?;
    let ic = vk
        .ic
        .iter()
        .map(|point| format_byte_array(&serialize_g1_point(point)))
        .collect::<Vec<_>>()
        .join(", ");

    let vk_code = format!(
        "VerificationKeyBytes {{\n    alpha: {},\n    beta: {},\n    gamma: {},\n    delta: {},\n    ic: &[{}],\n}}",
        format_byte_array(&serialize_g1_point(&vk.alpha)),
        format_byte_array(&serialize_g2_point(&vk.beta)),
        format_byte_array(&serialize_g2_point(&vk.gamma)),
        format_byte_array(&serialize_g2_point(&vk.delta)),
        ic
    );

    fs::write(out_dir.join("verification_key.rs"), vk_code)
        .context("failed to write verification_key.rs")?;

    Ok(())
}

fn load_verification_key(path: &Path) -> Result<VerificationKey> {
    let vk_contents = fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let vk_json: CircomVerificationKeyJson = serde_json::from_str(&vk_contents)
        .with_context(|| format!("Failed to parse {}", path.display()))?;

    verification_key_from_json(&vk_json)
}

fn verification_key_from_json(json: &CircomVerificationKeyJson) -> Result<VerificationKey> {
    let alpha = g1_from_coords(&json.vk_alpha_1)?;
    let beta = g2_from_coords(&json.vk_beta_2)?;
    let gamma = g2_from_coords(&json.vk_gamma_2)?;
    let delta = g2_from_coords(&json.vk_delta_2)?;

    let mut ic = Vec::with_capacity(json.ic.len());
    for point in &json.ic {
        ic.push(g1_from_coords(point)?);
    }

    Ok(VerificationKey {
        alpha,
        beta,
        gamma,
        delta,
        ic,
    })
}

fn g1_from_coords(coords: &[String; 3]) -> Result<G1Affine> {
    let x = Fq::from_str(&coords[0]).map_err(|_| anyhow!("Invalid field element for G1.x"))?;
    let y = Fq::from_str(&coords[1]).map_err(|_| anyhow!("Invalid field element for G1.y"))?;

    let point = G1Affine::new(x, y);
    ensure!(point.is_on_curve(), "G1 point not on curve");
    Ok(point)
}

fn g2_from_coords(coords: &[[String; 2]; 3]) -> Result<G2Affine> {
    let x = Fq2::new(
        Fq::from_str(&coords[0][0]).map_err(|_| anyhow!("Invalid field element for G2.x.c0"))?,
        Fq::from_str(&coords[0][1]).map_err(|_| anyhow!("Invalid field element for G2.x.c1"))?,
    );
    let y = Fq2::new(
        Fq::from_str(&coords[1][0]).map_err(|_| anyhow!("Invalid field element for G2.y.c0"))?,
        Fq::from_str(&coords[1][1]).map_err(|_| anyhow!("Invalid field element for G2.y.c1"))?,
    );

    let point = G2Affine::new(x, y);
    ensure!(point.is_on_curve(), "G2 point not on curve");
    Ok(point)
}

fn fq_to_be_bytes(f: &Fq) -> Vec<u8> {
    let num = f.into_bigint();
    num.to_bytes_be()
}

fn serialize_g1_point(p: &G1Affine) -> [u8; 64] {
    let mut buf = [0u8; 64];

    let (x, y) = p.xy().expect("Affine point has no coordinates");

    let x_bytes = fq_to_be_bytes(&x);
    let y_bytes = fq_to_be_bytes(&y);

    buf[0..32].copy_from_slice(&x_bytes);
    buf[32..64].copy_from_slice(&y_bytes);

    buf
}

fn serialize_g2_point(p: &G2Affine) -> [u8; 128] {
    let mut buf = [0u8; 128];

    let (x, y) = p.xy().expect("Affine point has no coordinates");
    let x_re = fq_to_be_bytes(&x.c0);
    let x_im = fq_to_be_bytes(&x.c1);
    let y_re = fq_to_be_bytes(&y.c0);
    let y_im = fq_to_be_bytes(&y.c1);

    buf[0..32].copy_from_slice(&x_re);
    buf[32..64].copy_from_slice(&x_im);
    buf[64..96].copy_from_slice(&y_re);
    buf[96..128].copy_from_slice(&y_im);

    buf
}

fn format_byte_array(bytes: &[u8]) -> String {
    let formatted: Vec<String> = bytes.iter().map(|b| format!("{:#04x}", b)).collect();
    format!("[{}]", formatted.join(", "))
}
