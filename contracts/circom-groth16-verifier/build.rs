//! Build script for `circom-groth16-verifier`.
//!
//! Reads a snarkjs `verification_key.json` and generates `vk.rs` in the Cargo
//! output directory.  `lib.rs` includes that file at compile time, embedding
//! the verification key as static byte arrays with no persistent storage.
//!
//! A Cargo feature picks the key file. Each `policy_tx_2_2[_<key>]_vk.json`
//! and `keyOwnership_vk.json` in `deployments/<network>/circuit_keys` has the
//! feature `vk-<network>-<key>`, lowercased, with `_` as `-` and the empty key
//! as `none`: `vk-testnet-b-gvk-t` embeds `policy_tx_2_2_B_gvk_T_vk.json`.
//! With no `vk-*` feature on, `VERIFIER_VK_JSON` names the key file.
//!
//! The script panics when more than one `vk-*` feature is on. With one on, it
//! panics when the feature matches no key file or two key files map to one
//! feature. With none on, it reads no `deployments/` file and panics when
//! `VERIFIER_VK_JSON` is unset.
//!
//! # Usage
//!
//! ```bash
//! cargo build -p circom-groth16-verifier --release --features vk-testnet-b
//! VERIFIER_VK_JSON=/path/to/verification_key.json \
//!   cargo build -p circom-groth16-verifier --release
//! ```

use std::{
    collections::HashMap,
    env,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};

use ark_bn254::{g1::G1Affine, g2::G2Affine};
use serde_json::Value;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));

    let features: Vec<String> = env::var("CARGO_CFG_FEATURE")
        .unwrap_or_default()
        .split(',')
        .filter(|f| f.starts_with("vk-"))
        .map(str::to_owned)
        .collect();
    let path = match features.as_slice() {
        [] => {
            println!("cargo:rerun-if-env-changed=VERIFIER_VK_JSON");
            PathBuf::from(env::var("VERIFIER_VK_JSON").expect(
                "no vk-* feature is on and VERIFIER_VK_JSON is not set; enable one \
                 vk-<network>-<key> feature or set VERIFIER_VK_JSON to a key file",
            ))
        }
        [feature] => key_files().remove(feature).unwrap_or_else(|| {
            panic!("feature `{feature}` matches no key file in deployments/*/circuit_keys")
        }),
        _ => panic!(
            "enable at most one vk-* feature, got {}",
            features.join(", ")
        ),
    };
    println!("cargo:rerun-if-changed={}", path.display());
    let json = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read VK file `{}`: {e}", path.display()));
    let content = vk_rs_from_json(&json);

    fs::write(out_dir.join("vk.rs"), content).expect("failed to write vk.rs");
}

/// Maps each `vk-*` feature to the key file it embeds.
fn key_files() -> HashMap<String, PathBuf> {
    // Not `env!`: Cargo reuses this binary across worktrees sharing a target.
    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let deployments = Path::new(&manifest_dir).join("../../deployments");
    let mut keys: HashMap<String, PathBuf> = HashMap::new();
    for network in fs::read_dir(&deployments).expect("failed to list deployments/") {
        let network = network.expect("failed to read deployments/").file_name();
        let Ok(files) = fs::read_dir(deployments.join(&network).join("circuit_keys")) else {
            continue;
        };
        for file in files {
            let path = file.expect("failed to read circuit_keys/").path();
            let Some(key) = path.file_name().and_then(|n| n.to_str()).and_then(key_name) else {
                continue;
            };
            let feature = format!("vk-{}-{key}", network.to_string_lossy())
                .to_lowercase()
                .replace('_', "-");
            if let Some(other) = keys.insert(feature.clone(), path.clone()) {
                panic!(
                    "`{}` and `{}` both map to feature `{feature}`",
                    other.display(),
                    path.display()
                );
            }
        }
    }
    keys
}

/// Returns the key a `circuit_keys` file name carries, `none` for the plain
/// policy key, or `None` when the file is not a verifier key.
fn key_name(file: &str) -> Option<&str> {
    let stem = file.strip_suffix("_vk.json")?;
    if stem == "keyOwnership" {
        return Some(stem);
    }
    match stem.strip_prefix("policy_tx_2_2")? {
        "" => Some("none"),
        rest => rest.strip_prefix('_'),
    }
}

/// Encode a snarkjs G1 point `[x, y, "1"]` as 64 bytes (x || y, big-endian).
fn g1_bytes(pt: &Value) -> [u8; 64] {
    let arr = pt.as_array().expect("G1 point must be a JSON array");
    let x = circuit_keys::parse_fq_decimal(arr[0].as_str().expect("G1.x must be a string"))
        .expect("invalid G1.x field element");
    let y = circuit_keys::parse_fq_decimal(arr[1].as_str().expect("G1.y must be a string"))
        .expect("invalid G1.y field element");
    circuit_keys::g1_to_soroban_bytes(&G1Affine::new_unchecked(x, y))
}

/// Encode a snarkjs G2 point `[[x_c0, x_c1], [y_c0, y_c1], ...]` as 128 bytes.
///
/// This repo's snarkjs JSON format (produced by
/// `circuit_keys::vk_to_snarkjs_json`) stores Fq2 components as `[real,
/// imaginary]` (c0 before c1). `circuit_keys::fq2_from_decimals` expects `(c0,
/// c1)`, matching this order directly.
fn g2_bytes(pt: &Value) -> [u8; 128] {
    let arr = pt.as_array().expect("G2 point must be a JSON array");
    let x = arr[0].as_array().expect("G2.x must be a JSON array");
    let y = arr[1].as_array().expect("G2.y must be a JSON array");
    let xf = circuit_keys::fq2_from_decimals(
        x[0].as_str().expect("G2.x.c0 must be a string"),
        x[1].as_str().expect("G2.x.c1 must be a string"),
    )
    .expect("invalid G2.x field element");
    let yf = circuit_keys::fq2_from_decimals(
        y[0].as_str().expect("G2.y.c0 must be a string"),
        y[1].as_str().expect("G2.y.c1 must be a string"),
    )
    .expect("invalid G2.y field element");
    circuit_keys::g2_to_soroban_bytes(&G2Affine::new_unchecked(xf, yf))
}

/// Render a byte slice as a Rust array literal (`[0x.., 0x.., ...]`).
fn fmt_bytes(bytes: &[u8]) -> String {
    let mut s = String::from("[");
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        write!(s, "0x{b:02x}").expect("infallible write to String");
    }
    s.push(']');
    s
}

/// Generate the contents of `vk.rs` from a snarkjs `verification_key.json`.
fn vk_rs_from_json(json: &str) -> String {
    let v: Value = serde_json::from_str(json).expect("VK file is not valid JSON");

    let alpha = g1_bytes(&v["vk_alpha_1"]);
    let beta = g2_bytes(&v["vk_beta_2"]);
    let gamma = g2_bytes(&v["vk_gamma_2"]);
    let delta = g2_bytes(&v["vk_delta_2"]);

    let ic_arr = v["IC"].as_array().expect("IC must be a JSON array");
    let ic_len = ic_arr.len();
    let ic_items: Vec<String> = ic_arr.iter().map(|pt| fmt_bytes(&g1_bytes(pt))).collect();

    let mut out = String::new();
    writeln!(out, "// Auto-generated by build.rs — do not edit manually.")
        .expect("infallible write to String");
    writeln!(out, "const VK_ALPHA_G1: [u8; 64] = {};", fmt_bytes(&alpha))
        .expect("infallible write to String");
    writeln!(out, "const VK_BETA_G2: [u8; 128] = {};", fmt_bytes(&beta))
        .expect("infallible write to String");
    writeln!(out, "const VK_GAMMA_G2: [u8; 128] = {};", fmt_bytes(&gamma))
        .expect("infallible write to String");
    writeln!(out, "const VK_DELTA_G2: [u8; 128] = {};", fmt_bytes(&delta))
        .expect("infallible write to String");
    writeln!(
        out,
        "const VK_IC: [[u8; 64]; {ic_len}] = [{}];",
        ic_items.join(",")
    )
    .expect("infallible write to String");
    out
}
