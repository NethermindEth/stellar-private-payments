use std::{env, fs, path::PathBuf};

use sha2::{Digest, Sha256};

fn main() {
    println!("cargo:rerun-if-changed=src/state/disclaimer.md");
    println!("cargo:rerun-if-changed=circuits.json");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    println!("cargo:rerun-if-env-changed=SPP_NETWORK");
    let network = env::var("SPP_NETWORK").unwrap_or_else(|_| "testnet".into());
    assert!(
        !network.is_empty()
            && network
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'),
        "invalid SPP_NETWORK"
    );
    let network_lock = manifest_dir
        .join("../../deployments")
        .join(&network)
        .join("circuits.json");
    // Published SDK packages keep their testnet lock alongside Cargo.toml.
    let circuit_lock = if network == "testnet" && !network_lock.exists() {
        manifest_dir.join("circuits.json")
    } else {
        network_lock
    };
    println!("cargo:rerun-if-changed={}", circuit_lock.display());
    fs::copy(
        &circuit_lock,
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR")).join("circuits.json"),
    )
    .expect("selected network circuit lock must exist");
    let disclaimer_path = manifest_dir.join("src").join("state").join("disclaimer.md");
    let disclaimer_md =
        fs::read_to_string(&disclaimer_path).expect("read src/state/disclaimer.md for hashing");

    let mut hasher = Sha256::new();
    hasher.update(disclaimer_md.as_bytes());
    let digest = hasher.finalize();
    let hex = hex::encode(digest);

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let out = out_dir.join("disclaimer_hash.rs");

    let contents = format!(
        "pub(crate) const CURRENT_DISCLAIMER_HASH_HEX: &str = \"{}\";\n",
        hex
    );
    fs::write(out, contents).expect("write generated disclaimer_hash.rs");
}
