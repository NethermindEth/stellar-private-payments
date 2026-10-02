use std::{env, fs, path::PathBuf};
fn main() {
    println!("cargo:rerun-if-env-changed=SPP_NETWORK");
    let network = env::var("SPP_NETWORK").unwrap_or_else(|_| "testnet".into());
    assert!(
        !network.is_empty()
            && network
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'),
        "invalid SPP_NETWORK"
    );
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let deployment = root.join("../../deployments").join(&network);
    let source = deployment.join("deployments.json");
    println!("cargo:rerun-if-changed={}", source.display());
    fs::copy(
        &source,
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR")).join("deployments.json"),
    )
    .expect("selected deployment must exist");
    println!("cargo:rustc-env=SPP_NETWORK={network}");
    println!(
        "cargo:rustc-env=SPP_CIRCUIT_KEYS={}",
        deployment.join("circuit_keys").display()
    );
}
