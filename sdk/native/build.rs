use std::{env, fs, path::PathBuf};

use sha2::{Digest, Sha256};

fn main() {
    println!("cargo:rerun-if-env-changed=SPP_SQLITE3MC_BUILD");
    assert!(
        env::var_os("CARGO_FEATURE_SQLITE3MC").is_some(),
        "SQLite3MC is required; do not disable the sqlite3mc feature"
    );
    let expected = format!("2.5.1:{}", env::var("TARGET").expect("TARGET"));
    assert_eq!(
        env::var("SPP_SQLITE3MC_BUILD").ok().as_deref(),
        Some(expected.as_str()),
        "SQLite3MC is required. Build with python3 scripts/sqlite3mc.py -- <cargo command>"
    );
    println!("cargo:rerun-if-changed=src/state/disclaimer.md");
    println!("cargo:rerun-if-changed=circuits.json");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
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
