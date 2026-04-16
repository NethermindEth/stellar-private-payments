use std::env;
use std::fs;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

fn main() {
    println!("cargo:rerun-if-changed=src/disclaimer.md");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let disclaimer_path = manifest_dir.join("src").join("disclaimer.md");
    let disclaimer_md =
        fs::read_to_string(&disclaimer_path).expect("read src/disclaimer.md for hashing");

    let mut hasher = Sha256::new();
    hasher.update(disclaimer_md.as_bytes());
    let digest = hasher.finalize();
    let hex = hex::encode(digest);

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let out = out_dir.join("disclaimer_hash.rs");

    let contents = format!(
        "pub const CURRENT_DISCLAIMER_HASH_HEX: &str = \"{}\";\n",
        hex
    );
    fs::write(out, contents).expect("write generated disclaimer_hash.rs");
}

