//! Build script: copies circuit artifacts for embedding via `include_bytes!()`.

use std::path::{Path, PathBuf};
use std::{env, fs};

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
    let workspace_root = manifest_dir
        .parent()
        .expect("Cannot find workspace root");

    // 1. Proving key: scripts/testdata/policy_test_proving_key.bin
    let pk_src = workspace_root.join("scripts/testdata/policy_test_proving_key.bin");
    let pk_dst = out_dir.join("policy_test_proving_key.bin");
    copy_if_exists(&pk_src, &pk_dst, "policy_test_proving_key.bin");

    // 2. Circuit WASM and R1CS: built by the circuits crate
    //    These are in target/*/build/circuits-*/out/circuits/...
    //    We search for them dynamically.
    let target_dir = workspace_root.join("target");
    let (wasm_src, r1cs_src) = find_circuit_artifacts(&target_dir);

    let wasm_dst = out_dir.join("policy_test.wasm");
    let r1cs_dst = out_dir.join("policy_test.r1cs");

    if let Some(ref wasm) = wasm_src {
        copy_if_exists(wasm, &wasm_dst, "policy_test.wasm");
    } else {
        // Create placeholder files so include_bytes! compiles
        // Real artifacts must be present for proof generation to work
        create_placeholder(&wasm_dst, "policy_test.wasm");
    }

    if let Some(ref r1cs) = r1cs_src {
        copy_if_exists(r1cs, &r1cs_dst, "policy_test.r1cs");
    } else {
        create_placeholder(&r1cs_dst, "policy_test.r1cs");
    }

    // Tell cargo to re-run if these source files change
    println!("cargo:rerun-if-changed={}", pk_src.display());
    if let Some(ref w) = wasm_src {
        println!("cargo:rerun-if-changed={}", w.display());
    }
    if let Some(ref r) = r1cs_src {
        println!("cargo:rerun-if-changed={}", r.display());
    }
}

fn copy_if_exists(src: &Path, dst: &Path, name: &str) {
    if src.exists() {
        fs::copy(src, dst).unwrap_or_else(|e| panic!("Failed to copy {name}: {e}"));
        eprintln!("cargo:warning=Copied {name} from {}", src.display());
    } else {
        create_placeholder(dst, name);
    }
}

fn create_placeholder(dst: &Path, name: &str) {
    if !dst.exists() {
        fs::write(dst, b"").unwrap_or_else(|e| panic!("Failed to create placeholder {name}: {e}"));
        eprintln!("cargo:warning=Created placeholder for {name} (proof generation will not work until real artifacts are built)");
    }
}

fn find_circuit_artifacts(target_dir: &Path) -> (Option<PathBuf>, Option<PathBuf>) {
    let mut wasm_path = None;
    let mut r1cs_path = None;

    // Search in both debug and release build directories
    for profile in &["debug", "release"] {
        let build_dir = target_dir.join(profile).join("build");
        if !build_dir.exists() {
            continue;
        }

        if let Ok(entries) = fs::read_dir(&build_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if !name_str.starts_with("circuits-") {
                    continue;
                }
                let out = entry.path().join("out").join("circuits");
                let w = out.join("wasm/policy_test_js/policy_test.wasm");
                let r = out.join("policy_test.r1cs");

                if w.exists() && wasm_path.is_none() {
                    wasm_path = Some(w);
                }
                if r.exists() && r1cs_path.is_none() {
                    r1cs_path = Some(r);
                }
                if wasm_path.is_some() && r1cs_path.is_some() {
                    return (wasm_path, r1cs_path);
                }
            }
        }
    }

    (wasm_path, r1cs_path)
}
