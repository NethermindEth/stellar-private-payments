//! Build script for the `spp` CLI.
//!
//! Produces the circuits licensing NOTICE that the binary embeds via
//! `include_str!`. The `@…@` placeholder substitution is delegated to the shared
//! `deployments/scripts/fill-circuits-notice.sh` so the CLI fills the same
//! template, the same way, as the web `dist/` staging
//! (`deployments/scripts/stage-dist-legal.sh`).
//!
//! We pass the literal `@SOURCE_BUNDLE_URL@` sentinel so the build only bakes the
//! provenance placeholders (repo commit / build date / circomlib revision); the
//! CLI fills the version-specific GitHub release URL at runtime.

use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir.join("..");
    let script = repo_root.join("deployments/scripts/fill-circuits-notice.sh");
    let template = repo_root.join("deployments/legal/dist/circuits-NOTICE.txt");
    let circomlib_lock = repo_root.join("circuits/circomlib.lock");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", script.display());
    println!("cargo:rerun-if-changed={}", template.display());
    println!("cargo:rerun-if-changed={}", circomlib_lock.display());

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let notice_out = out_dir.join("circuits-NOTICE.txt");

    // Fill the provenance placeholders, preserving @SOURCE_BUNDLE_URL@ for runtime.
    let filled = match Command::new("sh")
        .arg(&script)
        .arg("@SOURCE_BUNDLE_URL@")
        .output()
    {
        Ok(out) if out.status.success() => out.stdout,
        Ok(out) => {
            println!(
                "cargo:warning=fill-circuits-notice.sh exited with {}: {} — embedding the raw template",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
            fs::read(&template).expect("read circuits-NOTICE.txt template")
        }
        Err(e) => {
            println!(
                "cargo:warning=could not run fill-circuits-notice.sh ({e}) — embedding the raw template"
            );
            fs::read(&template).expect("read circuits-NOTICE.txt template")
        }
    };

    fs::write(&notice_out, filled).expect("write generated circuits-NOTICE.txt");
}
