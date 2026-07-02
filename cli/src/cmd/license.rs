//! `license` — the distribution/license notice, mirroring the app footer, plus
//! the full license texts and NOTICEs.
//!
//! The texts are read at runtime from the data-dir `dist` bundle
//! (`<data_dir>/dist`, provisioned by the installer), which mirrors the web
//! app's dist layout. In-repo runs fall back to the repository's `dist/`. This
//! keeps the compiled circuit artifacts accompanied by the LGPL-3.0/GPL-3.0
//! texts, the circuits NOTICE, and the Corresponding Source pointer required by
//! LGPL-3.0 §4.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Serialize;

use crate::{config::CliConfig, output};

const REPOSITORY: &str = "https://github.com/NethermindEth/stellar-private-payments";
const COPYRIGHT: &str = "Copyright 2025 Stellar Development Foundation";
const PRODUCT: &str = "Stellar Private Payments";

pub fn run(config: &CliConfig, json: bool) -> Result<()> {
    let dist = resolve_dist_dir(config)?;

    let notice = read(&dist, "NOTICE.txt")?;
    let circuits_notice = read(&dist, "circuits/NOTICE.txt")?;
    let apache_2_0 = read(&dist, "LICENSE.txt")?;
    let lgpl_3_0 = read(&dist, "licenses/LGPL-3.0.txt")?;
    let gpl_3_0 = read(&dist, "licenses/GPL-3.0.txt")?;

    #[derive(Serialize)]
    struct LicenseOut<'a> {
        product: &'a str,
        copyright: &'a str,
        license: &'a str,
        repository: &'a str,
        notice: &'a str,
        circuits_notice: &'a str,
        apache_2_0: &'a str,
        lgpl_3_0: &'a str,
        gpl_3_0: &'a str,
    }
    let payload = LicenseOut {
        product: PRODUCT,
        copyright: COPYRIGHT,
        license: "Apache-2.0",
        repository: REPOSITORY,
        notice: &notice,
        circuits_notice: &circuits_notice,
        apache_2_0: &apache_2_0,
        lgpl_3_0: &lgpl_3_0,
        gpl_3_0: &gpl_3_0,
    };
    if json {
        return output::emit(&payload, true);
    }

    output::print_section(payload.product);
    output::print_kv("copyright", payload.copyright);
    output::print_kv("license", payload.license);
    output::print_kv("repository", payload.repository);

    output::print_section("\n=== NOTICE ===");
    println!("{}", payload.notice);
    output::print_section("\n=== Circuits NOTICE ===");
    println!("{}", payload.circuits_notice);
    output::print_section("\n=== Apache License 2.0 ===");
    println!("{}", payload.apache_2_0);
    output::print_section("\n=== GNU Lesser General Public License v3.0 (iden3/circomlib) ===");
    println!("{}", payload.lgpl_3_0);
    output::print_section("\n=== GNU General Public License v3.0 ===");
    println!("{}", payload.gpl_3_0);
    Ok(())
}

/// Locate the `dist` directory holding the license/notice texts: the installed
/// data-dir bundle, else (for in-repo runs) the repository's `dist/`.
fn resolve_dist_dir(config: &CliConfig) -> Result<PathBuf> {
    let installed = config.data_dir.join("dist");
    if installed.is_dir() {
        return Ok(installed);
    }
    let repo_dist = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../dist");
    if repo_dist.is_dir() {
        return Ok(repo_dist);
    }
    bail!(
        "license/notice files not found under {} — install the CLI \
         (deployments/scripts/install.sh) or build the dist",
        installed.display()
    );
}

fn read(dist: &Path, rel: &str) -> Result<String> {
    let path = dist.join(rel);
    std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))
}
