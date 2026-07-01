//! `license` — the distribution/license notice, mirroring the app footer, plus
//! the path to the circuits source bundle.

use anyhow::Result;
use serde::Serialize;

use crate::{config::CliConfig, output};

const REPOSITORY: &str = "https://github.com/NethermindEth/stellar-private-payments";
const COPYRIGHT: &str = "Copyright 2025 Stellar Development Foundation";
const DISTRIBUTION_NOTICE: &str = "NOTICE · Circuits NOTICE · LGPL-3.0 · GPL-3.0 · Apache-2.0";
// Placeholder until the circuits source bundle ships alongside releases.
const CIRCUITS_SOURCE_BUNDLE: &str = "./circuits/source-bundle.tar.gz";

pub fn run(_config: &CliConfig, json: bool) -> Result<()> {
    #[derive(Serialize)]
    struct LicenseOut<'a> {
        product: &'a str,
        copyright: &'a str,
        license: &'a str,
        repository: &'a str,
        distribution_notice: &'a str,
        circuits_source_bundle: &'a str,
    }
    let payload = LicenseOut {
        product: "Stellar Private Payments — Proof of Concept Demo",
        copyright: COPYRIGHT,
        license: "Apache-2.0",
        repository: REPOSITORY,
        distribution_notice: DISTRIBUTION_NOTICE,
        circuits_source_bundle: CIRCUITS_SOURCE_BUNDLE,
    };
    if json {
        return output::emit(&payload, true);
    }
    output::print_section(payload.product);
    output::print_kv("copyright", payload.copyright);
    output::print_kv("license", payload.license);
    output::print_kv("repository", payload.repository);
    output::print_kv("distribution_notice", payload.distribution_notice);
    output::print_kv("circuits_source_bundle", payload.circuits_source_bundle);
    println!("\nThe source code is licensed under the Apache License, Version 2.0.");
    Ok(())
}
