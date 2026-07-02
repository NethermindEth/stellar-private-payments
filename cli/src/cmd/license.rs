//! `license` — the distribution/license notice, mirroring the app footer, plus
//! the full license texts and NOTICEs bundled into the binary.
//!
//! The license texts are embedded at build time via `include_str!` so the
//! standalone binary can satisfy the same distribution obligations as the web
//! `dist/` bundle — in particular LGPL-3.0 §4, which requires the compiled
//! circuit artifacts to be accompanied by the LGPL-3.0 text, a copy of the
//! GPL-3.0, the circuits NOTICE, and a pointer to Corresponding Source.

use anyhow::Result;
use serde::Serialize;

use crate::{config::CliConfig, output};

const REPOSITORY: &str = "https://github.com/NethermindEth/stellar-private-payments";
const COPYRIGHT: &str = "Copyright 2025 Stellar Development Foundation";
const PRODUCT: &str = "Stellar Private Payments — Proof of Concept Demo";

// Verbatim license texts, embedded from the repo root.
const APACHE_2_0: &str = include_str!("../../../LICENSE");
const NOTICE: &str = include_str!("../../../deployments/legal/dist/NOTICE.txt");
const LGPL_3_0: &str = include_str!("../../../deployments/legal/licenses/LGPL-3.0.txt");
const GPL_3_0: &str = include_str!("../../../circuits/COPYING");

// Circuits NOTICE with its provenance placeholders already filled by
// `build.rs` (via the shared `fill-circuits-notice.sh`). Only
// `@SOURCE_BUNDLE_URL@` remains, filled at runtime below.
const CIRCUITS_NOTICE_TEMPLATE: &str =
    include_str!(concat!(env!("OUT_DIR"), "/circuits-NOTICE.txt"));

pub fn run(_config: &CliConfig, json: bool) -> Result<()> {
    // The circuits source bundle is published as an asset on the GitHub Release
    // matching this CLI version.
    let source_bundle_url = format!("{REPOSITORY}/releases/tag/v{}", env!("CARGO_PKG_VERSION"));
    let circuits_notice =
        CIRCUITS_NOTICE_TEMPLATE.replace("@SOURCE_BUNDLE_URL@", &source_bundle_url);

    #[derive(Serialize)]
    struct LicenseOut<'a> {
        product: &'a str,
        copyright: &'a str,
        license: &'a str,
        repository: &'a str,
        circuits_source_bundle: &'a str,
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
        circuits_source_bundle: &source_bundle_url,
        notice: NOTICE,
        circuits_notice: &circuits_notice,
        apache_2_0: APACHE_2_0,
        lgpl_3_0: LGPL_3_0,
        gpl_3_0: GPL_3_0,
    };
    if json {
        return output::emit(&payload, true);
    }

    output::print_section(payload.product);
    output::print_kv("copyright", payload.copyright);
    output::print_kv("license", payload.license);
    output::print_kv("repository", payload.repository);
    output::print_kv("circuits_source_bundle", payload.circuits_source_bundle);

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
