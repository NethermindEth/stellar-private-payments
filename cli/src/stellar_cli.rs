//! Thin wrapper over the installed `stellar` CLI binary.
//!
//! Account operations are delegated to the official Stellar CLI so the private
//! payments CLI never handles a raw mnemonic or secret key: identities live in
//! the Stellar CLI's alias store (`stellar keys …`). We shell out for three
//! things:
//!
//! * resolve an alias to its address ([`public_key`]),
//! * produce the SEP-53 key-derivation signature ([`sign_message`]), and
//! * fetch the secret key just-in-time for transaction signing ([`secret`]).

use std::{path::Path, process::Command};

use anyhow::{Context, Result, bail};
use stellar_private_payments_sdk::{chain::Signature, types::KeyDerivationSignature};

/// Env var to override the `stellar` binary path (default: `stellar` on PATH).
const STELLAR_BIN_ENV: &str = "STELLAR_BIN";
const DEFAULT_BIN: &str = "stellar";

fn stellar_bin() -> String {
    std::env::var(STELLAR_BIN_ENV).unwrap_or_else(|_| DEFAULT_BIN.to_string())
}

/// Run `stellar <args…>` (with an optional `--config-dir`) and return trimmed
/// stdout. Info logs go to stderr and are ignored on success.
fn run(args: &[String], config_dir: Option<&Path>) -> Result<String> {
    let bin = stellar_bin();
    let mut cmd = Command::new(&bin);
    cmd.args(args);
    if let Some(dir) = config_dir {
        cmd.arg("--config-dir").arg(dir);
    }
    let output = cmd.output().with_context(|| {
        format!(
            "failed to run `{bin}`; install the Stellar CLI (https://stellar.org/cli) \
             or set {STELLAR_BIN_ENV} to its path"
        )
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("`{bin} {}` failed: {}", args.join(" "), stderr.trim());
    }
    let stdout =
        String::from_utf8(output.stdout).context("stellar CLI produced non-UTF-8 output")?;
    Ok(stdout.trim().to_string())
}

/// Resolve an alias to its Stellar address (`G…`) via `stellar keys public-key`.
pub fn public_key(alias: &str, config_dir: Option<&Path>) -> Result<String> {
    let args = vec![
        "keys".to_string(),
        "public-key".to_string(),
        alias.to_string(),
    ];
    let address = run(&args, config_dir)?;
    if !address.starts_with('G') {
        bail!("unexpected address for alias `{alias}`: {address}");
    }
    Ok(address)
}

/// Produce the SEP-53 signature of `message` via `stellar message sign`.
///
/// The Stellar CLI prefixes `"Stellar Signed Message:\n"`, SHA-256 hashes, then
/// Ed25519-signs — matching the web app / Freighter derivation exactly. Output
/// is base64 of the 64-byte signature.
pub fn sign_message(
    alias: &str,
    message: &str,
    config_dir: Option<&Path>,
) -> Result<KeyDerivationSignature> {
    let args = vec![
        "message".to_string(),
        "sign".to_string(),
        message.to_string(),
        "--sign-with-key".to_string(),
        alias.to_string(),
    ];
    let encoded = run(&args, config_dir)?;
    let signature = Signature::from_base64(&encoded)
        .context("decode SEP-53 signature returned by the stellar CLI")?;
    Ok(KeyDerivationSignature(signature.as_bytes().to_vec()))
}

/// Fetch an alias's secret key via `stellar keys secret` (transaction signing
/// only). Not available for ledger identities.
pub fn secret(alias: &str, config_dir: Option<&Path>) -> Result<String> {
    let args = vec!["keys".to_string(), "secret".to_string(), alias.to_string()];
    run(&args, config_dir)
}

/// Enforce alias-only usage: reject raw secret keys and seed phrases so secrets
/// never appear on the command line or in config.
pub fn validate_alias(value: &str) -> Result<()> {
    if value.chars().any(char::is_whitespace) {
        bail!(
            "--source-account must be a `stellar keys` alias name, not a seed phrase; \
             register one with `stellar keys add`/`stellar keys generate`"
        );
    }
    if value.len() == 56 && value.starts_with('S') {
        bail!(
            "--source-account must be a `stellar keys` alias name, not a raw secret key; \
             register one with `stellar keys add`"
        );
    }
    Ok(())
}
