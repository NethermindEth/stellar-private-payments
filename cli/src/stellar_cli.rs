//! Thin wrapper over the installed `stellar` CLI binary.
//!
//! Account operations are delegated to the official Stellar CLI so the private
//! payments CLI never handles a raw mnemonic or secret key: identities live in
//! the Stellar CLI's alias store (`stellar keys …`). We shell out for:
//!
//! * resolve an alias to its address ([`public_key`]),
//! * produce the SEP-53 key-derivation signature ([`sign_message`]), and
//! * sign transaction envelopes ([`sign_tx`]), including OS secure-store keys.

use std::{
    io::Write,
    path::Path,
    process::{Command, Stdio},
    time::Instant,
};

use anyhow::{Context, Result, bail};

use stellar_private_payments_sdk::{chain::Signature, types::KeyDerivationSignature};
use types::correlation_id_or_new;

/// Env var to override the `stellar` binary path (default: `stellar` on PATH).
const STELLAR_BIN_ENV: &str = "STELLAR_BIN";
const DEFAULT_BIN: &str = "stellar";

fn stellar_bin() -> String {
    std::env::var(STELLAR_BIN_ENV).unwrap_or_else(|_| DEFAULT_BIN.to_string())
}

/// Run `stellar <args…>` (with an optional `--config-dir`) and return trimmed
/// stdout. Info logs go to stderr and are ignored on success.
#[tracing::instrument(
    name = "stellar_cli_run",
    skip_all,
    fields(correlation_id = %correlation_id_or_new())
)]
fn run(args: &[String], config_dir: Option<&Path>) -> Result<String> {
    let start = Instant::now();
    let bin = stellar_bin();
    // Full args are Sensitive-wrapped: some call sites (e.g. `message sign`)
    // pass payload/Tier-1 values in args, so they stay redacted by default.
    tracing::info!(
        bin = %bin,
        subcommand = %args.first().map(String::as_str).unwrap_or(""),
        args = ?types::Sensitive(&args),
        "running external stellar command"
    );
    let mut cmd = Command::new(&bin);
    cmd.args(args);
    if let Some(dir) = config_dir {
        cmd.arg("--config-dir").arg(dir);
    }
    let result = cmd.output().with_context(|| {
        format!(
            "failed to run `{bin}`; install the Stellar CLI (https://stellar.org/cli) \
             or set {STELLAR_BIN_ENV} to its path"
        )
    });
    let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    match &result {
        Ok(output) => tracing::debug!(
            exit_status = %output.status,
            stdout_len = output.stdout.len(),
            stderr_len = output.stderr.len(),
            elapsed_ms,
            "external stellar command exited"
        ),
        Err(_) => tracing::debug!(elapsed_ms, "external stellar command failed to start"),
    }
    let output = result?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("`{bin} {}` failed: {}", args.join(" "), stderr.trim());
    }
    let stdout =
        String::from_utf8(output.stdout).context("stellar CLI produced non-UTF-8 output")?;
    Ok(stdout.trim().to_string())
}

/// Resolve an alias to its Stellar address (`G…`) via `stellar keys
/// public-key`.
#[tracing::instrument(
    name = "stellar_public_key",
    skip_all,
    fields(correlation_id = %correlation_id_or_new(), alias = ?types::Sensitive(&alias))
)]
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
#[tracing::instrument(
    name = "stellar_sign_message",
    skip_all,
    fields(correlation_id = %correlation_id_or_new(), alias = ?types::Sensitive(&alias), message_len = message.len())
)]
pub fn sign_message(
    alias: &str,
    message: &str,
    config_dir: Option<&Path>,
) -> Result<KeyDerivationSignature> {
    // The message contents and the produced signature are never logged.
    tracing::info!(
        alias = ?types::Sensitive(&alias),
        message_len = message.len(),
        "awaiting external signer (may prompt for key)"
    );
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

/// Sign an unsigned transaction envelope via `stellar tx sign`.
///
/// Works for identities stored in the config file or OS secure store. The
/// unsigned envelope XDR is passed on stdin; signed envelope XDR is returned
/// from stdout.
#[tracing::instrument(
    name = "stellar_sign_tx",
    skip_all,
    fields(correlation_id = %correlation_id_or_new(), alias = ?types::Sensitive(&alias), xdr_len = tx_xdr.len(), network = %network_passphrase)
)]
pub fn sign_tx(
    alias: &str,
    tx_xdr: &str,
    rpc_url: &str,
    network_passphrase: &str,
    config_dir: Option<&Path>,
) -> Result<String> {
    let start = Instant::now();
    // Host part of the RPC URL (scheme and path stripped); the envelope XDR
    // and the signed XDR output are never logged.
    let rpc_host = rpc_url
        .split("://")
        .nth(1)
        .unwrap_or(rpc_url)
        .split('/')
        .next()
        .unwrap_or("");
    tracing::info!(
        alias = ?types::Sensitive(&alias),
        xdr_len = tx_xdr.len(),
        network = %network_passphrase,
        rpc_host,
        "awaiting external signer (--auto-sign may block on hardware/secure-store prompt)"
    );
    let bin = stellar_bin();
    let mut cmd = Command::new(&bin);
    cmd.args([
        "tx",
        "sign",
        "--sign-with-key",
        alias,
        "--auto-sign",
        "--rpc-url",
        rpc_url,
        "--network-passphrase",
        network_passphrase,
    ]);
    if let Some(dir) = config_dir {
        cmd.arg("--config-dir").arg(dir);
    }
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().with_context(|| {
        format!(
            "failed to run `{bin} tx sign`; install the Stellar CLI (https://stellar.org/cli) \
             or set {STELLAR_BIN_ENV} to its path"
        )
    })?;

    child
        .stdin
        .take()
        .context("stellar tx sign stdin")?
        .write_all(tx_xdr.as_bytes())
        .context("write transaction XDR to stellar tx sign")?;

    let result = child.wait_with_output().context("wait for stellar tx sign");
    let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    match &result {
        Ok(output) => tracing::debug!(
            exit_status = %output.status,
            stdout_len = output.stdout.len(),
            stderr_len = output.stderr.len(),
            elapsed_ms,
            "external stellar command exited"
        ),
        Err(_) => tracing::debug!(elapsed_ms, "external stellar command failed"),
    }
    let output = result?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "`{bin} tx sign --sign-with-key {alias}` failed: {}",
            stderr.trim()
        );
    }

    let stdout =
        String::from_utf8(output.stdout).context("stellar CLI produced non-UTF-8 output")?;
    Ok(stdout.trim().to_string())
}

/// A network's connection parameters, resolved from the Stellar CLI.
#[derive(Debug, Clone)]
pub struct StellarNetwork {
    pub rpc_url: String,
    pub passphrase: String,
}

/// Confirm the `stellar` binary is available, returning its version line.
pub fn ensure_installed() -> Result<String> {
    run(&["--version".to_string()], None).map_err(|e| {
        anyhow::anyhow!(
            "{e}\n\nInstall the Stellar CLI: https://github.com/stellar/stellar-cli#install"
        )
    })
}

/// Resolve a network's RPC URL and passphrase from the Stellar CLI's own
/// network config (built-in networks like `testnet` and any custom ones added
/// via `stellar network add`), by parsing `stellar network ls --long`.
#[tracing::instrument(
    name = "stellar_network_lookup",
    skip_all,
    fields(correlation_id = %correlation_id_or_new(), network = %name)
)]
pub fn network(name: &str, config_dir: Option<&Path>) -> Result<StellarNetwork> {
    let listing = run(
        &[
            "network".to_string(),
            "ls".to_string(),
            "--long".to_string(),
        ],
        config_dir,
    )?;

    // Blocks are separated by blank lines; each has `Name:`, `RPC url:`,
    // `Network passphrase:` fields.
    for block in listing.split("\n\n") {
        let mut block_name = None;
        let mut rpc_url = None;
        let mut passphrase = None;
        for line in block.lines() {
            let line = line.trim();
            if let Some(v) = line.strip_prefix("Name:") {
                block_name = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("RPC url:") {
                rpc_url = Some(v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("Network passphrase:") {
                passphrase = Some(v.trim().to_string());
            }
        }
        if block_name.as_deref() != Some(name) {
            continue;
        }
        let (Some(rpc_url), Some(passphrase)) = (rpc_url, passphrase) else {
            bail!("network `{name}` is missing an RPC url or passphrase in the Stellar CLI config");
        };
        if !(rpc_url.starts_with("http://") || rpc_url.starts_with("https://")) {
            bail!(
                "network `{name}` has no usable RPC url (`{rpc_url}`). \
                 Configure one with `stellar network add {name} --rpc-url <URL> --network-passphrase <PHRASE>`"
            );
        }
        return Ok(StellarNetwork {
            rpc_url,
            passphrase,
        });
    }
    bail!(
        "network `{name}` is not known to the Stellar CLI; add it with \
         `stellar network add {name} --rpc-url <URL> --network-passphrase <PHRASE>` \
         or pick another with --network"
    )
}

/// Enforce alias-only usage: reject raw secret keys and seed phrases so secrets
/// never appear on the command line or in config.
pub fn validate_alias(value: &str) -> Result<()> {
    if value.chars().any(char::is_whitespace) {
        bail!(
            "--account must be a `stellar keys` alias name, not a seed phrase; \
             register one with `stellar keys add`/`stellar keys generate`"
        );
    }
    if value.len() == 56 && value.starts_with('S') {
        bail!(
            "--account must be a `stellar keys` alias name, not a raw secret key; \
             register one with `stellar keys add`"
        );
    }
    Ok(())
}
