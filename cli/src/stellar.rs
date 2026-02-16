//! Wraps stellar CLI subprocess calls (events, invoke, keys).

use anyhow::{Context, Result, bail};
use std::process::Command;

/// Run a stellar CLI command and return stdout as a string.
fn run_stellar(args: &[&str]) -> Result<String> {
    let output = Command::new("stellar")
        .args(args)
        .output()
        .context("Failed to run `stellar` CLI. Is it installed and in PATH?")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "stellar {} failed (exit {}): {}",
            args.join(" "),
            output.status,
            stderr.trim()
        );
    }

    let stdout = String::from_utf8(output.stdout).context("Invalid UTF-8 in stellar output")?;
    Ok(stdout.trim().to_string())
}

/// Get the G... public address for a stellar identity.
pub fn keys_address(name: &str, network: &str) -> Result<String> {
    run_stellar(&["keys", "address", name, "--network", network])
}

/// Get the S... secret key for a stellar identity.
pub fn keys_secret(name: &str, network: &str) -> Result<String> {
    run_stellar(&["keys", "secret", name, "--network", network])
}

/// Fetch contract events as JSON.
///
/// Returns the raw JSON string from `stellar events`.
pub fn fetch_events(
    contract_id: &str,
    start_ledger: u64,
    cursor: Option<&str>,
    network: &str,
) -> Result<String> {
    let start_str = start_ledger.to_string();

    let mut args = vec![
        "events",
        "--id",
        contract_id,
        "--output",
        "json",
        "--count",
        "1000",
        "--network",
        network,
    ];

    if let Some(c) = cursor {
        args.push("--cursor");
        args.push(c);
    } else {
        args.push("--start-ledger");
        args.push(&start_str);
    }

    run_stellar(&args)
}

/// Invoke a contract function (simulation only, no submission).
pub fn contract_invoke_view(
    contract_id: &str,
    source: &str,
    network: &str,
    function: &str,
    extra_args: &[&str],
) -> Result<String> {
    let mut args = vec![
        "contract",
        "invoke",
        "--id",
        contract_id,
        "--source-account",
        source,
        "--network",
        network,
        "--send",
        "no",
        "--",
        function,
    ];
    args.extend_from_slice(extra_args);
    run_stellar(&args)
}

/// Invoke a contract function (submit transaction).
pub fn contract_invoke(
    contract_id: &str,
    source: &str,
    network: &str,
    function: &str,
    extra_args: &[&str],
) -> Result<String> {
    let mut args = vec![
        "contract",
        "invoke",
        "--id",
        contract_id,
        "--source-account",
        source,
        "--network",
        network,
        "--",
        function,
    ];
    args.extend_from_slice(extra_args);
    run_stellar(&args)
}
