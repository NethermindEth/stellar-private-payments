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
        let msg = if stderr.trim().is_empty() {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        } else {
            stderr.trim().to_string()
        };
        bail!(
            "stellar {} failed (exit {}): {}",
            args.join(" "),
            output.status,
            msg
        );
    }

    let stdout = String::from_utf8(output.stdout).context("Invalid UTF-8 in stellar output")?;
    Ok(stdout.trim().to_string())
}

/// Get the G... public address for a stellar identity.
pub fn keys_address(name: &str, _network: &str) -> Result<String> {
    run_stellar(&["keys", "address", name])
}

/// Get the S... secret key for a stellar identity.
pub fn keys_secret(name: &str, _network: &str) -> Result<String> {
    run_stellar(&["keys", "secret", name])
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

/// Determine a good start ledger for event syncing.
///
/// The Stellar RPC `getEvents` has a limited scan window (~10,000 ledgers).
/// Starting from the oldest retained ledger would miss events at recent
/// ledgers. Instead, we probe to find the valid ledger range (min - max)
/// and return a start ledger close to the latest, within the scan window.
///
/// Returns `None` if the start ledger `1` is already valid (local/standalone).
pub fn get_oldest_ledger(contract_id: &str, network: &str) -> Result<Option<u64>> {
    let args = [
        "events",
        "--id",
        contract_id,
        "--output",
        "json",
        "--count",
        "1",
        "--network",
        network,
        "--start-ledger",
        "1",
    ];

    let output = Command::new("stellar")
        .args(args)
        .output()
        .context("Failed to run `stellar` CLI")?;

    if output.status.success() {
        // Ledger 1 was accepted — no adjustment needed (standalone/local)
        return Ok(None);
    }

    // Check both stderr and stdout — the Stellar CLI may put the error on either.
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stderr}\n{stdout}");

    // Parse: "startLedger must be within the ledger range: 920027 - 1040986"
    if let Some(pos) = combined.find("ledger range:") {
        let after = &combined[pos..];
        let nums: Vec<u64> = after
            .split(|c: char| !c.is_ascii_digit())
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.parse().ok())
            .collect();
        if nums.len() >= 2 {
            let min_ledger = nums[0];
            let max_ledger = nums[1];
            // The RPC scan window is ~10,000 ledgers. Start from
            // max - 10,000 to ensure we can reach recent events.
            // Clamp to min_ledger so we don't go below the valid range.
            let start = max_ledger.saturating_sub(10_000).max(min_ledger);
            return Ok(Some(start));
        }
        // Fallback: only got one number (min), use it with buffer
        if let Some(&min_ledger) = nums.first() {
            return Ok(Some(min_ledger.saturating_add(10)));
        }
    }

    // Could not parse — propagate original error
    bail!(
        "stellar events failed and could not determine valid ledger range: {}",
        combined.trim()
    );
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
