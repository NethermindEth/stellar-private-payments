//! Demonstrates deployment-level synchronization without any secrets.
//!
//! This example uses a read-only SDK client, so it needs neither circuit
//! artifacts nor `STELLAR_SECRET_KEY`. It does need network access to the
//! configured Soroban RPC endpoint (testnet by default).
//!
//! Run:
//!   cargo run --release --example sync
//!
//! Env vars:
//!   SPP_RPC_URL          default: https://soroban-testnet.stellar.org
//!   SPP_BOOTNODE_URL     default: https://bootnode.dev-nethermind.xyz
//!   SPP_WALLET_PATH      default: ./spp-example-wallet.sqlite
//!   SPP_DEPLOYMENT_JSON  default: deployments/testnet/deployments.json
//!
//! # Known limitation
//!
//! The checked-in testnet deployment is older than the public Soroban RPC
//! retention window, so a fresh wallet sometimes cannot sync the full
//! historical range. When this happens the example prints an explanation and
//! exits 0. Remedies: use `SPP_BOOTNODE_URL` to point to a bootnode with a
//! fresher handoff, use a full-history `SPP_RPC_URL`, or retry later.

mod common;

use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    common::init_tracing()?;

    let config = common::load_contract_config()?;
    let storage = common::open_storage()?;
    let client = common::build_readonly_client(storage, config.clone())?;

    let rpc_url = common::env_or("SPP_RPC_URL", "https://soroban-testnet.stellar.org");
    println!("Network: {}", config.network);
    println!("RPC:     {rpc_url}");

    println!();
    let needs_bootnode = probe_bootnode(&client)?;
    println!("Bootnode required for historical sync: {needs_bootnode}");

    println!();
    println!("Running inline sync...");
    match client.sync() {
        Ok(()) => println!("Inline sync complete."),
        Err(e) if is_retention_gap_error(&e) => {
            print_retention_gap_note();
            return Ok(());
        }
        Err(e) => return Err(Box::new(e)),
    }

    println!();
    println!("Starting background sync for ~5 seconds...");
    let mut client_for_bg = client;
    let background = client_for_bg.background_sync()?;
    let stop = background.stop_handle();
    let handle = std::thread::spawn(move || run_background_sync(background));
    std::thread::sleep(Duration::from_secs(5));
    stop.request();
    let bg_result = handle
        .join()
        .map_err(|e| format!("background sync thread panicked: {e:?}"))?;
    match bg_result {
        Ok(()) => println!("Background sync stopped."),
        Err(e) if is_retention_gap_error_str(&e) => print_retention_gap_note(),
        Err(e) => return Err(Box::new(std::io::Error::other(e))),
    }

    println!();
    println!("Recent operational feed:");
    let feed = client_for_bg.operational_feed(10)?;
    if feed.is_empty() {
        println!("  (no entries yet)");
    } else {
        for item in feed {
            println!("  [ledger {}] {}: {}", item.ledger, item.title, item.body);
        }
    }

    Ok(())
}

/// Delegates to [`common::is_retention_gap_error`] so both detectors stay in
/// step; keeping a second copy here is what let them drift apart.
fn is_retention_gap_error(e: &dyn std::error::Error) -> bool {
    common::is_retention_gap_error(e)
}

fn is_retention_gap_error_str(msg: &str) -> bool {
    common::is_retention_gap_message(msg)
}

fn print_retention_gap_note() {
    println!("NOTE: The wallet's required history is older than the RPC retention window,");
    println!("      and the configured bootnode's handoff point is stale.");
    println!("      Remedies:");
    println!("        - Set SPP_BOOTNODE_URL to a bootnode with a fresher handoff point,");
    println!("        - Set SPP_RPC_URL to a full-history RPC endpoint, or");
    println!("        - Retry later.");
}

/// Probe whether the main RPC can serve the full deployment history.
fn probe_bootnode(client: &stellar_private_payments::blocking::Client) -> Result<bool, String> {
    let fetcher = client
        .state_fetcher()
        .map_err(|e| format!("state fetcher: {e}"))?;
    let runtime = tokio::runtime::Runtime::new().map_err(|e| format!("tokio runtime: {e}"))?;
    runtime
        .block_on(stellar_private_payments::bootnode_required(
            fetcher.rpc(),
            client.storage(),
            client.contract_config(),
        ))
        .map_err(|e| format!("bootnode probe: {e}"))
}

/// Run the background indexer on a dedicated thread.
fn run_background_sync(
    background: stellar_private_payments::BackgroundSync<stellar_private_payments::LocalStorage>,
) -> Result<(), String> {
    let runtime = tokio::runtime::Runtime::new().map_err(|e| format!("tokio runtime: {e}"))?;
    runtime
        .block_on(background.run())
        .map_err(|e| format!("background sync: {e}"))
}
