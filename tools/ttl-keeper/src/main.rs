//! Keeps a deployment's ledger entries from being archived.
//!
//! Soroban expires persistent contract data that nobody touches. The keeper
//! enumerates every entry a deployment owns, asks the RPC which of them exist
//! and for how long, restores what the RPC reports archived, and extends what
//! is close to expiry.

mod keys;
mod ops;
mod state;

use anyhow::{Context, Result, bail};
use clap::Parser;
use state::State;
use std::{num::NonZeroUsize, path::PathBuf, time::Duration};
use stellar_private_payments::{
    chain::{Client, LocalSigner},
    types::ContractConfig,
};
use stellar_xdr::{self as xdr, LedgerKey};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, Parser)]
#[command(
    name = "ttl-keeper",
    about = "Extends the storage lifetime of a deployment"
)]
struct Args {
    /// Deployment manifest naming the contracts to keep alive.
    #[arg(long)]
    deployment: PathBuf,
    /// Soroban RPC endpoint.
    #[arg(long)]
    rpc_url: String,
    /// Bootnode endpoint, read first when paging pool events.
    #[arg(long)]
    bootnode_url: String,
    /// Environment variable holding the keeper account's secret key.
    #[arg(long, default_value = "TTL_KEEPER_SECRET")]
    keeper_secret_env: String,
    /// File holding the event cursor and the nullifiers seen so far.
    #[arg(long)]
    state_file: PathBuf,
    /// Run one round and exit.
    #[arg(long)]
    once: bool,
    /// Measure and log what a round would restore and extend, then exit
    /// without submitting anything.
    #[arg(long)]
    dry_run: bool,
    /// Seconds between rounds.
    #[arg(long, default_value_t = 3_600)]
    interval_secs: u64,
    /// Extend an entry once its remaining lifetime falls to this many ledgers.
    #[arg(long, default_value_t = 518_400)]
    threshold_ledgers: u32,
    /// Lifetime, in ledgers, an extension asks for. Without it, one ledger
    /// below the network's maximum entry lifetime, which is the most an
    /// extension may ask for.
    #[arg(long)]
    extend_to_ledgers: Option<u32>,
    /// Keys per lifetime transaction.
    #[arg(long, default_value = "100")]
    batch: NonZeroUsize,
}

/// Lowest protocol version whose RPC reports archived entries.
///
/// Before protocol 23 the RPC left an archived entry out of `getLedgerEntries`
/// the way it leaves out a key that was never written, so a keeper running
/// against such an RPC would never restore anything and never know it.
const MIN_PROTOCOL: u32 = 23;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let raw = std::fs::read_to_string(&args.deployment)
        .with_context(|| format!("read {}", args.deployment.display()))?;
    let config: ContractConfig = serde_json::from_str(&raw)
        .with_context(|| format!("parse {}", args.deployment.display()))?;

    let secret = std::env::var(&args.keeper_secret_env)
        .with_context(|| format!("read {}", args.keeper_secret_env))?;
    let signer = LocalSigner::from_secret(&secret)?;

    let rpc = Client::new(&args.rpc_url)?;
    let bootnode = Client::new(&args.bootnode_url)?;
    let passphrase = network_passphrase(&config.network)?;

    let protocol = rpc.get_latest_ledger().await?.protocol_version;
    if protocol < MIN_PROTOCOL {
        bail!(
            "the RPC runs protocol {protocol}; the keeper needs {MIN_PROTOCOL} or later, \
             because earlier versions leave archived entries out of getLedgerEntries and \
             nothing would ever be restored"
        );
    }

    loop {
        let outcome = round(&args, &config, &rpc, &bootnode, &signer, passphrase).await;
        if let Err(e) = &outcome {
            tracing::error!(error = %e, "round_failed");
        }
        if args.once || args.dry_run {
            return outcome;
        }
        tokio::time::sleep(Duration::from_secs(args.interval_secs)).await;
    }
}

/// Returns the network passphrase a manifest's network name implies.
///
/// An unknown name is an error rather than a default, because signing with a
/// passphrase the network does not use produces transactions it refuses.
///
/// # Errors
///
/// Returns an error if `network` is not one this keeper knows a passphrase for.
fn network_passphrase(network: &str) -> Result<&'static str> {
    match network {
        "public" | "mainnet" => Ok("Public Global Stellar Network ; September 2015"),
        "testnet" => Ok("Test SDF Network ; September 2015"),
        "futurenet" => Ok("Test SDF Future Network ; October 2022"),
        other => bail!("no network passphrase is known for '{other}'"),
    }
}

async fn round(
    args: &Args,
    config: &ContractConfig,
    rpc: &Client,
    bootnode: &Client,
    signer: &LocalSigner,
    passphrase: &str,
) -> Result<()> {
    run_round(args, config, rpc, bootnode, signer, passphrase).await
}

async fn run_round(
    args: &Args,
    config: &ContractConfig,
    rpc: &Client,
    bootnode: &Client,
    signer: &LocalSigner,
    passphrase: &str,
) -> Result<()> {
    let mut state = State::load(&args.state_file)?;
    refresh_nullifiers(config, rpc, bootnode, &mut state).await?;
    state.store(&args.state_file)?;

    let keys = keys::build(rpc, config, &state.nullifiers).await?;
    let measurement = ops::measure(rpc, &keys).await?;
    let archived = ops::archived(&measurement);
    let mut stale = ops::below_threshold(&measurement, args.threshold_ledgers);
    // Read here so the plan can be logged, but not raised here: the restore
    // phase does not need it.
    let extend_to = ops::max_entry_ttl(rpc)
        .await
        .map(|max| ops::extend_target(args.extend_to_ledgers, max));
    report_plan(
        &measurement,
        &archived,
        &stale,
        extend_to.as_ref().ok().copied(),
        args.dry_run,
    );
    if args.dry_run {
        return extend_to.map(|_| ());
    }

    // The two phases are independent: an extension needs nothing from a
    // restore, so a restore that fails must not leave the deployment's live
    // entries unextended. Both run, and the first error is returned last.
    let mut restored = Vec::new();
    let restore = submit_batches(
        args,
        rpc,
        signer,
        passphrase,
        &archived,
        None,
        &mut restored,
    )
    .await;
    // A restored entry comes back with the network minimum lifetime, which is
    // inside the threshold, so it is extended in the same round.
    stale.extend_from_slice(&restored);
    let mut extended = Vec::new();
    let (extend, extend_to) = match extend_to {
        Ok(extend_to) => (
            submit_batches(
                args,
                rpc,
                signer,
                passphrase,
                &stale,
                Some(extend_to),
                &mut extended,
            )
            .await,
            extend_to,
        ),
        Err(e) => (Err(e), 0),
    };

    report_lowest(&measurement, &extended, extend_to);
    restore.and(extend)
}

async fn refresh_nullifiers(
    config: &ContractConfig,
    rpc: &Client,
    bootnode: &Client,
    state: &mut State,
) -> Result<()> {
    let pools: Vec<(String, u32)> = config
        .pools
        .iter()
        .filter(|p| p.enabled)
        .map(|p| (p.pool_contract_id.clone(), p.deployment_ledger))
        .collect();
    if pools.is_empty() {
        return Ok(());
    }

    let (found, cursor) =
        keys::nullifiers_since(bootnode, rpc, &pools, state.cursor.clone()).await?;
    for (pool_id, nullifiers) in &found {
        state.extend_pool(pool_id, nullifiers.iter().map(keys::bytes_to_hex));
    }
    state.cursor = cursor;
    Ok(())
}

/// Submits `keys` in batches, appending the keys each confirmed transaction
/// named to `submitted`.
///
/// The simulation drops a key that needs nothing from the footprint, so
/// `submitted` can end up shorter than `keys`, and a batch whose footprint
/// comes back empty is not submitted at all. `submitted` is an out parameter
/// so that the batches confirmed before a failing one are still known to the
/// caller.
///
/// An extend whose simulation asks for a restore first names a key the RPC's
/// ledger-state answer called live and its simulation calls archived. The
/// keeper restores those keys, counts the disagreement, and simulates the
/// extend again.
///
/// # Errors
///
/// Returns an error if a simulation, a submission, or a confirmation fails,
/// or if the RPC still asks for a restore after the keys it named have been
/// restored.
async fn submit_batches(
    args: &Args,
    rpc: &Client,
    signer: &LocalSigner,
    passphrase: &str,
    keys: &[LedgerKey],
    extend_to: Option<u32>,
    submitted: &mut Vec<LedgerKey>,
) -> Result<()> {
    let operation = if extend_to.is_some() {
        "extend"
    } else {
        "restore"
    };

    for chunk in keys.chunks(args.batch.get()) {
        let mut simulated = simulate_batch(rpc, signer, chunk, extend_to).await?;
        if !simulated.restore_first.is_empty() {
            // One occurrence is an entry that expired between the read and the
            // simulation; the alert rule is what notices a repeat.
            tracing::warn!(
                keys = simulated.restore_first.len(),
                "rpc_simulation_calls_archived_what_its_ledger_state_called_live"
            );
            if extend_to.is_none() {
                bail!("a restore simulation asked for a restore of its own keys");
            }
            Box::pin(submit_batches(
                args,
                rpc,
                signer,
                passphrase,
                &simulated.restore_first,
                None,
                &mut Vec::new(),
            ))
            .await?;
            simulated = simulate_batch(rpc, signer, chunk, extend_to).await?;
            if !simulated.restore_first.is_empty() {
                // Sending anyway would extend nothing for those keys and count
                // them as extended, which is the failure this branch exists
                // to prevent.
                bail!(
                    "the RPC still asks to restore {} keys after they were restored",
                    simulated.restore_first.len()
                );
            }
        }

        let dropped = chunk.len().saturating_sub(simulated.keys.len());
        if dropped > 0 {
            tracing::info!(
                operation,
                dropped,
                "keys_the_simulation_left_out_of_the_footprint"
            );
        }
        if simulated.keys.is_empty() {
            continue;
        }

        let hash = ops::send(rpc, signer, passphrase, &simulated).await?;
        tracing::info!(
            keys = simulated.keys.len(),
            operation,
            %hash,
            "lifetime_transaction_confirmed"
        );
        submitted.extend(simulated.keys);
    }
    Ok(())
}

async fn simulate_batch(
    rpc: &Client,
    signer: &LocalSigner,
    chunk: &[LedgerKey],
    extend_to: Option<u32>,
) -> Result<ops::Simulated> {
    let sequence = next_sequence(rpc, signer.public_key()).await?;
    let envelope = match extend_to {
        Some(extend_to) => {
            ops::extend_envelope(signer.public_key(), sequence, chunk.to_vec(), extend_to)?
        }
        None => ops::restore_envelope(signer.public_key(), sequence, chunk.to_vec())?,
    };
    ops::simulate(rpc, envelope).await
}

async fn next_sequence(rpc: &Client, address: &str) -> Result<i64> {
    let account = rpc.get_account(address).await?;
    account
        .seq_num
        .0
        .checked_add(1)
        .context("account sequence number overflowed")
}

/// Logs what the round found and, on a dry run, every key it would name.
///
/// `extend_to` is absent when the network's maximum lifetime could not be read.
fn report_plan(
    measurement: &ops::Measurement,
    archived: &[LedgerKey],
    stale: &[LedgerKey],
    extend_to: Option<u32>,
    dry_run: bool,
) {
    let absent = measurement
        .entries
        .iter()
        .filter(|m| m.lifetime == ops::Lifetime::Absent)
        .count();
    tracing::info!(
        entries = measurement.entries.len(),
        latest_ledger = measurement.latest_ledger,
        absent,
        archived = archived.len(),
        stale = stale.len(),
        extend_to,
        "round_planned"
    );
    if !dry_run {
        return;
    }
    for key in archived {
        tracing::info!(key = %describe(key), "would_restore");
    }
    // A restored entry is extended in the same round, so it is listed twice.
    for key in stale.iter().chain(archived) {
        tracing::info!(key = %describe(key), "would_extend");
    }
}

/// Renders a key the way an operator reads it: the contract, the storage
/// variant, and the variant's arguments, with a `u256` in the hexadecimal the
/// state file uses.
fn describe(key: &LedgerKey) -> String {
    let argument = |part: &xdr::ScVal| match part {
        xdr::ScVal::U32(value) => value.to_string(),
        xdr::ScVal::U256(_) => keys::u256_bytes(part)
            .map_or_else(|_| format!("{part:?}"), |bytes| keys::bytes_to_hex(&bytes)),
        other => format!("{other:?}"),
    };
    match key {
        LedgerKey::ContractData(data) => match &data.key {
            xdr::ScVal::LedgerKeyContractInstance => format!("{} instance", data.contract),
            xdr::ScVal::Vec(Some(parts)) => {
                let mut parts = parts.iter();
                let variant = match parts.next() {
                    Some(xdr::ScVal::Symbol(name)) => name.to_string(),
                    other => format!("{other:?}"),
                };
                let arguments: Vec<String> = parts.map(argument).collect();
                format!("{} {variant}({})", data.contract, arguments.join(", "))
            }
            other => format!("{} {other:?}", data.contract),
        },
        LedgerKey::ContractCode(code) => format!("wasm {}", code.hash),
        other => format!("{other:?}"),
    }
}

/// Logs the shortest remaining lifetime each contract's entries have left.
fn report_lowest(measurement: &ops::Measurement, extended: &[LedgerKey], extend_to: u32) {
    let lowest = ops::lowest_by_contract(measurement, extended, extend_to);
    for (contract, remaining_ledgers) in &lowest {
        tracing::info!(%contract, remaining_ledgers, "contract_lowest_lifetime");
    }
    tracing::info!(
        entries = measurement.entries.len(),
        contracts = lowest.len(),
        "round_complete"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_manifest_network_selects_the_passphrase() {
        let of = |network| network_passphrase(network).expect("known network");
        assert_eq!(of("public"), of("mainnet"));
        assert_eq!(
            of("public"),
            "Public Global Stellar Network ; September 2015"
        );
        assert_eq!(of("testnet"), "Test SDF Network ; September 2015");
        assert_eq!(of("futurenet"), "Test SDF Future Network ; October 2022");
        assert!(network_passphrase("localnet").is_err());
    }

    #[test]
    fn a_key_is_described_by_contract_variant_and_arguments() {
        let contract = keys::address("CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE")
            .expect("address");
        let root = keys::data_key(&contract, "Root", vec![xdr::ScVal::U32(89)]).expect("key");
        assert_eq!(
            describe(&root),
            "CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE Root(89)"
        );
        let nullifier =
            keys::data_key(&contract, "Nullifier", vec![keys::u256([7u8; 32])]).expect("key");
        assert!(describe(&nullifier).ends_with(&format!("Nullifier({})", "07".repeat(32))));
        assert!(describe(&keys::instance_key(&contract)).ends_with(" instance"));
    }
}
