//! Core value operations: deposit, transfer, withdraw. Each takes the pool
//! contract id and requires a ready account.

use anyhow::Result;
use stellar_private_payments_sdk::types::TransactionResult;

use crate::{
    config::{CliConfig, validate_pool},
    explorer::Explorer,
    onboard, output,
    session::{PoolSession, parse_amount, resolve_transfer_recipient},
};

fn open(config: &CliConfig, pool: &str) -> Result<PoolSession> {
    let account = config.require_account()?;
    onboard::ensure_ready(config, &account)?;
    validate_pool(pool, &config.deployment)?;
    let network = config.resolve_network()?;
    PoolSession::open(
        config,
        &account,
        &network,
        pool,
        config.circuits_dir.as_deref(),
    )
}

pub fn deposit(config: &CliConfig, pool: &str, amount: &str, json: bool) -> Result<()> {
    let session = open(config, pool)?;
    let amount = parse_amount(amount)?;
    let result = session
        .pool()
        .deposit(amount)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    print_tx_results(config, "Deposit submitted", std::slice::from_ref(&result), json)
}

pub fn transfer(
    config: &CliConfig,
    pool: &str,
    amount: &str,
    to: Option<&str>,
    note_key: Option<&str>,
    encryption_key: Option<&str>,
    json: bool,
) -> Result<()> {
    let recipient = resolve_transfer_recipient(config, to, note_key, encryption_key)?;
    let session = open(config, pool)?;
    let amount = parse_amount(amount)?;
    let results = session
        .pool()
        .transfer(recipient, amount)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    print_tx_results(config, "Transfer submitted", &results, json)
}

pub fn withdraw(
    config: &CliConfig,
    pool: &str,
    amount: &str,
    to: Option<&str>,
    json: bool,
) -> Result<()> {
    let recipient = match to {
        Some(address) => address.to_string(),
        None => config.require_account()?.address,
    };
    let session = open(config, pool)?;
    let amount = parse_amount(amount)?;
    let results = session
        .pool()
        .withdraw(amount, recipient)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    print_tx_results(config, "Withdraw submitted", &results, json)
}

fn print_tx_results(
    config: &CliConfig,
    title: &str,
    results: &[TransactionResult],
    json: bool,
) -> Result<()> {
    if json {
        return output::emit(results, true);
    }
    let explorer = config
        .open_storage()
        .and_then(|s| crate::explorer::base_url(&s))
        .map(Explorer::new)
        .ok();
    output::print_section(title);
    for result in results {
        match &explorer {
            Some(explorer) => output::print_kv(
                "tx_hash",
                format!("{} → {}", result.tx_hash, explorer.tx(&result.tx_hash)),
            ),
            None => output::print_kv("tx_hash", &result.tx_hash),
        }
    }
    Ok(())
}
