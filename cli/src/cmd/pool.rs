//! Core value operations: deposit, transfer, withdraw. Each takes the pool
//! contract id and requires a ready account.

use anyhow::Result;
use stellar_private_payments_sdk::types::TransactionResult;

use crate::{
    config::{CliConfig, validate_pool},
    explorer::Explorer,
    onboard, output,
    session::{ClientSession, parse_amount, parse_transfer_recipient},
};

fn open_pool(
    config: &CliConfig,
    pool: &str,
) -> Result<stellar_private_payments_sdk::blocking::PrivatePool> {
    let account = config.require_account()?;
    onboard::ensure_ready(config, &account)?;
    validate_pool(pool, &config.deployment)?;
    let network = config.resolve_network()?;
    ClientSession::new(config, &account, &network, false)?.pool(pool)
}

pub fn deposit(config: &CliConfig, pool: &str, amount: &str, json: bool) -> Result<()> {
    let pool = open_pool(config, pool)?;
    let amount = parse_amount(amount)?;
    let result = pool.deposit(amount).map_err(|e| anyhow::anyhow!("{e}"))?;
    print_tx_results(
        config,
        "Deposit submitted",
        std::slice::from_ref(&result),
        json,
    )
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
    let pool = open_pool(config, pool)?;
    let recipient = parse_transfer_recipient(to, note_key, encryption_key)?;
    let amount = parse_amount(amount)?;
    let results = pool
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
    let pool = open_pool(config, pool)?;
    let amount = parse_amount(amount)?;
    let results = pool
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
