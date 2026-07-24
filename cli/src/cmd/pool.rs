//! Core value operations: deposit, transfer, withdraw. Each takes the pool
//! contract id and requires a ready account.

use anyhow::Result;
use stellar_private_payments_sdk::{Error, types::TransactionResult};

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
    let _span = tracing::info_span!(
        "cmd_deposit",
        correlation_id = %types::correlation_id_or_new(),
        amount = ?types::Sensitive(&amount)
    )
    .entered();
    let pool = open_pool(config, pool)?;
    let amount = parse_amount(amount)?;
    let result = pool
        .deposit(amount)
        .map_err(|e| map_pool_err(config, e, json))?;
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
    let _span = tracing::info_span!(
        "cmd_transfer",
        correlation_id = %types::correlation_id_or_new(),
        amount = ?types::Sensitive(&amount),
        recipient = ?types::Sensitive(&to)
    )
    .entered();
    let pool = open_pool(config, pool)?;
    let recipient = parse_transfer_recipient(to, note_key, encryption_key)?;
    let amount = parse_amount(amount)?;
    let results = pool
        .transfer(recipient, amount)
        .map_err(|e| map_pool_err(config, e, json))?;
    print_tx_results(config, "Transfer submitted", &results, json)
}

pub fn withdraw(
    config: &CliConfig,
    pool: &str,
    amount: &str,
    to: Option<&str>,
    json: bool,
) -> Result<()> {
    let _span = tracing::info_span!(
        "cmd_withdraw",
        correlation_id = %types::correlation_id_or_new(),
        amount = ?types::Sensitive(&amount),
        recipient = ?types::Sensitive(&to)
    )
    .entered();
    let recipient = match to {
        Some(address) => address.to_string(),
        None => config.require_account()?.address,
    };
    let pool = open_pool(config, pool)?;
    let amount = parse_amount(amount)?;
    let results = pool
        .withdraw(amount, recipient)
        .map_err(|e| map_pool_err(config, e, json))?;
    print_tx_results(config, "Withdraw submitted", &results, json)
}

fn map_pool_err(config: &CliConfig, error: Error, json: bool) -> anyhow::Error {
    if let Error::PlanExecution(plan) = &error {
        if !plan.completed.is_empty() {
            if json {
                let _ = output::emit(&plan.completed, true);
            } else {
                let _ =
                    print_tx_results(config, "Completed before failure", &plan.completed, false);
            }
        }
        anyhow::anyhow!("{}", plan.cause())
    } else {
        anyhow::anyhow!("{error}")
    }
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
