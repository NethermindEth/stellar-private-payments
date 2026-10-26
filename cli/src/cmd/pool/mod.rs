//! Core value operations: deposit, transfer, withdraw, and the advanced
//! `transact`. Each takes the pool contract id and requires a ready account.

mod deposit;
pub mod transact;
mod transfer;
mod withdraw;

use anyhow::Result;
use serde::Serialize;
use stellar_private_payments::{
    Error,
    blocking::PrivatePool,
    types::{NoteAmount, TransactionResult},
};

pub use self::{deposit::deposit, transfer::transfer, withdraw::withdraw};
use crate::{
    account::Account,
    cmd::overview,
    config::{CliConfig, validate_pool},
    explorer::Explorer,
    onboard, output,
    session::ClientSession,
};

/// Resolve the account, make sure it is onboarded, and bind a session to the
/// network for `pool`. Callers that only need the pool use [`open_pool`].
fn open_session(config: &CliConfig, pool: &str) -> Result<(Account, ClientSession)> {
    let account = config.require_account()?;
    onboard::ensure_ready(config, &account)?;
    validate_pool(pool, &config.deployment)?;
    let network = config.resolve_network()?;
    let session = ClientSession::new(config, &account, &network, false)?;
    Ok((account, session))
}

fn open_pool(config: &CliConfig, pool: &str) -> Result<PrivatePool> {
    let (_, session) = open_session(config, pool)?;
    session.pool(pool)
}

/// Formats a base-unit amount in the pool token's units, for example `0.1 XLM`.
fn token_amount(pool: &PrivatePool, decimals: u32, amount: NoteAmount) -> Result<String> {
    let config = pool.config();
    let entry = config.contract_config.pool(&config.pool_contract_id)?;
    Ok(output::format_token_amount(
        u128::from(amount),
        &overview::asset_symbol(&entry.asset),
        Some(decimals),
    ))
}

/// The fee a pool charges on every transaction, in the token's units and in
/// base units.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PoolFee {
    pool_fee: String,
    pool_fee_base_units: NoteAmount,
}

fn pool_fee(pool: &PrivatePool, decimals: u32) -> Result<PoolFee> {
    let fee = pool.fee()?;
    Ok(PoolFee {
        pool_fee: token_amount(pool, decimals, fee)?,
        pool_fee_base_units: fee,
    })
}

/// One submitted transaction in a pool command's JSON output.
#[derive(Serialize)]
struct Row<'a> {
    #[serde(flatten)]
    result: &'a TransactionResult,
    #[serde(flatten)]
    fee: Option<&'a PoolFee>,
}

fn map_pool_err(
    config: &CliConfig,
    pool: &PrivatePool,
    decimals: u32,
    fee: Option<&PoolFee>,
    error: Error,
    json: bool,
) -> anyhow::Error {
    match &error {
        Error::PlanExecution(plan) => {
            if !plan.completed.is_empty() {
                let _ = print_tx_results(
                    config,
                    "Completed before failure",
                    &plan.completed,
                    fee,
                    json,
                );
            }
            anyhow::anyhow!("{}", plan.cause())
        }
        Error::DepositBelowMinimum { minimum } => token_amount(pool, decimals, *minimum)
            .map_or_else(
                |_| anyhow::anyhow!("{error}"),
                |minimum| {
                    anyhow::anyhow!("deposit is below the pool minimum of {minimum} after the fee")
                },
            ),
        _ => anyhow::anyhow!("{error}"),
    }
}

fn print_tx_results(
    config: &CliConfig,
    title: &str,
    results: &[TransactionResult],
    fee: Option<&PoolFee>,
    json: bool,
) -> Result<()> {
    if json {
        let rows: Vec<Row<'_>> = results.iter().map(|result| Row { result, fee }).collect();
        return output::emit(&rows, true);
    }
    let explorer = config
        .open_storage()
        .and_then(|s| crate::explorer::base_url(&s, &config.deployment))
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
        if let Some(fee) = fee {
            output::print_kv("pool_fee", &fee.pool_fee);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_json_row_carries_the_fee_only_when_known() {
        let result = TransactionResult {
            tx_hash: "abc".into(),
        };
        let fee = PoolFee {
            pool_fee: "0.1 XLM".into(),
            pool_fee_base_units: NoteAmount::from(1_000_000u128),
        };
        let row = serde_json::to_value(Row {
            result: &result,
            fee: Some(&fee),
        })
        .expect("JSON");
        assert_eq!(row["txHash"], "abc");
        assert_eq!(row["poolFee"], "0.1 XLM");
        assert_eq!(row["poolFeeBaseUnits"], "1000000");
        let row = serde_json::to_value(Row {
            result: &result,
            fee: None,
        })
        .expect("JSON");
        assert_eq!(row, serde_json::json!({ "txHash": "abc" }));
    }
}
