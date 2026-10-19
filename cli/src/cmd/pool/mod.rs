//! Core value operations: deposit, transfer, withdraw, and the advanced
//! `transact`. Each takes the pool contract id and requires a ready account.

mod deposit;
pub mod transact;
mod transfer;
mod withdraw;

use anyhow::Result;
use stellar_private_payments::{Error, types::TransactionResult};

pub use self::{deposit::deposit, transfer::transfer, withdraw::withdraw};
use crate::{
    account::Account,
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

fn open_pool(
    config: &CliConfig,
    pool: &str,
) -> Result<stellar_private_payments::blocking::PrivatePool> {
    let (_, session) = open_session(config, pool)?;
    session.pool(pool)
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
    }
    Ok(())
}
