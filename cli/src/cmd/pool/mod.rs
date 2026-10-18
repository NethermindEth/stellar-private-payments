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
    planner::PlanError,
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

impl PoolFee {
    /// Reports whether the pool charges no fee.
    fn is_zero(&self) -> bool {
        self.pool_fee_base_units == NoteAmount::ZERO
    }

    /// Returns `clause` built from this fee, or nothing for a zero fee.
    fn clause(&self, clause: impl FnOnce(&str) -> String) -> String {
        if self.is_zero() {
            String::new()
        } else {
            clause(&self.pool_fee)
        }
    }
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
    fee: &'a PoolFee,
}

fn map_pool_err(
    config: &CliConfig,
    pool: &PrivatePool,
    decimals: u32,
    fee: &PoolFee,
    fee_included: bool,
    error: Error,
    json: bool,
) -> anyhow::Error {
    if let Error::PlanExecution(plan) = &error
        && !plan.completed.is_empty()
    {
        let _ = print_tx_results(
            config,
            "Completed before failure",
            &plan.completed,
            fee,
            json,
        );
    }
    error_message(&error, fee, fee_included, |amount| {
        token_amount(pool, decimals, amount).ok()
    })
}

/// Describes why a pool command failed, formatting amounts with `amount`. A
/// refused deposit names the smallest or largest deposit, as the fee comes on
/// top, unless `fee_included` says the amount holds the fee, as for
/// `spp transact --deposit`. A failed spend names the fee per transaction.
fn error_message(
    error: &Error,
    fee: &PoolFee,
    fee_included: bool,
    amount: impl Fn(NoteAmount) -> Option<String>,
) -> anyhow::Error {
    let cause = error.root_cause();
    let message = match cause {
        Error::DepositBelowMinimum { minimum } => amount(*minimum).map(|minimum| {
            if !fee_included {
                format!(
                    "the smallest deposit is {minimum}{}",
                    fee.clause(|fee| format!("; the {fee} pool fee is added on top"))
                )
            } else if fee.is_zero() {
                format!("--deposit must be at least {minimum}")
            } else {
                format!(
                    "--deposit must leave at least {minimum} after the {} pool fee",
                    fee.pool_fee
                )
            }
        }),
        Error::DepositAboveMaximum {
            maximum,
            largest_deposit,
        } => {
            if fee_included {
                NoteAmount::try_from(*maximum)
                    .ok()
                    .and_then(&amount)
                    .map(|maximum| {
                        format!(
                            "--deposit can be at most {maximum}{}",
                            fee.clause(|_| ", pool fee included".to_owned())
                        )
                    })
            } else {
                amount(*largest_deposit).map(|largest| {
                    format!(
                        "the largest deposit is {largest}{}",
                        fee.clause(|fee| format!("; the {fee} pool fee is added on top"))
                    )
                })
            }
        }
        _ if matches!(cause.plan_error(), Some(PlanError::NoSpendableNotes))
            || (cause.max_spend() == Some(NoteAmount::ZERO) && fee.is_zero()) =>
        {
            Some("you have nothing to send; deposit first".to_owned())
        }
        _ => cause.max_spend().and_then(|max_spend| {
            if max_spend == NoteAmount::ZERO {
                return Some(format!(
                    "you have nothing to send once the {} pool fee is paid; deposit more first",
                    fee.pool_fee
                ));
            }
            amount(max_spend).map(|max_spend| {
                format!(
                    "you can send at most {max_spend}{}",
                    fee.clause(|fee| format!("; each transaction pays a {fee} pool fee"))
                )
            })
        }),
    };
    message.map_or_else(|| anyhow::anyhow!("{cause}"), anyhow::Error::msg)
}

fn print_tx_results(
    config: &CliConfig,
    title: &str,
    results: &[TransactionResult],
    fee: &PoolFee,
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
        output::print_kv("pool_fee", &fee.pool_fee);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use stellar_private_payments::{
        PlanExecutionError, planner::SpendSessionError, types::ExtAmount,
    };

    use super::*;

    fn fee(display: &str, base_units: u128) -> PoolFee {
        PoolFee {
            pool_fee: display.into(),
            pool_fee_base_units: NoteAmount::from(base_units),
        }
    }

    fn xlm(amount: NoteAmount) -> Option<String> {
        Some(output::format_token_amount(amount.into(), "XLM", Some(7)))
    }

    #[test]
    fn a_json_row_carries_the_fee() {
        let result = TransactionResult {
            tx_hash: "abc".into(),
        };
        let row = serde_json::to_value(Row {
            result: &result,
            fee: &fee("0.1 XLM", 1_000_000),
        })
        .expect("JSON");
        assert_eq!(row["txHash"], "abc");
        assert_eq!(row["poolFee"], "0.1 XLM");
        assert_eq!(row["poolFeeBaseUnits"], "1000000");
    }

    /// `spp deposit` adds the fee on top; `spp transact` counts it in.
    #[test]
    fn a_deposit_below_the_minimum_names_the_smallest_deposit() {
        let error = Error::DepositBelowMinimum {
            minimum: NoteAmount::from(10_000u128),
        };
        for (fee_included, with_fee, no_fee) in [
            (
                false,
                "the smallest deposit is 0.001 XLM; the 0.0001 XLM pool fee is added on top",
                "the smallest deposit is 0.001 XLM",
            ),
            (
                true,
                "--deposit must leave at least 0.001 XLM after the 0.0001 XLM pool fee",
                "--deposit must be at least 0.001 XLM",
            ),
        ] {
            assert_eq!(
                error_message(&error, &fee("0.0001 XLM", 1_000), fee_included, xlm).to_string(),
                with_fee
            );
            assert_eq!(
                error_message(&error, &fee("0 XLM", 0), fee_included, xlm).to_string(),
                no_fee
            );
        }
    }

    #[test]
    fn an_over_cap_deposit_names_the_largest_deposit() {
        let error = Error::DepositAboveMaximum {
            maximum: ExtAmount::from(1_000_000_000),
            largest_deposit: NoteAmount::from(999_000_000u128),
        };
        let tenth = fee("0.1 XLM", 1_000_000);
        assert_eq!(
            error_message(&error, &tenth, false, xlm).to_string(),
            "the largest deposit is 99.9 XLM; the 0.1 XLM pool fee is added on top"
        );
        assert_eq!(
            error_message(&error, &tenth, true, xlm).to_string(),
            "--deposit can be at most 100 XLM, pool fee included"
        );
        let no_fee = Error::DepositAboveMaximum {
            maximum: ExtAmount::from(1_000_000_000),
            largest_deposit: NoteAmount::from(1_000_000_000u128),
        };
        let zero = fee("0 XLM", 0);
        assert_eq!(
            error_message(&no_fee, &zero, false, xlm).to_string(),
            "the largest deposit is 100 XLM"
        );
        assert_eq!(
            error_message(&no_fee, &zero, true, xlm).to_string(),
            "--deposit can be at most 100 XLM"
        );
    }

    /// An estimate fails bare, a spend through its session, and a later step
    /// under the steps already confirmed.
    #[test]
    fn a_spend_above_max_spend_names_it() {
        let no_combination = || PlanError::NoCombination {
            max_spend: NoteAmount::from(99_000u128),
        };
        let completed = vec![TransactionResult {
            tx_hash: "abc".into(),
        }];
        for error in [
            Error::Plan(no_combination()),
            Error::SpendSession(SpendSessionError::Plan(no_combination())),
            PlanExecutionError::into_error(
                completed,
                Error::SpendSession(SpendSessionError::Plan(no_combination())),
            ),
        ] {
            assert_eq!(
                error_message(&error, &fee("0.0001 XLM", 1_000), false, xlm).to_string(),
                "you can send at most 0.0099 XLM; each transaction pays a 0.0001 XLM pool fee"
            );
            assert_eq!(
                error_message(&error, &fee("0 XLM", 0), false, xlm).to_string(),
                "you can send at most 0.0099 XLM"
            );
        }
    }

    /// An empty wallet can send nothing, bare or through its session, and the
    /// pool fee is not why.
    #[test]
    fn a_spend_from_no_notes_has_nothing_to_send() {
        for error in [
            Error::Plan(PlanError::NoSpendableNotes),
            Error::SpendSession(SpendSessionError::Plan(PlanError::NoSpendableNotes)),
        ] {
            for fee in [fee("0.0001 XLM", 1_000), fee("0 XLM", 0)] {
                assert_eq!(
                    error_message(&error, &fee, false, xlm).to_string(),
                    "you have nothing to send; deposit first"
                );
            }
        }
    }

    #[test]
    fn notes_the_fee_takes_whole_leave_nothing_to_send() {
        let error = Error::Plan(PlanError::NoCombination {
            max_spend: NoteAmount::ZERO,
        });
        assert_eq!(
            error_message(&error, &fee("0.0001 XLM", 1_000), false, xlm).to_string(),
            "you have nothing to send once the 0.0001 XLM pool fee is paid; deposit more first"
        );
        assert_eq!(
            error_message(&error, &fee("0 XLM", 0), false, xlm).to_string(),
            "you have nothing to send; deposit first"
        );
    }

    /// `map_pool_err` prints the steps a plan confirmed, so the message names
    /// only the failure that stopped it.
    #[test]
    fn a_failure_after_a_confirmed_step_reads_as_its_cause() {
        let error = PlanExecutionError::into_error(
            vec![TransactionResult {
                tx_hash: "abc".into(),
            }],
            Error::Other(anyhow::anyhow!("simulate transaction: boom")),
        );
        assert_eq!(
            error_message(&error, &fee("0.0001 XLM", 1_000), false, xlm).to_string(),
            "simulate transaction: boom"
        );
    }
}
