use anyhow::Result;
use stellar_private_payments::types::{NoteAmount, Sensitive, correlation_id_or_new};

use super::{map_pool_err, open_pool, pool_fee, print_tx_results};
use crate::config::CliConfig;

#[tracing::instrument(
    name = "cmd_deposit",
    skip_all,
    fields(correlation_id = %correlation_id_or_new(), amount = ?Sensitive(&amount))
)]
pub fn deposit(config: &CliConfig, pool: &str, amount: &str, json: bool) -> Result<()> {
    let pool = open_pool(config, pool)?;
    let decimals = pool.token_decimals()?;
    let amount = NoteAmount::from_decimal(amount, decimals)?;
    let fee = pool_fee(&pool, decimals)?;
    let result = pool
        .deposit(amount)
        .map_err(|e| map_pool_err(config, &pool, decimals, &fee, false, e, json))?;
    print_tx_results(
        config,
        "Deposit submitted",
        std::slice::from_ref(&result),
        &fee,
        json,
    )
}
