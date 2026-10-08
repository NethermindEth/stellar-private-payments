use anyhow::Result;
use stellar_private_payments::types::{Sensitive, correlation_id_or_new};

use super::{map_pool_err, open_pool, print_tx_results};
use crate::{config::CliConfig, session::parse_amount};

#[tracing::instrument(
    name = "cmd_deposit",
    skip_all,
    fields(correlation_id = %correlation_id_or_new(), amount = ?Sensitive(&amount))
)]
pub fn deposit(config: &CliConfig, pool: &str, amount: &str, json: bool) -> Result<()> {
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
