use anyhow::Result;
use stellar_private_payments::types::{Sensitive, correlation_id_or_new};

use super::{map_pool_err, open_pool, print_tx_results};
use crate::{config::CliConfig, session::parse_amount};

#[tracing::instrument(
    name = "cmd_withdraw",
    skip_all,
    fields(correlation_id = %correlation_id_or_new(), amount = ?Sensitive(&amount), recipient = ?Sensitive(&to))
)]
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
        .map_err(|e| map_pool_err(config, e, json))?;
    print_tx_results(config, "Withdraw submitted", &results, json)
}
