use anyhow::Result;
use stellar_private_payments::types::{Sensitive, correlation_id_or_new};

use super::{map_pool_err, open_pool, print_tx_results};
use crate::{
    config::CliConfig,
    session::{parse_amount, parse_transfer_recipient},
};

#[tracing::instrument(
    name = "cmd_transfer",
    skip_all,
    fields(correlation_id = %correlation_id_or_new(), amount = ?Sensitive(&amount), recipient = ?Sensitive(&to))
)]
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
        .map_err(|e| map_pool_err(config, e, json))?;
    print_tx_results(config, "Transfer submitted", &results, json)
}
