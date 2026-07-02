//! `feed` — latest operational events, mirroring the app dashboard feed.

use anyhow::Result;
use serde::Serialize;

use crate::{config::CliConfig, explorer::Explorer, onboard, output, session::PoolSession};

const DEFAULT_LIMIT: u32 = 5;

pub fn run(config: &CliConfig, limit: Option<u32>, json: bool) -> Result<()> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT);
    let account = config.require_account()?;
    onboard::ensure_ready(config, &account)?;
    let network = config.resolve_network()?;

    // Sync every enabled pool so the local event tables are current.
    for entry in config.deployment.pools.iter().filter(|p| p.enabled) {
        PoolSession::open(
            config,
            &account,
            &network,
            &entry.pool_contract_id,
        )?;
    }

    let storage = config.open_storage()?;
    let explorer = Explorer::new(crate::explorer::base_url(&storage)?);
    let items = storage.get_operational_feed(
        limit,
        &config.deployment.asp_membership,
        &config.deployment.public_key_registry,
    )?;

    #[derive(Serialize)]
    struct FeedRow {
        kind: String,
        title: String,
        body: String,
        ledger: u32,
        ledger_link: String,
    }
    let rows: Vec<FeedRow> = items
        .into_iter()
        .map(|i| FeedRow {
            kind: i.kind,
            title: i.title,
            body: i.body,
            ledger: i.ledger,
            ledger_link: explorer.ledger(i.ledger),
        })
        .collect();

    if json {
        return output::emit(&rows, true);
    }

    output::print_section("Latest activity");
    if rows.is_empty() {
        println!("(none)");
        return Ok(());
    }
    for row in &rows {
        output::print_kv(&row.title, &row.body);
        output::print_kv("  ledger", format!("{} → {}", row.ledger, row.ledger_link));
        println!();
    }
    Ok(())
}
