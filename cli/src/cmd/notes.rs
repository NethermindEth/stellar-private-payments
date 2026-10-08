//! `notes` — owned notes from the local wallet database, filterable by pool
//! and spent status.

use anyhow::Result;
use serde::Serialize;
use stellar_private_payments::types::UserNoteSummary;

use crate::{
    cmd::overview,
    config::{CliConfig, validate_pool},
    explorer::Explorer,
    onboard, output,
    session::ClientSession,
};

/// Symbol used when a note's pool is absent from the deployment config
const UNKNOWN_ASSET: &str = "tokens";

/// Which notes to show, from the `--spent` / `--unspent` flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotesStatus {
    All,
    Spent,
    Unspent,
}

impl NotesStatus {
    pub fn from_flags(spent: bool, unspent: bool) -> Self {
        match (spent, unspent) {
            (true, false) => Self::Spent,
            (false, true) => Self::Unspent,
            _ => Self::All,
        }
    }

    fn matches(self, spent: bool) -> bool {
        match self {
            Self::All => true,
            Self::Spent => spent,
            Self::Unspent => !spent,
        }
    }

    fn heading(self) -> &'static str {
        match self {
            Self::All => "Notes",
            Self::Spent => "Spent notes",
            Self::Unspent => "Unspent notes",
        }
    }
}

#[derive(Serialize)]
struct NoteRow {
    commitment: String,
    pool_contract_id: String,
    pool_link: String,
    asset: String,
    amount: String,
    amount_base_units: String,
    decimals: Option<u32>,
    spent: bool,
    leaf_index: u32,
    created_at_ledger: u32,
    ledger_link: String,
}

#[derive(Serialize)]
struct NotesReport {
    account: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pool_contract_id: Option<String>,
    total: usize,
    unspent: usize,
    spent: usize,
    shown: usize,
    notes: Vec<NoteRow>,
}

struct Amount {
    total: usize,
    unspent: usize,
    spent: usize,
}

fn select(
    mut notes: Vec<UserNoteSummary>,
    pool: Option<&str>,
    status: NotesStatus,
    limit: Option<u32>,
) -> (Amount, Vec<UserNoteSummary>) {
    if let Some(pool) = pool {
        notes.retain(|note| note.pool_contract_id == pool);
    }

    let total = notes.len();
    let spent = notes.iter().filter(|note| note.spent).count();
    let unspent = total.saturating_sub(spent);

    let totals = Amount {
        total,
        unspent,
        spent,
    };

    notes.retain(|note| status.matches(note.spent));
    if let Some(limit) = limit {
        notes.truncate(limit as usize);
    }
    (totals, notes)
}

#[tracing::instrument(
    name = "cmd_notes",
    skip_all,
    fields(
        correlation_id = %stellar_private_payments::types::correlation_id_or_new(),
        status = ?status,
        limit = ?limit,
    )
)]
pub fn run(
    config: &CliConfig,
    pool: Option<&str>,
    status: NotesStatus,
    limit: Option<u32>,
    json: bool,
) -> Result<()> {
    let account = config.require_account()?;
    onboard::ensure_ready(config, &account)?;
    if let Some(pool) = pool {
        validate_pool(pool, &config.deployment)?;
    }
    let network = config.resolve_network()?;
    let session = ClientSession::new(config, &account, &network, true)?;

    let notes = session
        .account()
        .user_notes(u32::MAX)
        .map_err(|e| anyhow::anyhow!("list notes: {e}"))?;
    let (totals, notes) = select(notes, pool, status, limit);

    let storage = config.open_storage()?;
    let explorer = Explorer::new(crate::explorer::base_url(&storage, &config.deployment)?);

    let decimals = session.token_decimals(
        notes
            .iter()
            .filter(|note| config.deployment.pool(&note.pool_contract_id).is_ok())
            .map(|note| note.pool_contract_id.as_str()),
    );
    let rows = note_rows(notes, &config.deployment, &explorer, &decimals);

    let report = NotesReport {
        account: account.address.clone(),
        pool_contract_id: pool.map(str::to_string),
        total: totals.total,
        unspent: totals.unspent,
        spent: totals.spent,
        shown: rows.len(),
        notes: rows,
    };

    if json {
        return output::emit(&report, true);
    }
    print(&report, status);
    Ok(())
}

fn print(report: &NotesReport, status: NotesStatus) {
    output::print_section(status.heading());
    if report.notes.is_empty() {
        println!("(none)");
    }
    for row in &report.notes {
        output::print_kv("commitment", &row.commitment);
        output::print_kv(
            "  pool",
            format!("{} → {}", row.pool_contract_id, row.pool_link),
        );
        output::print_kv("  amount", &row.amount);
        output::print_kv("  status", if row.spent { "spent" } else { "unspent" });
        output::print_kv("  leaf_index", row.leaf_index);
        output::print_kv(
            "  ledger",
            format!("{} → {}", row.created_at_ledger, row.ledger_link),
        );
        println!();
    }

    output::print_section("Summary");
    if let Some(pool) = &report.pool_contract_id {
        output::print_kv("pool", pool);
    }
    output::print_kv(
        "notes",
        format!(
            "{} total ({} unspent, {} spent)",
            report.total, report.unspent, report.spent
        ),
    );
    if report.shown != report.total {
        output::print_kv("shown", report.shown);
    }
}

fn note_rows(
    notes: Vec<UserNoteSummary>,
    deployment: &stellar_private_payments::types::ContractConfig,
    explorer: &Explorer,
    decimals: &std::collections::HashMap<String, Result<u32>>,
) -> Vec<NoteRow> {
    for (pool, result) in decimals {
        if let Err(error) = result {
            log::warn!("Token precision unavailable for {pool}; displaying base units: {error:#}");
        }
    }
    notes
        .into_iter()
        .map(|note| {
            let symbol = deployment
                .pool(&note.pool_contract_id)
                .map_or(UNKNOWN_ASSET.to_string(), |e| {
                    overview::asset_symbol(&e.asset)
                });
            let precision = decimals
                .get(&note.pool_contract_id)
                .and_then(|value| value.as_ref().ok())
                .copied();
            NoteRow {
                commitment: note.id.to_string(),
                pool_link: explorer.contract(&note.pool_contract_id),
                asset: symbol.to_string(),
                amount: output::format_token_amount(
                    u128::from(note.amount),
                    symbol.as_str(),
                    precision,
                ),
                amount_base_units: note.amount.to_string(),
                decimals: precision,
                pool_contract_id: note.pool_contract_id,
                spent: note.spent,
                leaf_index: note.leaf_index,
                created_at_ledger: note.created_at_ledger,
                ledger_link: explorer.ledger(note.created_at_ledger),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_private_payments::types::{Field, NoteAmount};

    #[test]
    fn metadata_failure_preserves_note_and_exact_json_amount() {
        let deployment = serde_json::from_value(serde_json::json!({
            "network": "testnet", "deployer": "", "admin": "", "pools": [], "asp_membership": "", "asp_non_membership": "", "public_key_registry": "", "verifiers": {}
        })).expect("deployment");
        let rows = note_rows(
            vec![UserNoteSummary {
                id: Field::ZERO,
                pool_contract_id: "pool".into(),
                amount: NoteAmount::from(9_007_199_254_740_993u128),
                leaf_index: 1,
                created_at_ledger: 2,
                spent: false,
                gvk_ciphertext: None,
            }],
            &deployment,
            &Explorer::new("https://example.test"),
            &[("pool".into(), Err(anyhow::anyhow!("offline")))].into(),
        );
        let row = serde_json::to_value(&rows[0]).expect("JSON");
        assert_eq!(rows.len(), 1);
        assert_eq!(row["amount"], "9007199254740993 base units");
        assert_eq!(row["amount_base_units"], "9007199254740993");
        assert!(row["decimals"].is_null());
    }
}
