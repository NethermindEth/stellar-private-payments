//! `blocklist` — reads for the admin of the non-membership trees.

use anyhow::Result;
use clap::Subcommand;
use serde::Serialize;
use stellar_private_payments::{blocking::BlocklistOperator, operator::blocklist_ids};

use super::{AdminRow, print_admin, rpc_url, selected_ids};
use crate::{config::CliConfig, output};

#[derive(Debug, Subcommand)]
pub enum BlocklistCommands {
    /// Root and admin of each non-membership tree
    Show {
        /// Non-membership tree contract id (C…); omit for every tree
        #[arg(long)]
        tree: Option<String>,
    },
}

#[derive(Serialize)]
struct TreeRow {
    contract_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_empty: Option<bool>,
    #[serde(flatten)]
    admin: Option<AdminRow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

pub fn run(config: &CliConfig, command: BlocklistCommands, json: bool) -> Result<()> {
    match command {
        BlocklistCommands::Show { tree } => show(config, tree.as_deref(), json),
    }
}

fn show(config: &CliConfig, tree: Option<&str>, json: bool) -> Result<()> {
    let rpc_url = rpc_url(config)?;
    let rows: Vec<TreeRow> = selected_ids(blocklist_ids(&config.deployment), tree)
        .into_iter()
        .map(|contract_id| {
            let read = BlocklistOperator::open(&rpc_url, config.deployment.clone(), &contract_id)
                .and_then(|operator| Ok((operator.state()?, operator.admin()?)));
            match read {
                Ok((state, admin)) => TreeRow {
                    contract_id,
                    root: Some(state.root.to_string()),
                    is_empty: Some(state.is_empty),
                    admin: Some(admin.into()),
                    error: None,
                },
                Err(e) => TreeRow {
                    contract_id,
                    root: None,
                    is_empty: None,
                    admin: None,
                    error: Some(e.to_string()),
                },
            }
        })
        .collect();

    if json {
        return output::emit(&rows, true);
    }
    for row in &rows {
        output::print_section(&format!("Blocklist {}", row.contract_id));
        if let Some(error) = &row.error {
            output::print_kv("  error", error);
        }
        if let Some(root) = &row.root {
            output::print_kv("  root", root);
        }
        if let Some(admin) = &row.admin {
            print_admin(admin);
        }
    }
    Ok(())
}
