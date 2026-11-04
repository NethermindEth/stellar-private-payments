//! `pool-admin` — reads for the admin of the pools.

use anyhow::Result;
use clap::Subcommand;
use serde::Serialize;
use stellar_private_payments::{blocking::PoolAdmin, operator::pool_ids};

use super::{AdminRow, print_admin, rpc_url, selected_ids};
use crate::{config::CliConfig, output};

#[derive(Debug, Subcommand)]
pub enum PoolAdminCommands {
    /// Admin and pending admin of each pool
    Show {
        /// Pool contract id (C…); omit for every pool
        #[arg(long)]
        pool: Option<String>,
    },
}

#[derive(Serialize)]
struct PoolRow {
    contract_id: String,
    #[serde(flatten)]
    admin: Option<AdminRow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

pub fn run(config: &CliConfig, command: PoolAdminCommands, json: bool) -> Result<()> {
    match command {
        PoolAdminCommands::Show { pool } => show(config, pool.as_deref(), json),
    }
}

fn show(config: &CliConfig, pool: Option<&str>, json: bool) -> Result<()> {
    let rpc_url = rpc_url(config)?;
    let rows: Vec<PoolRow> = selected_ids(pool_ids(&config.deployment), pool)
        .into_iter()
        .map(|contract_id| {
            match PoolAdmin::open(&rpc_url, config.deployment.clone(), &contract_id)
                .and_then(|admin| admin.admin())
            {
                Ok(admin) => PoolRow {
                    contract_id,
                    admin: Some(admin.into()),
                    error: None,
                },
                Err(e) => PoolRow {
                    contract_id,
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
        output::print_section(&format!("Pool {}", row.contract_id));
        if let Some(error) = &row.error {
            output::print_kv("  error", error);
        }
        if let Some(admin) = &row.admin {
            print_admin(admin);
        }
    }
    Ok(())
}
