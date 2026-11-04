//! `pool-admin` — reads and admin calls for the admin of the pools.

use anyhow::Result;
use clap::{ArgGroup, Subcommand};
use serde::Serialize;
use stellar_private_payments::{blocking::PoolAdmin, operator::pool_ids};

use super::{
    AdminRow, print_admin, rpc_url, selected_ids, warn_unlisted,
    write::{AdminCommands, WriteArgs, deliver},
};
use crate::{config::CliConfig, output};

#[derive(Debug, Subcommand)]
pub enum PoolAdminCommands {
    /// Admin and pending admin of each pool
    Show {
        /// Pool contract id (C…); omit for every pool
        #[arg(long)]
        pool: Option<String>,
    },
    /// Point a pool at another membership or non-membership tree
    #[command(group(ArgGroup::new("tree").required(true).args(["allowlist", "blocklist"])))]
    Repoint {
        /// Pool contract id (C…)
        #[arg(long)]
        pool: String,
        /// Membership tree contract id (C…) the pool should read
        #[arg(long)]
        allowlist: Option<String>,
        /// Non-membership tree contract id (C…) the pool should read
        #[arg(long)]
        blocklist: Option<String>,
        #[command(flatten)]
        write: WriteArgs,
    },
    /// Stop deposits into a pool; transfers and withdrawals continue
    Pause {
        /// Pool contract id (C…)
        #[arg(long)]
        pool: String,
        #[command(flatten)]
        write: WriteArgs,
    },
    /// Resume deposits into a pool
    Unpause {
        /// Pool contract id (C…)
        #[arg(long)]
        pool: String,
        #[command(flatten)]
        write: WriteArgs,
    },
    /// Hand a pool to a new admin
    Admin {
        /// Pool contract id (C…)
        #[arg(long)]
        pool: String,
        #[command(subcommand)]
        command: AdminCommands,
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
        PoolAdminCommands::Repoint {
            pool,
            allowlist,
            blocklist,
            write,
        } => {
            let network = config.resolve_network()?;
            let admin = open(config, &network.rpc_url, &pool)?;
            let built = match (allowlist, blocklist) {
                (Some(tree), _) => admin.repoint_allowlist(&tree)?,
                (None, Some(tree)) => admin.repoint_blocklist(&tree)?,
                (None, None) => unreachable!("clap requires --allowlist or --blocklist"),
            };
            deliver(config, &network, built, &write, json)
        }
        PoolAdminCommands::Pause { pool, write } => {
            let network = config.resolve_network()?;
            let admin = open(config, &network.rpc_url, &pool)?;
            deliver(config, &network, admin.pause_deposits()?, &write, json)
        }
        PoolAdminCommands::Unpause { pool, write } => {
            let network = config.resolve_network()?;
            let admin = open(config, &network.rpc_url, &pool)?;
            deliver(config, &network, admin.unpause_deposits()?, &write, json)
        }
        PoolAdminCommands::Admin { pool, command } => {
            let network = config.resolve_network()?;
            let admin = open(config, &network.rpc_url, &pool)?;
            let built = match &command {
                AdminCommands::Propose { new_admin, .. } => admin.propose_admin(new_admin)?,
                AdminCommands::Cancel { .. } => admin.cancel_admin_transfer()?,
                AdminCommands::Accept { .. } => admin.accept_admin()?,
            };
            deliver(config, &network, built, command.write(), json)
        }
    }
}

fn open(config: &CliConfig, rpc_url: &str, pool: &str) -> Result<PoolAdmin> {
    let admin = PoolAdmin::open(rpc_url, config.deployment.clone(), pool)?;
    warn_unlisted(admin.is_listed(), "pool", pool);
    Ok(admin)
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
