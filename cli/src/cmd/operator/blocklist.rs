//! `blocklist` — reads for the admin of the non-membership trees.

use anyhow::{Context, Result};
use clap::Subcommand;
use serde::Serialize;
use stellar_private_payments::{
    blocking::BlocklistOperator, operator::blocklist_ids, types::NotePublicKey,
};

use super::{
    AdminRow,
    lists::{ListAccess, ListKind, resolve_tree},
    print_admin, rpc_url, selected_ids,
    write::{AdminCommands, WriteArgs, deliver},
};
use crate::{config::CliConfig, output};

#[derive(Debug, Subcommand)]
pub enum BlocklistCommands {
    /// Root and admin of each non-membership tree
    Show {
        /// Non-membership tree contract id (C…); omit for every tree
        #[arg(long)]
        tree: Option<String>,
    },
    /// Block note public keys, as the tree's admin
    Add {
        /// Note public keys (hex), as users share them from `spp keys`
        #[arg(required = true)]
        note_keys: Vec<String>,
        /// Non-membership tree contract id (C…); default: the blocklist the
        /// enabled pools use
        #[arg(long)]
        tree: Option<String>,
        #[command(flatten)]
        write: WriteArgs,
    },
    /// Unblock a note public key, as the tree's admin
    Remove {
        /// Note public key (hex)
        note_key: String,
        /// Non-membership tree contract id (C…); default: the blocklist the
        /// enabled pools use
        #[arg(long)]
        tree: Option<String>,
        #[command(flatten)]
        write: WriteArgs,
    },
    /// Hand a non-membership tree to a new admin
    Admin {
        /// Non-membership tree contract id (C…); default: the blocklist the
        /// enabled pools use
        #[arg(long)]
        tree: Option<String>,
        #[command(subcommand)]
        command: AdminCommands,
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
        BlocklistCommands::Add {
            note_keys,
            tree,
            write,
        } => {
            let keys = note_keys
                .iter()
                .map(|key| {
                    NotePublicKey::parse(key).with_context(|| format!("parse note key {key}"))
                })
                .collect::<Result<Vec<_>>>()?;
            let network = config.resolve_network()?;
            let access = ListAccess::Write { yes: write.yes };
            let built =
                open(config, &network.rpc_url, tree.as_deref(), access)?.insert_keys(&keys)?;
            deliver(config, &network, built, &write, json)
        }
        BlocklistCommands::Remove {
            note_key,
            tree,
            write,
        } => {
            let key = NotePublicKey::parse(&note_key).context("parse note key")?;
            let network = config.resolve_network()?;
            let access = ListAccess::Write { yes: write.yes };
            let built =
                open(config, &network.rpc_url, tree.as_deref(), access)?.delete_key(&key)?;
            deliver(config, &network, built, &write, json)
        }
        BlocklistCommands::Admin { tree, command } => {
            let network = config.resolve_network()?;
            let operator = open(config, &network.rpc_url, tree.as_deref(), ListAccess::Admin)?;
            let built = match &command {
                AdminCommands::Propose { new_admin, .. } => operator.propose_admin(new_admin)?,
                AdminCommands::Cancel { .. } => operator.cancel_admin_transfer()?,
                AdminCommands::Accept { .. } => operator.accept_admin()?,
            };
            deliver(config, &network, built, command.write(), json)
        }
    }
}

fn open(
    config: &CliConfig,
    rpc_url: &str,
    tree: Option<&str>,
    access: ListAccess,
) -> Result<BlocklistOperator> {
    let tree = resolve_tree(config, rpc_url, ListKind::Blocklist, tree, access)?;
    Ok(BlocklistOperator::open(
        rpc_url,
        config.deployment.clone(),
        &tree,
    )?)
}

fn show(config: &CliConfig, tree: Option<&str>, json: bool) -> Result<()> {
    let rpc_url = rpc_url(config)?;
    let rows: Vec<TreeRow> = selected_ids(blocklist_ids(&config.deployment), tree)
        .into_iter()
        .map(|contract_id| {
            let read = BlocklistOperator::open(&rpc_url, config.deployment.clone(), &contract_id)
                .and_then(|operator| Ok((operator.state()?, operator.pending_admin()?)));
            match read {
                Ok((state, pending_admin)) => TreeRow {
                    contract_id,
                    root: Some(state.root.to_string()),
                    is_empty: Some(state.is_empty),
                    admin: Some(AdminRow {
                        admin: state.admin,
                        pending_admin,
                    }),
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
