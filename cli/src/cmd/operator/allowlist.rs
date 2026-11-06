//! `allowlist` — reads for the admin of the membership trees.

use anyhow::{Context, Result};
use clap::Subcommand;
use serde::Serialize;
use std::{
    io::Read,
    path::{Path, PathBuf},
    str::FromStr,
};
use stellar_private_payments::{
    blocking::AllowlistOperator,
    operator::{allowlist_ids, derive_asp_user_leaf},
    types::{Field, NotePublicKey},
};

use super::{
    AdminRow,
    lists::{ListAccess, ListKind, resolve_tree},
    print_admin, rpc_url, selected_ids,
    write::{AdminCommands, WriteArgs, deliver},
};
use crate::{config::CliConfig, output};

#[derive(Debug, Subcommand)]
pub enum AllowlistCommands {
    /// Root, size and admin of each membership tree
    Show {
        /// Membership tree contract id (C…); omit for every tree
        #[arg(long)]
        tree: Option<String>,
    },
    /// Append a leaf to a membership tree, as its admin
    Add {
        /// The leaf (hex), from `spp allowlist leaf`
        #[arg(long)]
        leaf: String,
        /// Membership tree contract id (C…); default: the allowlist the
        /// enabled pools use
        #[arg(long)]
        tree: Option<String>,
        #[command(flatten)]
        write: WriteArgs,
    },
    /// Hand a membership tree to a new admin
    Admin {
        /// Membership tree contract id (C…); default: the allowlist the
        /// enabled pools use
        #[arg(long)]
        tree: Option<String>,
        #[command(subcommand)]
        command: AdminCommands,
    },
    /// Derive a user's allowlist leaf from the keys they shared
    Leaf {
        /// The user's note public key (hex), from `spp keys`
        #[arg(long)]
        note_key: String,
        /// File holding the user's ASP secret (hex), from `spp asp-secret`;
        /// `-` reads it from stdin
        #[arg(long, value_name = "FILE")]
        asp_secret_file: PathBuf,
    },
}

#[derive(Serialize)]
struct TreeRow {
    contract_id: String,
    #[serde(flatten)]
    state: Option<TreeState>,
    #[serde(flatten)]
    admin: Option<AdminRow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct TreeState {
    root: String,
    levels: u32,
    next_index: String,
    capacity: u64,
}

pub fn run(config: &CliConfig, command: AllowlistCommands, json: bool) -> Result<()> {
    match command {
        AllowlistCommands::Show { tree } => show(config, tree.as_deref(), json),
        AllowlistCommands::Leaf {
            note_key,
            asp_secret_file,
        } => leaf(&note_key, &asp_secret_file, json),
        AllowlistCommands::Add { leaf, tree, write } => {
            let leaf = Field::from_str(&leaf).context("parse --leaf")?;
            let network = config.resolve_network()?;
            let access = ListAccess::Write { yes: write.yes };
            let built =
                open(config, &network.rpc_url, tree.as_deref(), access)?.insert_leaf(leaf)?;
            deliver(config, &network, built, &write, json)
        }
        AllowlistCommands::Admin { tree, command } => {
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
) -> Result<AllowlistOperator> {
    let tree = resolve_tree(config, rpc_url, ListKind::Allowlist, tree, access)?;
    Ok(AllowlistOperator::open(
        rpc_url,
        config.deployment.clone(),
        &tree,
    )?)
}

fn show(config: &CliConfig, tree: Option<&str>, json: bool) -> Result<()> {
    let rpc_url = rpc_url(config)?;
    let rows: Vec<TreeRow> = selected_ids(allowlist_ids(&config.deployment), tree)
        .into_iter()
        .map(|contract_id| {
            let read = AllowlistOperator::open(&rpc_url, config.deployment.clone(), &contract_id)
                .and_then(|operator| Ok((operator.state()?, operator.admin()?)));
            match read {
                Ok((state, admin)) => TreeRow {
                    contract_id,
                    state: Some(TreeState {
                        root: state.root.to_string(),
                        levels: state.levels,
                        next_index: state.next_index,
                        capacity: state.capacity,
                    }),
                    admin: Some(admin.into()),
                    error: None,
                },
                Err(e) => TreeRow {
                    contract_id,
                    state: None,
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
        output::print_section(&format!("Allowlist {}", row.contract_id));
        if let Some(error) = &row.error {
            output::print_kv("  error", error);
        }
        if let Some(state) = &row.state {
            output::print_kv("  root", &state.root);
            output::print_kv("  levels", state.levels);
            output::print_kv(
                "  leaves",
                format!("{} of {}", state.next_index, state.capacity),
            );
        }
        if let Some(admin) = &row.admin {
            print_admin(admin);
        }
    }
    Ok(())
}

fn leaf(note_key: &str, asp_secret_file: &Path, json: bool) -> Result<()> {
    let note = NotePublicKey::parse(note_key).context("parse --note-key")?;
    let mut secret = String::new();
    if asp_secret_file == Path::new("-") {
        std::io::stdin()
            .read_to_string(&mut secret)
            .context("read the ASP secret from stdin")?;
    } else {
        secret = std::fs::read_to_string(asp_secret_file)
            .with_context(|| format!("read {}", asp_secret_file.display()))?;
    }
    let blinding = Field::from_str(secret.trim()).context("parse the ASP secret")?;
    let leaf = derive_asp_user_leaf(&note, &blinding)?.to_string();

    #[derive(Serialize)]
    struct LeafOut {
        leaf: String,
    }
    if json {
        return output::emit(&LeafOut { leaf }, true);
    }
    output::print_kv("leaf", leaf);
    Ok(())
}
