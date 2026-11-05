//! `pool-admin` — reads and admin calls for the admin of the pools.

use anyhow::{Result, bail};
use clap::{ArgGroup, Subcommand};
use serde::Serialize;
use stellar_private_payments::{
    blocking::{AllowlistOperator, BlocklistOperator, PoolAdmin},
    operator::{PoolLists, allowlist_ids, pool_ids},
};

use super::{
    AdminRow,
    lists::{ListKind, confirm},
    print_admin, rpc_url, selected_ids, warn_unlisted,
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
            let (kind, tree) = match (allowlist, blocklist) {
                (Some(tree), _) => (ListKind::Allowlist, tree),
                (None, Some(tree)) => (ListKind::Blocklist, tree),
                (None, None) => unreachable!("clap requires --allowlist or --blocklist"),
            };
            check_repoint(config, &network.rpc_url, &admin, kind, &tree, write.yes)?;
            let built = match kind {
                ListKind::Allowlist => admin.repoint_allowlist(&tree)?,
                ListKind::Blocklist => admin.repoint_blocklist(&tree)?,
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

/// Runs the admin page's re-point checks, except the entry comparison. The
/// pool itself checks only the tree's code.
fn check_repoint(
    config: &CliConfig,
    rpc_url: &str,
    admin: &PoolAdmin,
    kind: ListKind,
    tree: &str,
    yes: bool,
) -> Result<()> {
    let lists = admin.lists()?;
    let listed = allowlist_ids(&config.deployment)
        .iter()
        .any(|id| id == tree);
    if !repoint_changes_users(kind, &lists, tree, listed)? {
        eprintln!(
            "note: the pool's policy doesn't use its {}, so this changes nothing for users",
            kind.name()
        );
        return Ok(());
    }
    let pool_admin = admin.admin()?.admin;
    let tree_admin = match kind {
        ListKind::Allowlist => {
            let open = |id: &str| AllowlistOperator::open(rpc_url, config.deployment.clone(), id);
            let new = open(tree)?.state()?;
            let current = open(&lists.allowlist)?.state()?;
            check_levels(tree, new.levels, current.levels)?;
            new.admin
        }
        ListKind::Blocklist => {
            BlocklistOperator::open(rpc_url, config.deployment.clone(), tree)?
                .state()?
                .admin
        }
    };
    if tree_admin != pool_admin {
        confirm(
            &format!(
                "{} {tree} is run by {tree_admin}, not the pool's admin {pool_admin}",
                kind.name()
            ),
            yes,
        )?;
    }
    eprintln!(
        "note: entries are not compared; check them on the admin page or against your records"
    );
    Ok(())
}

/// Whether pointing the pool at `tree` changes what its users prove against.
/// Refuses the tree the pool already uses, and an allowlist the deployment
/// config doesn't list, which clients would refuse.
fn repoint_changes_users(
    kind: ListKind,
    lists: &PoolLists,
    tree: &str,
    listed: bool,
) -> Result<bool> {
    let name = kind.name();
    if kind.tree(lists) == tree {
        bail!("the pool already uses {name} {tree}");
    }
    if !kind.is_used(lists) {
        return Ok(false);
    }
    if kind == ListKind::Allowlist && !listed {
        bail!(
            "the deployment config doesn't list allowlist {tree}, so clients would refuse the \
             pool; add it to added_asp_memberships in deployments.json first"
        );
    }
    Ok(true)
}

fn check_levels(tree: &str, levels: u32, needed: u32) -> Result<()> {
    if levels != needed {
        bail!(
            "allowlist {tree} has {levels} levels, but the pool needs {needed}; use an allowlist \
             built with {needed} levels"
        );
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use stellar_private_payments::types::PolicyFlags;

    use super::*;

    fn lists(policy_flags: PolicyFlags) -> PoolLists {
        PoolLists {
            allowlist: "A-old".to_string(),
            blocklist: "B-old".to_string(),
            policy_flags,
        }
    }

    #[test]
    fn a_repoint_to_the_current_tree_is_refused() {
        let lists = lists(PolicyFlags::ALLOWLIST);
        let err = repoint_changes_users(ListKind::Allowlist, &lists, "A-old", true)
            .expect_err("same tree");
        assert!(err.to_string().contains("already uses"), "{err}");
    }

    #[test]
    fn an_unlisted_allowlist_is_refused_only_when_the_pool_uses_it() {
        let used = lists(PolicyFlags::ALLOWLIST);
        let err = repoint_changes_users(ListKind::Allowlist, &used, "A-new", false)
            .expect_err("unlisted");
        assert!(err.to_string().contains("added_asp_memberships"), "{err}");
        assert!(repoint_changes_users(ListKind::Allowlist, &used, "A-new", true).expect("listed"));

        let unused = lists(PolicyFlags::BLOCKLIST);
        assert!(
            !repoint_changes_users(ListKind::Allowlist, &unused, "A-new", false)
                .expect("unused allowlist")
        );
    }

    #[test]
    fn a_blocklist_needs_no_listing() {
        let lists = lists(PolicyFlags::BLOCKLIST);
        assert!(
            repoint_changes_users(ListKind::Blocklist, &lists, "B-new", false).expect("blocklist")
        );
    }

    #[test]
    fn an_allowlist_of_other_levels_is_refused() {
        check_levels("A-new", 10, 10).expect("same levels");
        let err = check_levels("A-new", 20, 10).expect_err("other levels");
        assert!(err.to_string().contains("needs 10"), "{err}");
    }
}
