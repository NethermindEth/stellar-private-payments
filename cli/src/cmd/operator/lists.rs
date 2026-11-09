//! The trees the enabled pools use. A re-point changes them without changing
//! the deployment config, so list commands resolve their tree from the pools.

use anyhow::{Context, Result, bail};
use stellar_private_payments::{
    blocking::pool_lists,
    operator::{PoolLists, allowlist_ids},
};

use super::confirm;
use crate::config::CliConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListKind {
    Allowlist,
    Blocklist,
}

impl ListKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Allowlist => "allowlist",
            Self::Blocklist => "blocklist",
        }
    }

    /// The pool's tree of this kind, used by its policy or not.
    pub fn tree(self, lists: &PoolLists) -> &str {
        match self {
            Self::Allowlist => &lists.allowlist,
            Self::Blocklist => &lists.blocklist,
        }
    }

    pub fn is_used(self, lists: &PoolLists) -> bool {
        match self {
            Self::Allowlist => lists.uses_allowlist(),
            Self::Blocklist => lists.uses_blocklist(),
        }
    }
}

/// What a list command does with the tree it resolves.
#[derive(Debug, Clone, Copy)]
pub enum ListAccess {
    /// Changes the tree's entries; asks first when no enabled pool uses it,
    /// or when the pools can't be read.
    Write { yes: bool },
    /// Transfers the tree's admin, which any tree may need. An explicit tree
    /// skips reading the pools.
    Admin,
}

/// A tree and the enabled pools whose policy uses it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub tree: String,
    pub used_by: Vec<String>,
}

/// The tree a list command acts on: `explicit`, else the one tree of `kind`
/// the enabled pools use.
pub fn resolve_tree(
    config: &CliConfig,
    rpc_url: &str,
    kind: ListKind,
    explicit: Option<&str>,
    access: ListAccess,
) -> Result<String> {
    let name = kind.name();
    let pools = match (explicit, access) {
        (Some(tree), ListAccess::Admin) => return Ok(tree.to_string()),
        (Some(tree), ListAccess::Write { yes }) => match enabled_pool_lists(config, rpc_url) {
            Ok(pools) => pools,
            Err(err) => {
                confirm(
                    &format!("can't tell which enabled pools use {name} {tree}: {err:#}"),
                    yes,
                )?;
                return Ok(tree.to_string());
            }
        },
        (None, _) => enabled_pool_lists(config, rpc_url)?,
    };
    let target = target_tree(kind, &pools, explicit)?;
    if explicit.is_none() {
        eprintln!(
            "{name} {}, used by {}",
            target.tree,
            target.used_by.join(", ")
        );
    }
    if target.used_by.is_empty() {
        if let ListAccess::Write { yes } = access {
            confirm(&unused_warning(kind, &target.tree), yes)?;
        }
    } else if kind == ListKind::Allowlist
        && !allowlist_ids(&config.deployment).contains(&target.tree)
    {
        eprintln!(
            "warning: the deployment config doesn't list allowlist {}, so clients refuse the pools \
             that use it until added_asp_memberships names it",
            target.tree
        );
    }
    Ok(target.tree)
}

/// The lists of every enabled pool of the deployment config.
fn enabled_pool_lists(config: &CliConfig, rpc_url: &str) -> Result<Vec<(String, PoolLists)>> {
    let pools: Vec<String> = config
        .deployment
        .pools
        .iter()
        .filter(|pool| pool.enabled)
        .map(|pool| pool.pool_contract_id.clone())
        .collect();
    let lists = pool_lists(rpc_url, &pools).context("read the trees the enabled pools use")?;
    Ok(pools.into_iter().zip(lists).collect())
}

fn target_tree(
    kind: ListKind,
    pools: &[(String, PoolLists)],
    explicit: Option<&str>,
) -> Result<Target> {
    let mut used: Vec<Target> = Vec::new();
    for (pool, lists) in pools.iter().filter(|(_, lists)| kind.is_used(lists)) {
        let tree = kind.tree(lists);
        match used.iter_mut().find(|target| target.tree == tree) {
            Some(target) => target.used_by.push(pool.clone()),
            None => used.push(Target {
                tree: tree.to_string(),
                used_by: vec![pool.clone()],
            }),
        }
    }
    let name = kind.name();
    if let Some(tree) = explicit {
        return Ok(used
            .into_iter()
            .find(|target| target.tree == tree)
            .unwrap_or_else(|| Target {
                tree: tree.to_string(),
                used_by: Vec::new(),
            }));
    }
    match <[Target; 1]>::try_from(used) {
        Ok([target]) => Ok(target),
        Err(used) if used.is_empty() => bail!("no enabled pool uses any {name}; pass --tree"),
        Err(used) => {
            let trees: Vec<String> = used
                .iter()
                .map(|target| format!("{} (used by {})", target.tree, target.used_by.join(", ")))
                .collect();
            bail!(
                "enabled pools use different {name}s: {}; pass --tree",
                trees.join("; ")
            )
        }
    }
}

fn unused_warning(kind: ListKind, tree: &str) -> String {
    match kind {
        ListKind::Allowlist => {
            format!("no enabled pool uses allowlist {tree}, so this member can't use any pool yet")
        }
        ListKind::Blocklist => {
            format!("no enabled pool uses blocklist {tree}, so this change has no effect yet")
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use stellar_private_payments::types::{PolicyFlag, PolicyFlags};

    use super::*;
    use crate::config::CliConfigOverrides;

    /// Refuses connections, so reading the pools fails.
    const UNREACHABLE_RPC: &str = "http://127.0.0.1:9";
    const TREE: &str = "CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE";

    fn config() -> CliConfig {
        CliConfig::load(
            None,
            None,
            CliConfigOverrides {
                deployment_path: Some(
                    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../deployments/testnet"),
                ),
                data_dir: Some(std::env::temp_dir().join("spp-list-tests")),
                ..Default::default()
            },
        )
        .expect("the test deployment should load")
    }

    #[test]
    fn an_explicit_tree_does_not_need_the_pools() {
        let config = config();
        assert!(config.deployment.pools.iter().any(|pool| pool.enabled));
        let admin = resolve_tree(
            &config,
            UNREACHABLE_RPC,
            ListKind::Blocklist,
            Some(TREE),
            ListAccess::Admin,
        );
        assert_eq!(admin.expect("admin"), TREE);
        let write = resolve_tree(
            &config,
            UNREACHABLE_RPC,
            ListKind::Allowlist,
            Some(TREE),
            ListAccess::Write { yes: true },
        );
        assert_eq!(write.expect("write with --yes"), TREE);
    }

    #[test]
    fn the_default_tree_needs_the_pools() {
        let read = resolve_tree(
            &config(),
            UNREACHABLE_RPC,
            ListKind::Blocklist,
            None,
            ListAccess::Admin,
        );
        assert!(read.is_err());
    }

    fn pool(id: &str, allowlist: &str, blocklist: &str, flags: PolicyFlags) -> (String, PoolLists) {
        (
            id.to_string(),
            PoolLists {
                allowlist: allowlist.to_string(),
                blocklist: blocklist.to_string(),
                policy_flags: flags,
            },
        )
    }

    fn target(tree: &str, used_by: &[&str]) -> Target {
        Target {
            tree: tree.to_string(),
            used_by: used_by.iter().map(ToString::to_string).collect(),
        }
    }

    #[test]
    fn the_default_is_the_tree_the_pools_use() {
        let both = PolicyFlags::ALLOWLIST.with(PolicyFlag::Blocklist);
        let pools = [
            pool("P1", "A1", "B-new", both),
            pool("P2", "A2", "B-new", PolicyFlags::BLOCKLIST),
        ];
        assert_eq!(
            target_tree(ListKind::Blocklist, &pools, None).expect("blocklist"),
            target("B-new", &["P1", "P2"])
        );
        // P2's policy leaves its allowlist out.
        assert_eq!(
            target_tree(ListKind::Allowlist, &pools, None).expect("allowlist"),
            target("A1", &["P1"])
        );
    }

    #[test]
    fn no_or_several_used_trees_need_an_explicit_one() {
        let pools = [
            pool("P1", "A", "B1", PolicyFlags::BLOCKLIST),
            pool("P2", "A", "B2", PolicyFlags::BLOCKLIST),
        ];
        let several = target_tree(ListKind::Blocklist, &pools, None).expect_err("several");
        assert!(
            several
                .to_string()
                .contains("B1 (used by P1); B2 (used by P2)"),
            "{several}"
        );
        let none = target_tree(ListKind::Allowlist, &pools, None).expect_err("none");
        assert!(
            none.to_string()
                .contains("no enabled pool uses any allowlist"),
            "{none}"
        );
    }

    #[test]
    fn an_explicit_tree_reports_who_uses_it() {
        let pools = [pool("P1", "A", "B-new", PolicyFlags::BLOCKLIST)];
        assert_eq!(
            target_tree(ListKind::Blocklist, &pools, Some("B-new")).expect("used"),
            target("B-new", &["P1"])
        );
        assert_eq!(
            target_tree(ListKind::Blocklist, &pools, Some("B-old")).expect("unused"),
            target("B-old", &[])
        );
    }
}
