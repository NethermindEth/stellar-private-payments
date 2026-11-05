//! Operator commands, one group per administered contract kind.
//!
//! The allowlist, blocklist and pool admin commands need only the network and
//! the deployment, so they unlock no local storage. Writes are signed with a
//! `stellar keys` alias, or written to a file for multisig signers.

pub mod allowlist;
pub mod blocklist;
pub mod envelope;
pub mod gvk;
mod lists;
pub mod pool_admin;
mod write;

use anyhow::Result;
use serde::Serialize;
use stellar_private_payments::operator::AdminState;

use crate::config::CliConfig;

#[derive(Serialize)]
struct AdminRow {
    admin: String,
    pending_admin: Option<String>,
}

impl From<AdminState> for AdminRow {
    fn from(state: AdminState) -> Self {
        Self {
            admin: state.admin,
            pending_admin: state.pending_admin,
        }
    }
}

/// `selected`, or every id of the kind when none was named.
fn selected_ids(all: Vec<String>, selected: Option<&str>) -> Vec<String> {
    match selected {
        Some(id) => vec![id.to_string()],
        None => all,
    }
}

fn warn_unlisted(listed: bool, kind: &str, contract_id: &str) {
    if !listed {
        eprintln!("warning: {contract_id} is not a {kind} of the deployment config");
    }
}

fn rpc_url(config: &CliConfig) -> Result<String> {
    Ok(config.resolve_network()?.rpc_url)
}

fn print_admin(admin: &AdminRow) {
    crate::output::print_kv("  admin", &admin.admin);
    crate::output::print_kv(
        "  pending_admin",
        admin.pending_admin.as_deref().unwrap_or("none"),
    );
}
