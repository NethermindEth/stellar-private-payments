//! Operator commands, one group per administered contract kind.
//!
//! The allowlist, blocklist and pool admin reads need only the network and the
//! deployment, so they unlock no local storage.

pub mod allowlist;
pub mod blocklist;
pub mod gvk;
pub mod pool_admin;

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
