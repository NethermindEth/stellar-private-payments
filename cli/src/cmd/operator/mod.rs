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

use std::io::{BufRead, IsTerminal, Write};

use anyhow::{Context, Result, bail};
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

/// Proceeds past `warning` with `--yes`, or once the user agrees on a
/// terminal.
fn confirm(warning: &str, yes: bool) -> Result<()> {
    if yes {
        eprintln!("warning: {warning}");
        return Ok(());
    }
    ask(
        &format!("{warning}. Continue?"),
        &format!("{warning}; pass --yes to continue"),
    )
}

/// Asks `question` on a terminal, and fails with `without_terminal` when
/// there is none to ask on.
fn ask(question: &str, without_terminal: &str) -> Result<()> {
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        bail!("{without_terminal}");
    }
    eprint!("{question} [y/N] ");
    std::io::stderr().flush().ok();
    let mut answer = String::new();
    stdin
        .lock()
        .read_line(&mut answer)
        .context("read from stdin")?;
    if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
        bail!("cancelled");
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirm_passes_with_yes() {
        confirm("a warning", true).expect("--yes continues");
    }
}
