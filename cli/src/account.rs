//! Account identity resolved from a `stellar keys` alias.
//!
//! The account is
//! named by an alias and resolved to an address through the Stellar CLI. The
//! secret is never read here — only at transaction-signing time (see
//! [`crate::signer::AliasSigner`]).

use std::path::Path;

use anyhow::Result;

use crate::stellar_cli;

/// A signing account backed by a Stellar CLI alias.
///
/// The alias fully identifies the account (the Stellar CLI stores each identity
/// with its own derivation), so no HD path is threaded here.
#[derive(Debug, Clone)]
pub struct Account {
    /// `stellar keys` alias name.
    pub alias: String,
    /// Resolved Stellar address (`G…`).
    pub address: String,
}

/// Resolve a `--source-account` alias to an [`Account`] via the Stellar CLI.
pub fn resolve(alias: &str, config_dir: Option<&Path>) -> Result<Account> {
    stellar_cli::validate_alias(alias)?;
    let address = stellar_cli::public_key(alias, config_dir)?;
    Ok(Account {
        alias: alias.to_string(),
        address,
    })
}
