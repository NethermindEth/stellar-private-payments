//! Account identity resolved from a `stellar keys` alias.
//!
//! Replaces the old plaintext `--secret`/`--mnemonic` handling: the account is
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

/// Resolve `--source-account` (an alias) to an [`Account`], or `None` when no
/// account was supplied.
pub fn resolve_account(
    source_account: Option<&str>,
    config_dir: Option<&Path>,
) -> Result<Option<Account>> {
    let Some(alias) = source_account else {
        return Ok(None);
    };
    stellar_cli::validate_alias(alias)?;
    let address = stellar_cli::public_key(alias, config_dir)?;
    Ok(Some(Account {
        alias: alias.to_string(),
        address,
    }))
}
