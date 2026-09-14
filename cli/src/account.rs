//! Account identity resolved from a `stellar keys` alias.
//!
//! The account is
//! named by an alias and resolved to an address through the Stellar CLI.
//! Transaction signing is delegated to `stellar tx sign` via
//! [`crate::signer::AliasSigner`].
//!
//! One of these stands behind each of the two roles a session holds: the owner
//! that the notes belong to (`--account`) and the payer that sources and signs
//! every envelope (`--sign-as`, defaulting to the owner).

use std::path::Path;

use anyhow::Result;

use crate::stellar_cli;

/// An account backed by a Stellar CLI alias, in either the owner or the payer
/// role.
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

/// Resolve an alias to an [`Account`] via the Stellar CLI.
///
/// `flag` is the option the alias came from (`--account`, `--sign-as`), so a
/// value that is not an alias is reported against the one the user typed.
pub fn resolve(flag: &str, alias: &str, config_dir: Option<&Path>) -> Result<Account> {
    stellar_cli::validate_alias(flag, alias)?;
    let address = stellar_cli::public_key(alias, config_dir)?;
    Ok(Account {
        alias: alias.to_string(),
        address,
    })
}
