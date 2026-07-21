//! `keys` — show the account's privacy public keys; `asp-secret` reveals
//! the ASP secret (membership blinding).

use anyhow::Result;
use serde::Serialize;

use crate::{config::CliConfig, onboard, output, session::ClientSession};

pub fn show(config: &CliConfig, json: bool) -> Result<()> {
    // No value fields: this command prints secrets to stdout; logs get nothing.
    let _span = tracing::info_span!(
        "cmd_keys_show",
        correlation_id = %types::correlation_id_or_new()
    )
    .entered();
    let account = config.require_account()?;
    onboard::ensure_ready(config, &account)?;
    let network = config.resolve_network()?;
    let session = ClientSession::new(config, &account, &network, true)?;
    let (note, enc) = session
        .account()
        .user_public_keys()
        .map_err(|e| anyhow::anyhow!("privacy keys: {e}"))?;

    let note = hex0x(&note)?;
    let encryption = hex0x(&enc)?;

    #[derive(Serialize)]
    struct KeysOut<'a> {
        account: &'a str,
        note_public_key: &'a str,
        encryption_public_key: &'a str,
    }
    let payload = KeysOut {
        account: &account.address,
        note_public_key: &note,
        encryption_public_key: &encryption,
    };
    if json {
        return output::emit(&payload, true);
    }
    output::print_section("Public keys");
    output::print_kv("account", payload.account);
    output::print_kv("note_public_key", payload.note_public_key);
    output::print_kv("encryption_public_key", payload.encryption_public_key);
    Ok(())
}

pub fn asp_secret(config: &CliConfig, json: bool) -> Result<()> {
    // No value fields: this command prints secrets to stdout; logs get nothing.
    let _span = tracing::info_span!(
        "cmd_keys_asp_secret",
        correlation_id = %types::correlation_id_or_new()
    )
    .entered();
    let account = config.require_account()?;
    onboard::ensure_ready(config, &account)?;
    let network = config.resolve_network()?;
    let session = ClientSession::new(config, &account, &network, true)?;
    let secret = session
        .account()
        .asp_secret()
        .map_err(|e| anyhow::anyhow!("ASP secret: {e}"))?;
    let secret = secret.to_string();

    eprintln!(
        "WARNING: this is your ASP secret. Anyone who learns it can link your notes. \
         Keep it secret — do not share, paste, or commit it anywhere."
    );

    #[derive(Serialize)]
    struct AspOut<'a> {
        account: &'a str,
        asp_secret: &'a str,
    }
    let payload = AspOut {
        account: &account.address,
        asp_secret: &secret,
    };
    if json {
        return output::emit(&payload, true);
    }
    output::print_section("ASP secret");
    output::print_kv("account", payload.account);
    output::print_kv("asp_secret", payload.asp_secret);
    Ok(())
}

/// Render a key type via its serde `0x…` hex representation.
fn hex0x<T: Serialize>(value: &T) -> Result<String> {
    match serde_json::to_value(value)? {
        serde_json::Value::String(s) => Ok(s),
        other => Ok(other.to_string()),
    }
}
