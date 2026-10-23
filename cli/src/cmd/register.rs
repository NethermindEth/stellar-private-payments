//! Register the account's note + encryption public keys in the on-chain
//! address book (public key registry), so others can transfer to the account
//! by its Stellar address.

use anyhow::Result;
use serde::Serialize;

use crate::{config::CliConfig, onboard, output, session::ClientSession};

#[tracing::instrument(
    name = "cmd_register",
    skip_all,
    fields(correlation_id = %stellar_private_payments::types::correlation_id_or_new())
)]
pub fn run(config: &CliConfig, json: bool) -> Result<()> {
    let account = config.require_account()?;
    onboard::ensure_ready(config, &account)?;
    let network = config.resolve_network()?;

    let hash = register_account(config, &account, &network)?;

    #[derive(Serialize)]
    struct RegisterOut<'a> {
        account: &'a str,
        tx_hash: &'a str,
    }
    let payload = RegisterOut {
        account: &account.address,
        tx_hash: &hash,
    };
    if json {
        return output::emit(&payload, true);
    }
    output::print_section("Public keys registered");
    output::print_kv("account", payload.account);
    output::print_kv("tx_hash", payload.tx_hash);
    Ok(())
}

/// Register the account's privacy keys on-chain. Returns the transaction hash.
/// Registration is write-once on-chain: the same keys again change nothing,
/// and different keys are refused, so no local pre-check is required.
pub fn register_account(
    config: &CliConfig,
    account: &crate::account::Account,
    network: &crate::stellar_cli::StellarNetwork,
) -> Result<String> {
    log::info!(
        "Preparing address registration for {}",
        stellar_private_payments::types::Sensitive(&account.address)
    );
    let result =
        ClientSession::new_registration(config, account, network)?.register_public_keys()?;
    log::info!("Registration confirmed: {}", result.tx_hash);
    Ok(result.tx_hash)
}
