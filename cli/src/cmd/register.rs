//! Register the account's note + encryption public keys in the on-chain
//! address book (public key registry), so others can transfer to the account
//! by its Stellar address.

use anyhow::Result;
use serde::Serialize;

use crate::{config::CliConfig, onboard, output, session::ClientSession};

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
/// Registration is idempotent on-chain (re-registering just updates the stored
/// keys), so no local pre-check is required.
pub fn register_account(
    config: &CliConfig,
    account: &crate::account::Account,
    network: &crate::stellar_cli::StellarNetwork,
) -> Result<String> {
    log::info!("Preparing address registration for {}", account.address);
    let result = ClientSession::new(config, account, network, true)?.register_public_keys()?;
    log::info!("Registration confirmed: {}", result.tx_hash);
    Ok(result.tx_hash)
}
