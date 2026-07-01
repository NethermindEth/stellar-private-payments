//! Register the account's note + encryption public keys in the on-chain
//! address book (public key registry), so others can transfer to the account
//! by its Stellar address.

use anyhow::{Context, Result};
use serde::Serialize;
use stellar_private_payments_sdk::{
    Client,
    chain::{LocalSigner, confirm_tx, submit_tx},
    state::SqliteStorage,
};

use crate::{
    account::Account, config::CliConfig, onboard, output, runtime::block_on, stellar_cli,
    stellar_cli::StellarNetwork,
};

pub fn run(config: &CliConfig, json: bool) -> Result<()> {
    let account = config.require_account()?;
    onboard::ensure_ready(config, &account)?;
    let network = config.resolve_network()?;
    let storage = config.open_storage()?;

    let hash = register_account(config, &account, &network, &storage)?;

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

/// Prepare → sign → submit → confirm the registry `register` call. Returns the
/// transaction hash. Registration is idempotent on-chain (re-registering just
/// updates the stored keys), so no local pre-check is required.
pub fn register_account(
    config: &CliConfig,
    account: &Account,
    network: &StellarNetwork,
    storage: &SqliteStorage,
) -> Result<String> {
    let keys = storage
        .get_user_keys(&account.address)?
        .context("privacy keys not found; run `spp onboard` first")?;
    let note_key = keys.note_keypair.public.0;
    let encryption_key = keys.encryption_keypair.public.0;

    let client = Client::new(&network.rpc_url, config.deployment.clone())
        .map_err(|e| anyhow::anyhow!("rpc client: {e}"))?;
    let fetcher = client.state_fetcher();

    log::info!("Preparing registration for {}", account.address);
    let prepared = block_on(fetcher.prepare_register(&account.address, note_key, encryption_key))??;

    let secret = stellar_cli::secret(&account.alias, config.stellar_config_dir.as_deref())?;
    let signer = LocalSigner::from_secret(&secret).context("build signer for registration")?;
    let envelope = signer
        .sign_prepared_transaction(&prepared, &network.passphrase, &account.address)
        .context("sign registration transaction")?;

    log::info!("Submitting registration…");
    let hash = block_on(submit_tx(&envelope, fetcher.rpc()))??;
    block_on(confirm_tx(&hash, fetcher.rpc()))??;
    log::info!("Registration confirmed: {hash}");
    Ok(hash)
}
