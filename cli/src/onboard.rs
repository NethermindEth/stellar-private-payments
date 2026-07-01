use anyhow::{Context, Result};
use stellar_private_payments_sdk::{
    state::SqliteStorage,
    tx::encryption::{
        KEY_DERIVATION_MESSAGE, derive_encryption_and_note_keypairs, derive_membership_blinding,
    },
};

use crate::{account::Account, config::CliConfig, stellar_cli};

pub fn ensure_onboarded(config: &CliConfig) -> Result<()> {
    let account = config.require_account()?;
    let path = config.wallet_db_path();
    let mut storage =
        SqliteStorage::connect_file(&path).with_context(|| format!("open {}", path.display()))?;

    if storage.get_user_keys(&account.address)?.is_some() {
        return Ok(());
    }

    save_privacy_keys(config, account, &mut storage)
}

fn save_privacy_keys(
    config: &CliConfig,
    account: &Account,
    storage: &mut SqliteStorage,
) -> Result<()> {
    // Delegate the SEP-53 key-derivation signature to the Stellar CLI so the
    // secret never enters this process. The CLI prefixes, hashes, and signs
    // exactly like Freighter / the web app, yielding identical privacy keys.
    let signature = stellar_cli::sign_message(
        &account.alias,
        KEY_DERIVATION_MESSAGE,
        config.stellar_config_dir.as_deref(),
    )
    .context("derive privacy-key signature via stellar CLI")?;

    let (note_keypair, encryption_keypair) = derive_encryption_and_note_keypairs(signature.clone())
        .context("derive privacy keypairs from wallet signature")?;
    let membership_blinding = derive_membership_blinding(&signature, &config.deployment.network)?;

    storage
        .save_encryption_and_note_keypairs(
            &account.address,
            &note_keypair,
            &encryption_keypair,
            &membership_blinding,
        )
        .context("save privacy keys to local wallet database")?;

    Ok(())
}
