use anyhow::{Context, Result};
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest, Sha256};
use stellar_private_payments_sdk::{
    state::SqliteStorage,
    tx::encryption::{
        KEY_DERIVATION_MESSAGE, derive_encryption_and_note_keypairs, derive_membership_blinding,
    },
    types::KeyDerivationSignature,
};
use stellar_strkey::ed25519::PrivateKey;

use crate::{config::CliConfig, signing::WalletCredentials};

/// SEP-53 prefix used by Freighter `signMessage` (must match the web app).
const SEP53_MESSAGE_PREFIX: &[u8] = b"Stellar Signed Message:\n";

pub fn ensure_onboarded(config: &CliConfig) -> Result<()> {
    let wallet = config.require_wallet()?;
    let path = config.wallet_db_path();
    let mut storage =
        SqliteStorage::connect_file(&path).with_context(|| format!("open {}", path.display()))?;

    if storage.get_user_keys(&wallet.address)?.is_some() {
        return Ok(());
    }

    save_privacy_keys(config, wallet, &mut storage)
}

fn save_privacy_keys(
    config: &CliConfig,
    wallet: &WalletCredentials,
    storage: &mut SqliteStorage,
) -> Result<()> {
    let signature = wallet_derivation_signature(&wallet.secret_key)?;
    let (note_keypair, encryption_keypair) = derive_encryption_and_note_keypairs(signature.clone())
        .context("derive privacy keypairs from wallet signature")?;
    let membership_blinding = derive_membership_blinding(&signature, &config.deployment.network)?;

    storage
        .save_encryption_and_note_keypairs(
            &wallet.address,
            &note_keypair,
            &encryption_keypair,
            &membership_blinding,
        )
        .context("save privacy keys to local wallet database")?;

    Ok(())
}

fn wallet_derivation_signature(secret: &str) -> Result<KeyDerivationSignature> {
    let private_key: PrivateKey = secret
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid secret key: {e}"))?;
    let signing_key = SigningKey::from_bytes(&private_key.0);

    // Match Freighter / web: SEP-53 hash then ed25519 sign (not raw message sign).
    let capacity = SEP53_MESSAGE_PREFIX
        .len()
        .saturating_add(KEY_DERIVATION_MESSAGE.len());
    let mut payload = Vec::with_capacity(capacity);
    payload.extend_from_slice(SEP53_MESSAGE_PREFIX);
    payload.extend_from_slice(KEY_DERIVATION_MESSAGE.as_bytes());
    let digest: [u8; 32] = Sha256::digest(payload).into();
    let signature = signing_key.sign(&digest);

    Ok(KeyDerivationSignature(signature.to_bytes().to_vec()))
}
