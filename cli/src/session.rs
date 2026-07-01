use std::path::Path;

use anyhow::{Context, Result};
use stellar_private_payments_sdk::{
    PrivatePoolConfig, Signer, TransferRecipient,
    blocking::PrivatePool,
    types::{EncryptionPublicKey, NoteAmount, NotePublicKey},
};

use crate::{
    account::Account, artifacts::load_prover_artifacts, config::CliConfig, signer::AliasSigner,
    stellar_cli::StellarNetwork,
};

pub struct PoolSession {
    pool: PrivatePool,
}

impl PoolSession {
    /// Open and sync one pool. `account` and `network` are resolved once by the
    /// caller (so overview/feed can reuse them across pools). Loads circuit
    /// artifacts — callers that only read balances still pay this, which is
    /// acceptable since the artifacts ship with the tool.
    pub fn open(
        config: &CliConfig,
        account: &Account,
        network: &StellarNetwork,
        pool_contract_id: &str,
        circuits_dir: Option<&Path>,
    ) -> Result<Self> {
        let signer: Box<dyn Signer> = Box::new(AliasSigner {
            alias: account.alias.clone(),
            network_passphrase: network.passphrase.clone(),
            user_address: account.address.clone(),
            config_dir: config.stellar_config_dir.clone(),
        });

        log::info!("Opening pool {pool_contract_id}");
        let pool = PrivatePool::open(
            PrivatePoolConfig {
                rpc_url: network.rpc_url.clone(),
                contract_config: config.deployment.clone(),
                pool_contract_id: pool_contract_id.to_string(),
                user_address: account.address.clone(),
                storage_path: config.wallet_db_path().to_string_lossy().into_owned(),
                prover_artifacts: load_prover_artifacts(circuits_dir)?,
            },
            signer,
        )
        .map_err(|e| anyhow::anyhow!("open pool session: {e}"))?;

        log::info!("Syncing pool {pool_contract_id}…");
        pool.sync().map_err(|e| anyhow::anyhow!("sync pool: {e}"))?;
        log::info!("Synced pool {pool_contract_id}");

        Ok(Self { pool })
    }

    pub fn pool(&self) -> &PrivatePool {
        &self.pool
    }
}

pub fn parse_amount(raw: &str) -> Result<NoteAmount> {
    raw.parse::<NoteAmount>()
        .map_err(|e| anyhow::anyhow!("invalid amount (stroops): {e}"))
}

/// Recipient of a private transfer: either an address (looked up in the local
/// registry index) or explicit note + encryption keys.
pub fn resolve_transfer_recipient(
    config: &CliConfig,
    to: Option<&str>,
    note_key: Option<&str>,
    encryption_key: Option<&str>,
) -> Result<TransferRecipient> {
    match (to, note_key, encryption_key) {
        (Some(address), None, None) => recipient_from_address(config, address),
        (None, Some(note_key), Some(encryption_key)) => {
            recipient_from_keys(note_key, encryption_key)
        }
        _ => anyhow::bail!(
            "specify the recipient with --to <G…>, or both --note-key <hex> and --encryption-key <hex>"
        ),
    }
}

fn recipient_from_address(config: &CliConfig, to: &str) -> Result<TransferRecipient> {
    let storage = config.open_storage()?;
    let entry = storage.lookup_public_key_by_address(to)?.with_context(|| {
        format!(
            "recipient {to} not found in the public key registry; \
             they must register keys on-chain (`spp register`)"
        )
    })?;
    Ok(TransferRecipient {
        note_public_key: entry.note_key,
        encryption_public_key: entry.encryption_key,
    })
}

fn recipient_from_keys(note_key: &str, encryption_key: &str) -> Result<TransferRecipient> {
    Ok(TransferRecipient {
        note_public_key: NotePublicKey::parse(note_key)
            .map_err(|e| anyhow::anyhow!("invalid recipient note key: {e}"))?,
        encryption_public_key: EncryptionPublicKey::parse(encryption_key)
            .map_err(|e| anyhow::anyhow!("invalid recipient encryption key: {e}"))?,
    })
}
