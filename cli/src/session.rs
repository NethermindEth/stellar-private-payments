use std::path::Path;

use anyhow::{Context, Result};
use stellar_private_payments_sdk::{
    LocalSigner, PrivatePoolConfig, Signer, TransferRecipient,
    blocking::PrivatePool,
    state::SqliteStorage,
    types::{EncryptionPublicKey, NoteAmount, NotePublicKey},
};

use crate::{artifacts::load_prover_artifacts, config::CliConfig, onboard::ensure_onboarded};

/// How the CLI names a private transfer recipient.
#[derive(Debug, clap::Subcommand)]
pub enum TransferRecipientCmd {
    /// Look up recipient privacy keys from the on-chain public key registry
    To {
        /// Recipient Stellar address (G…)
        address: String,
    },
    /// Provide recipient privacy keys directly
    Keys {
        /// Recipient BN254 note public key (hex)
        #[arg(long)]
        note_key: String,
        /// Recipient X25519 encryption public key (hex)
        #[arg(long)]
        encryption_key: String,
    },
}

pub struct PoolSession {
    pool: PrivatePool,
}

impl PoolSession {
    pub fn open(config: &CliConfig, circuits_dir: Option<&Path>) -> Result<Self> {
        let wallet = config.require_wallet()?;
        let pool_contract_id = config.require_pool()?.to_string();

        std::fs::create_dir_all(&config.data_dir)
            .with_context(|| format!("create data dir {}", config.data_dir.display()))?;

        ensure_onboarded(config)?;

        let signer: Box<dyn Signer> = Box::new(
            LocalSigner::new(
                &wallet.secret_key,
                config.network_passphrase(),
                &wallet.address,
            )
            .map_err(|e| anyhow::anyhow!("{e}"))?,
        );

        let pool = PrivatePool::open(
            PrivatePoolConfig {
                rpc_url: config.rpc_url.clone(),
                contract_config: config.deployment.clone(),
                pool_contract_id,
                user_address: wallet.address.clone(),
                storage_path: config.wallet_db_path().to_string_lossy().into_owned(),
                prover_artifacts: load_prover_artifacts(circuits_dir)?,
            },
            signer,
        )
        .map_err(|e| anyhow::anyhow!("open pool session: {e}"))?;

        pool.sync().map_err(|e| anyhow::anyhow!("sync pool: {e}"))?;

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

pub fn resolve_transfer_recipient_cmd(
    config: &CliConfig,
    recipient: &TransferRecipientCmd,
) -> Result<TransferRecipient> {
    match recipient {
        TransferRecipientCmd::To { address } => resolve_transfer_recipient(config, address),
        TransferRecipientCmd::Keys {
            note_key,
            encryption_key,
        } => transfer_recipient_from_keys(note_key, encryption_key),
    }
}

pub fn resolve_transfer_recipient(config: &CliConfig, to: &str) -> Result<TransferRecipient> {
    let storage = SqliteStorage::connect_file(config.wallet_db_path())
        .context("open wallet database for recipient lookup")?;
    let entry = storage.lookup_public_key_by_address(to)?.with_context(|| {
        format!(
            "recipient {to} not found in the public key registry; \
                 they must register keys on-chain"
        )
    })?;
    Ok(TransferRecipient {
        note_public_key: entry.note_key,
        encryption_public_key: entry.encryption_key,
    })
}

pub fn transfer_recipient_from_keys(
    note_key: &str,
    encryption_key: &str,
) -> Result<TransferRecipient> {
    Ok(TransferRecipient {
        note_public_key: NotePublicKey::parse(note_key)
            .map_err(|e| anyhow::anyhow!("invalid recipient note key: {e}"))?,
        encryption_public_key: EncryptionPublicKey::parse(encryption_key)
            .map_err(|e| anyhow::anyhow!("invalid recipient encryption key: {e}"))?,
    })
}
