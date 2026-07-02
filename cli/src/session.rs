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
                prover_artifacts: load_prover_artifacts(Some(
                    config.circuits_dir_path().as_path(),
                ))?,
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
    const DECIMALS: u32 = 7;
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(anyhow::anyhow!("invalid amount: empty input"));
    }

    let (negative, digits) = match raw.as_bytes()[0] {
        b'+' => (false, &raw[1..]),
        b'-' => (true, &raw[1..]),
        _ => (false, raw),
    };
    let (int_part, frac_part) = match digits.split_once('.') {
        Some((int_part, frac_part)) => {
            (if int_part.is_empty() { "0" } else { int_part }, frac_part)
        }
        None => (if digits.is_empty() { "0" } else { digits }, ""),
    };

    if int_part.is_empty() || !int_part.chars().all(|c| c.is_ascii_digit()) {
        return Err(anyhow::anyhow!("invalid amount: {raw}"));
    }
    if !frac_part.chars().all(|c| c.is_ascii_digit()) {
        return Err(anyhow::anyhow!("invalid amount: {raw}"));
    }
    if frac_part.len() > DECIMALS as usize {
        return Err(anyhow::anyhow!("too many decimal places (max {DECIMALS})"));
    }

    let scale = 10u128.pow(DECIMALS);
    let int_units = int_part
        .parse::<u128>()
        .map_err(|e| anyhow::anyhow!("invalid amount: {e}"))?;
    let frac_units = if frac_part.is_empty() {
        0u128
    } else {
        let padded = format!("{frac_part:0<width$}", width = DECIMALS as usize);
        padded
            .parse::<u128>()
            .map_err(|e| anyhow::anyhow!("invalid amount: {e}"))?
    };

    let amount = int_units
        .checked_mul(scale)
        .and_then(|v| v.checked_add(frac_units))
        .ok_or_else(|| anyhow::anyhow!("amount is too large"))?;
    if negative && amount != 0 {
        return Err(anyhow::anyhow!("amount must be non-negative"));
    }
    Ok(NoteAmount::from(amount))
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

#[cfg(test)]
mod tests {
    use super::parse_amount;
    use stellar_private_payments_sdk::types::NoteAmount;

    #[test]
    fn parses_token_units_with_decimals() {
        assert_eq!(parse_amount("1").unwrap(), NoteAmount::from(10_000_000u128));
        assert_eq!(
            parse_amount("1.").unwrap(),
            NoteAmount::from(10_000_000u128)
        );
        assert_eq!(parse_amount(".5").unwrap(), NoteAmount::from(5_000_000u128));
        assert_eq!(parse_amount("0.0000001").unwrap(), NoteAmount::from(1u128));
        assert_eq!(
            parse_amount("12.3456789").unwrap(),
            NoteAmount::from(123_456_789u128)
        );
    }

    #[test]
    fn rejects_too_many_decimals() {
        assert!(parse_amount("0.00000001").is_err());
    }
}
