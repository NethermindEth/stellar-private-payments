use anyhow::Result;
use stellar_private_payments_sdk::{
    Handle, LocalProver, LocalStorage, NoopProver, Prover, ProverArtifacts, Signer, SyncMode,
    TransferRecipient,
    blocking::{Client, PrivatePool},
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
    /// Open one pool with a full prover. `account` and `network` are resolved
    /// once by the caller (so callers can reuse them across pools). Loads
    /// circuit artifacts (proving key + circuit) — required for transacting
    /// commands (deposit/transfer/withdraw), which is the only caller of this
    /// path.
    pub fn open(
        config: &CliConfig,
        account: &Account,
        network: &StellarNetwork,
        pool_contract_id: &str,
    ) -> Result<Self> {
        let artifacts = load_prover_artifacts(Some(config.circuits_dir_path().as_path()))?;
        Self::open_with(config, account, network, pool_contract_id, artifacts, false)
    }

    /// Open one pool without a prover. Skips loading the circuit artifacts
    /// entirely (no proving-key deserialization, no WASM compile), so
    /// read-only commands (`overview`, `feed`) are cheap. The resulting pool
    /// can read balances/notes and sync, but any transact/prove call errors.
    pub fn open_readonly(
        config: &CliConfig,
        account: &Account,
        network: &StellarNetwork,
        pool_contract_id: &str,
    ) -> Result<Self> {
        Self::open_with(
            config,
            account,
            network,
            pool_contract_id,
            ProverArtifacts::empty(),
            true,
        )
    }

    fn open_with(
        config: &CliConfig,
        account: &Account,
        network: &StellarNetwork,
        pool_contract_id: &str,
        prover_artifacts: ProverArtifacts,
        readonly: bool,
    ) -> Result<Self> {
        let storage_path = config.db_path().to_string_lossy().into_owned();
        let storage =
            LocalStorage::open(&storage_path).map_err(|e| anyhow::anyhow!("open storage: {e}"))?;

        let prover: Handle<dyn Prover> = if readonly {
            Handle::from_box(Box::new(NoopProver) as Box<dyn Prover>)
        } else {
            Handle::from_box(
                Box::new(LocalProver::from_artifacts(&prover_artifacts)?) as Box<dyn Prover>
            )
        };

        let client = Client::new(
            storage,
            prover,
            SyncMode::Inline,
            config.deployment.clone(),
            network.rpc_url.clone(),
        );
        let sdk_account = client
            .account(&account.address, alias_signer(config, account, network))
            .map_err(|e| anyhow::anyhow!("open account session: {e}"))?;

        log::info!("Opening pool {pool_contract_id}");
        let pool = sdk_account
            .pool(pool_contract_id)
            .map_err(|e| anyhow::anyhow!("open pool session: {e}"))?;

        Ok(Self { pool })
    }

    pub fn pool(&self) -> &PrivatePool {
        &self.pool
    }
}

fn alias_signer(
    config: &CliConfig,
    account: &Account,
    network: &StellarNetwork,
) -> Handle<dyn Signer> {
    Handle::from_box(Box::new(AliasSigner {
        alias: account.alias.clone(),
        rpc_url: network.rpc_url.clone(),
        network_passphrase: network.passphrase.clone(),
        config_dir: config.stellar_config_dir.clone(),
    }) as Box<dyn Signer>)
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

/// Parse `--to` address or explicit note + encryption keys into a
/// [`TransferRecipient`].
pub fn parse_transfer_recipient(
    to: Option<&str>,
    note_key: Option<&str>,
    encryption_key: Option<&str>,
) -> Result<TransferRecipient> {
    match (to, note_key, encryption_key) {
        (Some(address), None, None) => Ok(TransferRecipient::from(address)),
        (None, Some(note_key), Some(encryption_key)) => Ok(TransferRecipient::keys(
            NotePublicKey::parse(note_key)
                .map_err(|e| anyhow::anyhow!("invalid recipient note key: {e}"))?,
            EncryptionPublicKey::parse(encryption_key)
                .map_err(|e| anyhow::anyhow!("invalid recipient encryption key: {e}"))?,
        )),
        _ => anyhow::bail!(
            "specify the recipient with --to <G…>, or both --note-key <hex> and --encryption-key <hex>"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_amount;
    use stellar_private_payments_sdk::types::NoteAmount;

    #[test]
    fn parses_token_units_with_decimals() {
        assert_eq!(
            parse_amount("1").expect("1 should parse as 1 token"),
            NoteAmount::from(10_000_000u128)
        );
        assert_eq!(
            parse_amount("1.").expect("1. should parse as 1 token"),
            NoteAmount::from(10_000_000u128)
        );
        assert_eq!(
            parse_amount(".5").expect(".5 should parse as 0.5 token"),
            NoteAmount::from(5_000_000u128)
        );
        assert_eq!(
            parse_amount("0.0000001").expect("smallest unit should parse"),
            NoteAmount::from(1u128)
        );
        assert_eq!(
            parse_amount("12.3456789").expect("12.3456789 should parse"),
            NoteAmount::from(123_456_789u128)
        );
    }

    #[test]
    fn rejects_too_many_decimals() {
        assert!(parse_amount("0.00000001").is_err());
    }
}
