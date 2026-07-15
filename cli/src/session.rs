use crate::{
    account::Account, artifacts::load_transact_artifacts, config::CliConfig, signer::AliasSigner,
    stellar_cli::StellarNetwork,
};
use anyhow::Result;
use stellar_private_payments_sdk::{
    Handle, LocalProver, LocalStorage, Prover, Signer, SyncMode, TransferRecipient,
    blocking::{Account as SdkAccount, Client, PrivatePool},
    types::{EncryptionPublicKey, NoteAmount, NotePublicKey},
};

/// SDK `Client` → `Account` session; open pools via [`Self::pool`].
pub struct ClientSession {
    client: Client,
    account: SdkAccount,
}

impl ClientSession {
    /// Bind wallet + deployment. `readonly` skips circuit artifact load
    /// (balance/notes/sync only).
    pub fn new(
        config: &CliConfig,
        account: &Account,
        network: &StellarNetwork,
        readonly: bool,
    ) -> Result<Self> {
        let storage_path = config.db_path().to_string_lossy().into_owned();
        let storage =
            LocalStorage::open(&storage_path).map_err(|e| anyhow::anyhow!("open storage: {e}"))?;

        let client = if readonly {
            Client::new_readonly(
                storage,
                SyncMode::Inline,
                config.deployment.clone(),
                network.rpc_url.clone(),
            )
        } else {
            let artifacts = load_transact_artifacts(Some(config.circuits_dir_path().as_path()))?;
            let prover = Handle::from_box(Box::new(
                LocalProver::from_artifacts(&artifacts)
                    .map_err(|e| anyhow::anyhow!("init transact prover: {e}"))?,
            ) as Box<dyn Prover>);
            Client::new(
                storage,
                prover,
                SyncMode::Inline,
                config.deployment.clone(),
                network.rpc_url.clone(),
            )
        };
        let sdk_account = client
            .account(&account.address, alias_signer(config, account, network))
            .map_err(|e| anyhow::anyhow!("open account session: {e}"))?;

        Ok(Self {
            client,
            account: sdk_account,
        })
    }

    pub fn account(&self) -> &SdkAccount {
        &self.account
    }

    pub fn operational_feed(
        &self,
        limit: u32,
    ) -> Result<Vec<stellar_private_payments_sdk::OperationalFeedItem>> {
        self.client
            .operational_feed(limit)
            .map_err(|e| anyhow::anyhow!("operational feed: {e}"))
    }

    pub fn pool(&self, pool_contract_id: &str) -> Result<PrivatePool> {
        log::info!("Opening pool {pool_contract_id}");
        self.account
            .pool(pool_contract_id)
            .map_err(|e| anyhow::anyhow!("open pool session: {e}"))
    }

    /// Register this account's public keys on the deployment-wide registry.
    pub fn register_public_keys(
        &self,
    ) -> Result<stellar_private_payments_sdk::types::TransactionResult> {
        log::info!("Registering public keys");
        self.account
            .register_public_keys(None, None)
            .map_err(|e| anyhow::anyhow!("register public keys: {e}"))
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
