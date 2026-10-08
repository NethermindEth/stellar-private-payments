//! Explorer link building + the persisted explorer base-URL setting.
//!
//! Mirrors the web app: a single explorer base URL (stored in sqlite under
//! `APP_SETTING_EXPLORER` as `{"baseUrl": …}`) drives
//! account/contract/tx/ledger links.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use stellar_private_payments::state::{APP_SETTING_EXPLORER, SqliteStorage};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplorerSetting {
    #[serde(rename = "baseUrl")]
    pub base_url: String,
}

/// Configured explorer base URL, or the default when unset.
pub fn base_url(
    storage: &SqliteStorage,
    deployment: &stellar_private_payments::types::ContractConfig,
) -> Result<String> {
    let setting: Option<ExplorerSetting> = storage.get_setting_json(APP_SETTING_EXPLORER)?;
    Ok(setting.map(|s| s.base_url).unwrap_or_else(|| {
        stellar_private_payments::network_defaults::for_passphrase(
            deployment.network_passphrase.as_deref().unwrap_or_default(),
        )
        .map(|defaults| defaults.explorer_url.clone())
        .unwrap_or_default()
    }))
}

pub fn set_base_url(storage: &mut SqliteStorage, base_url: &str) -> Result<()> {
    storage.set_setting_json(
        APP_SETTING_EXPLORER,
        &ExplorerSetting {
            base_url: base_url.to_string(),
        },
    )
}

/// Builds explorer URLs from a base like `https://stellar.expert/explorer/testnet`.
pub struct Explorer {
    base: String,
}

impl Explorer {
    pub fn new(base: impl Into<String>) -> Self {
        let base = base.into();
        Self {
            base: base.trim_end_matches('/').to_string(),
        }
    }

    pub fn account(&self, address: &str) -> String {
        format!("{}/account/{address}", self.base)
    }

    pub fn contract(&self, contract_id: &str) -> String {
        format!("{}/contract/{contract_id}", self.base)
    }

    pub fn tx(&self, hash: &str) -> String {
        format!("{}/tx/{hash}", self.base)
    }

    pub fn ledger(&self, ledger: u32) -> String {
        format!("{}/ledger/{ledger}", self.base)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_private_payments::types::ContractConfig;

    #[test]
    fn explorer_defaults_follow_identity_and_preserve_user_overrides() {
        let mut deployment: ContractConfig =
            serde_json::from_str(include_str!("../../deployments/testnet/deployments.json"))
                .expect("deployment");
        let mut storage = SqliteStorage::connect_in_memory().expect("storage");
        assert_eq!(
            base_url(&storage, &deployment).expect("default"),
            "https://stellar.expert/explorer/testnet"
        );
        deployment.network_passphrase = Some("custom network".into());
        assert_eq!(base_url(&storage, &deployment).expect("no default"), "");
        set_base_url(&mut storage, "https://explorer.example").expect("save override");
        assert_eq!(
            base_url(&storage, &deployment).expect("override"),
            "https://explorer.example"
        );
        set_base_url(&mut storage, "").expect("disable explorer");
        deployment.network_passphrase = Some("Test SDF Network ; September 2015".into());
        assert_eq!(base_url(&storage, &deployment).expect("disabled"), "");
    }
}
