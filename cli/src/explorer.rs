//! Explorer link building + the persisted explorer base-URL setting.
//!
//! Mirrors the web app: a single explorer base URL (stored in sqlite under
//! `APP_SETTING_EXPLORER` as `{"baseUrl": …}`) drives account/contract/tx/ledger
//! links.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use stellar_private_payments_sdk::state::{APP_SETTING_EXPLORER, SqliteStorage};

pub const DEFAULT_EXPLORER_BASE_URL: &str = "https://stellar.expert/explorer/testnet";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplorerSetting {
    #[serde(rename = "baseUrl")]
    pub base_url: String,
}

/// Configured explorer base URL, or the default when unset.
pub fn base_url(storage: &SqliteStorage) -> Result<String> {
    let setting: Option<ExplorerSetting> = storage.get_setting_json(APP_SETTING_EXPLORER)?;
    Ok(setting
        .map(|s| s.base_url)
        .unwrap_or_else(|| DEFAULT_EXPLORER_BASE_URL.to_string()))
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
