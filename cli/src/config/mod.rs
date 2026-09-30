mod toml;

use std::{
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
};

use anyhow::{Context, Result, bail};
use stellar_private_payments::{
    state::{SqliteStorage, database_key::DatabaseKey},
    types::{ContractConfig, Sensitive},
};

use crate::{
    account::{Account, resolve},
    stellar_cli::{self, StellarNetwork},
};

pub use toml::{
    FileConfig, default_config_path, load_file_config, resolve_config_path, write_config_template,
};

/// Testnet deployment baked into the binary (from
/// `deployments/testnet/deployments.json`).
pub const DEFAULT_DEPLOYMENT_JSON: &str =
    include_str!("../../../deployments/testnet/deployments.json");

pub const EMBEDDED_DEPLOYMENT_LABEL: &str = "embedded:testnet";

/// Deployment config provisioned into the data dir by `scripts/install.sh`.
pub const DEPLOYMENT_FILE_NAME: &str = "deployments.json";

/// Flag names, so a rejected alias is reported against the option it came from.
const ACCOUNT_FLAG: &str = "--account";
const SIGN_AS_FLAG: &str = "--sign-as";

/// CLI flag overrides used to build a [`CliConfig`].
#[derive(Debug, Default)]
pub struct CliConfigOverrides {
    pub deployment_path: Option<PathBuf>,
    pub network: Option<String>,
    pub data_dir: Option<PathBuf>,
    pub account: Option<String>,
    pub sign_as: Option<String>,
    pub stellar_config_dir: Option<PathBuf>,
    pub circuits_dir: Option<PathBuf>,
    pub storage_account: Option<String>,
}

/// Resolved (offline) CLI configuration.
///
/// Loading never calls the `stellar` binary; the RPC/passphrase (via
/// [`CliConfig::resolve_network`]), the note owner (via
/// [`CliConfig::require_account`]) and the payer (via
/// [`CliConfig::require_signer`]) are resolved on demand by the commands that
/// need them.
#[derive(Debug, Clone)]
pub struct CliConfig {
    /// TOML config file when loaded; otherwise None.
    pub config_file: Option<PathBuf>,
    /// File path when overridden; otherwise [`EMBEDDED_DEPLOYMENT_LABEL`].
    pub deployment_source: String,
    pub deployment: ContractConfig,
    /// Stellar CLI network name (built-in like `testnet`, or a custom one).
    pub network: String,
    pub data_dir: PathBuf,
    /// Config dir passed through to the `stellar` CLI (`--config-dir`).
    pub stellar_config_dir: Option<PathBuf>,
    /// `stellar keys` alias supplied via `--account`: the note owner.
    pub account: Option<String>,
    /// `stellar keys` alias supplied via `--sign-as`: the payer that sources
    /// and signs every envelope. `None` means the owner pays for itself.
    pub sign_as: Option<String>,
    pub circuits_dir: Option<PathBuf>,
    /// Identity that unlocks storage, defaulting to the note owner.
    pub storage_account: Option<String>,
    /// The database key once unlocked, so one command asks only once.
    database_key: Arc<OnceLock<DatabaseKey>>,
}

impl CliConfig {
    pub fn load(
        config_file: Option<PathBuf>,
        file: Option<FileConfig>,
        overrides: CliConfigOverrides,
    ) -> Result<Self> {
        let file = file.unwrap_or_default();
        let CliConfigOverrides {
            deployment_path,
            network,
            data_dir,
            account,
            sign_as,
            stellar_config_dir,
            circuits_dir,
            storage_account,
        } = overrides;

        let deployment_path = deployment_path.or(file.defaults.deployment.map(toml::expand_path));
        let data_dir = data_dir
            .or(file.defaults.data_dir.map(toml::expand_path))
            .unwrap_or_else(default_data_dir);
        let circuits_dir = circuits_dir.or(file.defaults.circuits_dir.map(toml::expand_path));
        let stellar_config_dir =
            stellar_config_dir.or(file.defaults.stellar_config_dir.map(toml::expand_path));

        let (deployment_source, deployment) =
            load_deployment(deployment_path.as_deref(), &data_dir)?;
        // Network name: --network > config default > the deployment's network
        // (which matches a Stellar CLI built-in like `testnet`).
        let network = network
            .or(file.defaults.network)
            .unwrap_or_else(|| deployment.network.clone());

        Ok(Self {
            config_file,
            deployment_source,
            deployment,
            network,
            data_dir,
            stellar_config_dir,
            account,
            sign_as,
            circuits_dir,
            storage_account: storage_account.or(file.defaults.storage_account),
            database_key: Arc::default(),
        })
    }

    /// Resolve the RPC URL + network passphrase from the Stellar CLI.
    pub fn resolve_network(&self) -> Result<StellarNetwork> {
        stellar_cli::network(&self.network, self.stellar_config_dir.as_deref())
    }

    /// Resolve the note owner from its `--account` alias.
    pub fn require_account(&self) -> Result<Account> {
        let alias = self.account.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "this command requires --account <stellar keys alias> \
                 (spp works with Stellar CLI identities; see `stellar keys`)"
            )
        })?;
        resolve(ACCOUNT_FLAG, alias, self.stellar_config_dir.as_deref())
    }

    /// Resolve the payer that sources and signs this session's envelopes.
    ///
    /// Without `--sign-as` the owner pays for itself, and the returned account
    /// is `owner` unchanged — the single-alias behaviour, with no second
    /// lookup through the Stellar CLI.
    pub fn require_signer(&self, owner: &Account) -> Result<Account> {
        match self.sign_as.as_deref() {
            None => Ok(owner.clone()),
            Some(alias) => resolve(SIGN_AS_FLAG, alias, self.stellar_config_dir.as_deref()),
        }
    }

    /// Refuse a separate payer for a step that only the owner can perform.
    ///
    /// Onboarding derives the note secret from the owner's own signature and
    /// files it under the owner's address, so a payer has nothing it could
    /// contribute — signing with the owner's key regardless would honour the
    /// `--account` half of the request while silently discarding the
    /// `--sign-as` half. Call this before touching any state; the SDK raises
    /// the equivalent refusal for registration.
    pub fn ensure_owner_signs(&self, owner: &Account) -> Result<()> {
        ensure_owner_is_signer(owner, &self.require_signer(owner)?)
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("spp.db")
    }

    pub fn circuits_dir_path(&self) -> PathBuf {
        self.circuits_dir
            .clone()
            .unwrap_or_else(|| default_circuits_dir(&self.data_dir))
    }

    /// Storage ownership is independent of the transaction payer.
    pub fn storage_alias(&self) -> Result<&str> {
        let alias = self
            .storage_account
            .as_deref()
            .or(self.account.as_deref())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "storage requires --storage-account <stellar keys alias> or --account"
                )
            })?;
        stellar_cli::validate_alias("--storage-account", alias)?;
        Ok(alias)
    }

    /// The key of the local database, unlocking it on first use (and creating
    /// or encrypting it if needed).
    pub fn database_key(&self) -> Result<&DatabaseKey> {
        if let Some(key) = self.database_key.get() {
            return Ok(key);
        }
        std::fs::create_dir_all(&self.data_dir)
            .with_context(|| format!("create data dir {}", self.data_dir.display()))?;
        let alias = self.storage_alias()?;
        let key = stellar_private_payments::state::native_wallet::unlock_with_stellar(
            &self.db_path(),
            alias,
            self.stellar_config_dir.as_deref(),
        )?;
        Ok(self.database_key.get_or_init(|| key))
    }

    /// Open the local encrypted database (`spp.db`), unlocking it first.
    pub fn open_storage(&self) -> Result<SqliteStorage> {
        let key = self.database_key()?;
        let path = self.db_path();
        SqliteStorage::reopen_encrypted(&path, key)
            .with_context(|| format!("open {}", path.display()))
    }
}

/// The refusal itself, split from the lookup so it can be tested without the
/// Stellar CLI. Mirrors the SDK's `ensure_signer_is_note_owner`, which raises
/// the equivalent for registration.
fn ensure_owner_is_signer(owner: &Account, signer: &Account) -> Result<()> {
    if signer.address == owner.address {
        return Ok(());
    }
    bail!(
        "signing account {} cannot stand in for the note owner {}; \
         this step needs the owner's own signature. \
         Re-run it with --account {} and without --sign-as.",
        Sensitive(&signer.address),
        Sensitive(&owner.address),
        owner.alias
    )
}

pub fn default_data_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".local/share/stellar-private-payments"))
        .unwrap_or_else(|| PathBuf::from(".stellar-pp"))
}

pub fn default_circuits_dir(data_dir: &Path) -> PathBuf {
    if cfg!(debug_assertions) {
        PathBuf::from("target/circuits-artifacts")
    } else {
        data_dir.join("circuits")
    }
}

/// Resolve the deployment config: `--deployment` > the copy provisioned into
/// the data dir by `scripts/install.sh` > [`DEFAULT_DEPLOYMENT_JSON`].
fn load_deployment(path: Option<&Path>, data_dir: &Path) -> Result<(String, ContractConfig)> {
    if let Some(path) = path {
        return read_deployment_file(path);
    }
    let provisioned = data_dir.join(DEPLOYMENT_FILE_NAME);
    if provisioned.is_file() {
        return read_deployment_file(&provisioned);
    }
    let deployment = serde_json::from_str(DEFAULT_DEPLOYMENT_JSON)
        .context("parse embedded testnet deployment")?;
    Ok((EMBEDDED_DEPLOYMENT_LABEL.to_string(), deployment))
}

fn read_deployment_file(path: &Path) -> Result<(String, ContractConfig)> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read deployment file {}", path.display()))?;

    // A schema mismatch here usually means the file is newer than this binary
    let deployment = serde_json::from_str(&raw)
        .with_context(|| format!("parse deployment file {}", path.display()))?;
    Ok((path.display().to_string(), deployment))
}

pub fn validate_pool(pool: &str, deployment: &ContractConfig) -> Result<()> {
    let entry = deployment.pool(pool)?;
    if entry.enabled {
        Ok(())
    } else {
        bail!("pool {pool} is not an enabled pool in the deployment config");
    }
}

#[cfg(test)]
mod tests {
    use super::{CliConfig, CliConfigOverrides};
    use crate::account::Account;

    const OWNER_ADDRESS: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
    const PAYER_ADDRESS: &str = "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB6BQ";
    /// Shaped like a raw secret key: 56 characters starting with `S`.
    const SECRET_SHAPED: &str = "SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    /// A config over the embedded testnet deployment. The data dir is a name
    /// that holds no provisioned `deployments.json`, so loading stays offline
    /// and independent of the machine's own wallet directory.
    fn config_with(sign_as: Option<&str>) -> CliConfig {
        CliConfig::load(
            None,
            None,
            CliConfigOverrides {
                data_dir: Some(std::env::temp_dir().join("spp-require-signer-tests")),
                account: Some("owner".to_string()),
                sign_as: sign_as.map(str::to_string),
                ..Default::default()
            },
        )
        .expect("the embedded testnet deployment should load")
    }

    fn owner() -> Account {
        Account {
            alias: "owner".to_string(),
            address: OWNER_ADDRESS.to_string(),
        }
    }

    #[test]
    fn storage_identity_defaults_to_owner_and_never_to_payer() {
        let mut config = config_with(Some("payer"));
        assert_eq!(
            config.storage_alias().expect("valid storage alias"),
            "owner"
        );
        config.storage_account = Some("vault-owner".into());
        assert_eq!(
            config.storage_alias().expect("valid storage alias"),
            "vault-owner"
        );
        config.account = None;
        assert_eq!(
            config.storage_alias().expect("valid storage alias"),
            "vault-owner"
        );
        config.storage_account = None;
        assert!(config.storage_alias().is_err());
        config.storage_account = Some(SECRET_SHAPED.into());
        assert!(
            config
                .storage_alias()
                .expect_err("raw secret keys must not be accepted as aliases")
                .to_string()
                .contains("not a raw secret key")
        );
    }

    #[test]
    fn without_sign_as_the_owner_pays_for_itself() {
        let owner = owner();
        let signer = config_with(None)
            .require_signer(&owner)
            .expect("the owner needs no lookup to stand in for itself");

        assert_eq!(signer.alias, owner.alias);
        assert_eq!(signer.address, owner.address);
    }

    #[test]
    fn onboarding_steps_refuse_a_payer_that_is_not_the_owner() {
        let payer = Account {
            alias: "payer".to_string(),
            address: PAYER_ADDRESS.to_string(),
        };
        let error = super::ensure_owner_is_signer(&owner(), &payer)
            .expect_err("the derivation signature is the note secret; only the owner has it");
        let message = error.to_string();

        assert!(
            message.starts_with("signing account <redacted> cannot stand in for the note owner"),
            "both addresses are Tier-1 and must be redacted, got: {message}"
        );
        assert!(
            !message.contains(PAYER_ADDRESS) && !message.contains(OWNER_ADDRESS),
            "no address may survive into the rendered message, got: {message}"
        );
        // The app classifies a wallet cancellation by substring; this refusal
        // is not one, so it must not carry any of the words that classifier
        // looks for.
        let lowercased = message.to_lowercase();
        for banned in ["rejected", "denied", "cancelled"] {
            assert!(
                !lowercased.contains(banned),
                "`{banned}` would be read as a wallet cancellation, got: {message}"
            );
        }
    }

    #[test]
    fn the_owner_signing_for_itself_is_accepted() {
        super::ensure_owner_is_signer(&owner(), &owner())
            .expect("the owner is always allowed to sign its own onboarding");
        config_with(None)
            .ensure_owner_signs(&owner())
            .expect("without --sign-as the owner signs for itself");
    }

    #[test]
    fn sign_as_is_validated_before_the_stellar_cli_is_asked() {
        let error = config_with(Some(SECRET_SHAPED))
            .require_signer(&owner())
            .expect_err("a raw secret key must never reach the command line");

        assert!(
            error
                .to_string()
                .starts_with("--sign-as must be a `stellar keys` alias name, not a raw secret key"),
            "the payer's alias should be reported against --sign-as, got: {error}"
        );
    }
}
