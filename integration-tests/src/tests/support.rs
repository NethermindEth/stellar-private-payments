//! Shared setup for tests: each test deploys the one pool it needs on the
//! shared network, then opens its own wallet session against it.

use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::{Context, Result};
use stellar_private_payments::{
    Account, CircuitStore, Client, Error, LocalProver, LocalSigner, LocalStorage,
    PreparedTransaction, PrivatePool, Signer,
    chain::PreparedSorobanTx,
    types::{
        ContractConfig, KeyDerivationSignature, NoteOwnerAddress, PoolConfigEntry,
        SignedTransaction, SignerAddress,
    },
    zk::disclosure::find_circuit,
};

use crate::{
    keypair::TestKeypair,
    network::{self, DeploymentIdentity, LocalNetwork, NETWORK_PASSPHRASE},
    pool::PoolOptions,
};

const MAX_DEPOSIT_STROOPS: u128 = 1_000_000_000_000;
const ASP_LEVELS: u32 = 10;
const POOL_LEVELS: u32 = 20;

pub struct TestSession {
    pub account: Account,
    pub wallet: TestKeypair,
    pub identity: DeploymentIdentity,
    pool_contract_ids: Vec<String>,
    storage_path: PathBuf,
    storage_key: std::sync::Arc<stellar_private_payments::state::database_key::DatabaseKey>,
    reject_next_transaction: Arc<AtomicBool>,
}

impl TestSession {
    /// Make the wallet reject the next transaction it is asked to sign, as a
    /// user declining the wallet prompt would.
    pub fn reject_next_transaction(&self) {
        self.reject_next_transaction.store(true, Ordering::SeqCst);
    }

    pub fn pool(&self) -> Result<PrivatePool> {
        self.pool_at(0)
    }

    pub fn pool_at(&self, index: usize) -> Result<PrivatePool> {
        let pool_contract_id = self
            .pool_contract_ids
            .get(index)
            .with_context(|| format!("no deployed pool at index {index}"))?;
        Ok(self.account.pool(pool_contract_id)?)
    }

    /// Another session for the same wallet on the same wallet database, under
    /// `config` (e.g. another `kdf_domain`).
    pub async fn fork(&self, config: ContractConfig) -> Result<TestSession> {
        let network = LocalNetwork::start().await?;
        let storage = LocalStorage::open_with_key(
            self.storage_path
                .to_str()
                .context("storage path is not UTF-8")?,
            &self.storage_key,
        )?;
        build_session(
            &network,
            config,
            self.identity.clone(),
            self.wallet.clone(),
            self.storage_path.clone(),
            self.storage_key.clone(),
            storage,
        )
        .await
    }
}

pub async fn deploy_default() -> Result<(ContractConfig, DeploymentIdentity)> {
    deploy(&[PoolOptions::NONE]).await
}

/// Deploy every entry of `pools` together (one `deploy.sh` invocation, so
/// they share ASP membership/non-membership contracts).
pub async fn deploy(pools: &[PoolOptions]) -> Result<(ContractConfig, DeploymentIdentity)> {
    deploy_with_max_deposit(MAX_DEPOSIT_STROOPS, pools).await
}

/// Like [`deploy`], but with an explicit `max_deposit` cap instead of the
/// suite-wide default.
pub async fn deploy_with_max_deposit(
    max_deposit: u128,
    pools: &[PoolOptions],
) -> Result<(ContractConfig, DeploymentIdentity)> {
    let network = LocalNetwork::start().await?;
    network
        .deploy(max_deposit, ASP_LEVELS, POOL_LEVELS, pools, None)
        .await
}

/// Like [`deploy`], but `scope` is folded into the deploy cache key,
/// guaranteeing a deployment private to this scope instead of one shared
/// with any other test using the same `pools`.
pub async fn deploy_scoped(
    pools: &[PoolOptions],
    scope: &str,
) -> Result<(ContractConfig, DeploymentIdentity)> {
    let network = LocalNetwork::start().await?;
    network
        .deploy(
            MAX_DEPOSIT_STROOPS,
            ASP_LEVELS,
            POOL_LEVELS,
            pools,
            Some(scope),
        )
        .await
}

/// Asserts that `err` carries the contract error `code`, which a refused
/// simulation prints as `Error(Contract, #code)`.
pub fn assert_contract_error(err: impl Into<anyhow::Error>, code: u32) {
    let err = format!("{:#}", err.into());
    let expected = format!("Error(Contract, #{code})");
    assert!(err.contains(&expected), "expected {expected}, got: {err}");
}

/// Open a new wallet session against an existing deployment.
pub async fn session(
    (config, identity): (ContractConfig, DeploymentIdentity),
) -> Result<TestSession> {
    let network = LocalNetwork::start().await?;
    let wallet = TestKeypair::generate();
    network.fund(&wallet.address()).await?;

    let storage_path = std::env::temp_dir().join(format!(
        "spp-integration-tests-wallet-{}-{}.sqlite",
        std::process::id(),
        wallet.address()
    ));
    let _ = std::fs::remove_file(&storage_path);
    let storage_key = std::sync::Arc::new(
        stellar_private_payments::state::database_key::DatabaseKey::generate()?,
    );
    let storage = LocalStorage::open_encrypted(
        storage_path.to_str().context("storage path is not UTF-8")?,
        stellar_private_payments::state::database_key::DatabaseKey::new(**storage_key),
        stellar_private_payments::state::database_key::OpenPurpose::CreateNew,
    )?;
    build_session(
        &network,
        config,
        identity,
        wallet,
        storage_path,
        storage_key,
        storage,
    )
    .await
}

async fn build_session(
    network: &LocalNetwork,
    config: ContractConfig,
    identity: DeploymentIdentity,
    wallet: TestKeypair,
    storage_path: PathBuf,
    storage_key: std::sync::Arc<stellar_private_payments::state::database_key::DatabaseKey>,
    storage: LocalStorage,
) -> Result<TestSession> {
    let pool_entries: Vec<PoolConfigEntry> = config.enabled_pools().cloned().collect();
    let storage = storage.into();

    let lock = stellar_private_payments::circuit_lock(&std::fs::read_to_string(
        network::repo_root().join("deployments/testnet/circuits.json"),
    )?)?;
    let store = CircuitStore::open(network::repo_root().join("target/circuits-artifacts"), lock);
    store
        .ensure()
        .await
        .context("ensure circuit artifacts (run `make circuits` first)")?;

    let mut circuit_artifacts = Vec::new();
    let mut seen_stems = std::collections::HashSet::new();
    for pool_entry in &pool_entries {
        let stem = pool_entry.circuit_stem();
        if seen_stems.insert(stem.to_string()) {
            let artifacts = store
                .artifacts(&stem.to_string())
                .context("load circuit artifacts for a deployed pool")?;
            circuit_artifacts.push((stem, artifacts));
        }
    }
    let disclosure_artifacts = store
        .disclosure_artifacts()
        .context("load disclosure circuit artifacts")?
        .into_iter()
        .map(|(name, artifacts)| {
            find_circuit(name)
                .map(|circuit| (circuit, artifacts))
                .with_context(|| format!("unregistered disclosure circuit: {name}"))
        })
        .collect::<Result<Vec<_>>>()?;
    let key_ownership_artifacts = store
        .key_ownership_artifacts()
        .context("load key ownership circuit artifacts")?;
    let prover = LocalProver::from_all_artifacts(&circuit_artifacts, &disclosure_artifacts)
        .context("init local prover")?
        .with_key_ownership_artifacts(&key_ownership_artifacts)
        .context("init key ownership prover")?
        .into();

    let client = Client::init(network.rpc_url(), storage, prover, config, None)?;

    let reject_next_transaction = Arc::new(AtomicBool::new(false));
    let signer = WalletSigner {
        inner: LocalSigner::new(
            &wallet.secret(),
            NETWORK_PASSPHRASE,
            SignerAddress::new(wallet.address()),
        )?,
        reject_next_transaction: reject_next_transaction.clone(),
    }
    .into();
    let account = client.account(NoteOwnerAddress::new(wallet.address()), signer)?;
    account
        .derive_privacy_keys()
        .await
        .context("derive privacy keys")?;

    Ok(TestSession {
        account,
        wallet,
        identity,
        pool_contract_ids: pool_entries
            .into_iter()
            .map(|e| e.pool_contract_id)
            .collect(),
        storage_path,
        storage_key,
        reject_next_transaction,
    })
}

/// A [`LocalSigner`] that can reject a transaction the way a browser wallet
/// does when the user declines its prompt.
struct WalletSigner {
    inner: LocalSigner,
    reject_next_transaction: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl Signer for WalletSigner {
    fn signer_address(&self) -> SignerAddress {
        self.inner.signer_address()
    }

    async fn sign_transaction(
        &self,
        prepared: &PreparedTransaction,
    ) -> Result<SignedTransaction, Error> {
        self.sign_soroban_transaction(&prepared.soroban_tx).await
    }

    async fn sign_soroban_transaction(
        &self,
        prepared: &PreparedSorobanTx,
    ) -> Result<SignedTransaction, Error> {
        if self.reject_next_transaction.swap(false, Ordering::SeqCst) {
            return Err(Error::UserRejected("user declined the request".to_string()));
        }
        self.inner.sign_soroban_transaction(prepared).await
    }

    async fn sign_message(&self, message: &str) -> Result<KeyDerivationSignature, Error> {
        self.inner.sign_message(message).await
    }
}
