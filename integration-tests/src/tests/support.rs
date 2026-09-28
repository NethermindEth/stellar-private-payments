//! Shared setup for tests: each test deploys the one pool it needs on the
//! shared network, then opens its own wallet session against it.

use anyhow::{Context, Result};
use stellar_private_payments::{
    Account, CircuitStore, Client, Handle, LocalProver, LocalSigner, LocalStorage, PrivatePool,
    Prover, Signer, Storage,
    types::{ContractConfig, NoteOwnerAddress, PoolConfigEntry, SignerAddress},
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
}

impl TestSession {
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
}

pub async fn setup_default() -> Result<TestSession> {
    setup(&[PoolOptions::NONE]).await
}

/// Deploy every entry of `pools` together (one `deploy.sh` invocation, so
/// they share ASP membership/non-membership contracts).
pub async fn setup(pools: &[PoolOptions]) -> Result<TestSession> {
    let network = LocalNetwork::start().await?;
    let (config, identity) = network
        .deploy(MAX_DEPOSIT_STROOPS, ASP_LEVELS, POOL_LEVELS, pools)
        .await?;
    let pool_entries: Vec<PoolConfigEntry> = config.enabled_pools().cloned().collect();
    build_session(&network, config, identity, pool_entries).await
}

async fn build_session(
    network: &LocalNetwork,
    config: ContractConfig,
    identity: DeploymentIdentity,
    pool_entries: Vec<PoolConfigEntry>,
) -> Result<TestSession> {
    let wallet = TestKeypair::generate();
    network.fund(&wallet.address()).await?;

    let storage_path = std::env::temp_dir().join(format!(
        "spp-integration-tests-wallet-{}-{}.sqlite",
        std::process::id(),
        wallet.address()
    ));
    let _ = std::fs::remove_file(&storage_path);
    let storage = Handle::from_box(Box::new(LocalStorage::open(
        storage_path.to_str().context("storage path is not UTF-8")?,
    )?) as Box<dyn Storage>);

    let store = CircuitStore::open(network::repo_root().join("target/circuits-artifacts"));
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
    let prover = Handle::from_box(Box::new(
        LocalProver::from_artifacts(&circuit_artifacts).context("init local prover")?,
    ) as Box<dyn Prover>);

    let client = Client::init(network.rpc_url(), storage, prover, config, None)?;

    let signer = Handle::from_box(Box::new(LocalSigner::new(
        &wallet.secret(),
        NETWORK_PASSPHRASE,
        SignerAddress::new(wallet.address()),
    )?) as Box<dyn Signer>);
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
    })
}
