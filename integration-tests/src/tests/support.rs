//! Shared setup for tests: one pool, deployed once on the shared network,
//! that every test opens its own wallet session against.

use anyhow::{Context, Result};
use stellar_private_payments::{
    Account, CircuitStore, Client, Handle, LocalProver, LocalSigner, LocalStorage, PrivatePool,
    Prover, Signer,
    types::{ContractConfig, KeyDerivationSignature, NoteOwnerAddress, SignerAddress},
    zk::encryption::{self, KEY_DERIVATION_MESSAGE},
};
use tokio::sync::OnceCell;

use crate::{
    keypair::TestKeypair,
    network::{self, LocalNetwork, NETWORK_PASSPHRASE},
};

const MAX_DEPOSIT_STROOPS: u128 = 1_000_000_000_000;

static DEPLOYMENT: OnceCell<ContractConfig> = OnceCell::const_new();

/// Deploy the suite's one pool, once, on the shared network.
async fn shared_deployment() -> Result<&'static ContractConfig> {
    DEPLOYMENT
        .get_or_try_init(|| async {
            let network = LocalNetwork::shared().await?;
            let deployer = TestKeypair::generate();
            network.fund(&deployer.address()).await?;
            network
                .deploy(&deployer.secret(), MAX_DEPOSIT_STROOPS)
                .await
        })
        .await
}

pub struct TestSession {
    pub account: Account<LocalStorage>,
    pub wallet: TestKeypair,
    pool_contract_id: String,
}

impl TestSession {
    pub fn pool(&self) -> Result<PrivatePool<LocalStorage>> {
        Ok(self.account.pool(&self.pool_contract_id)?)
    }
}

pub async fn setup() -> Result<TestSession> {
    let network = LocalNetwork::shared().await?;
    let config = shared_deployment().await?.clone();
    let pool_entry = config
        .enabled_pools()
        .next()
        .context("deployment has no enabled pools")?
        .clone();

    let wallet = TestKeypair::generate();
    network.fund(&wallet.address()).await?;

    let storage_path = std::env::temp_dir().join(format!(
        "spp-integration-test-{}-{}.sqlite",
        std::process::id(),
        wallet.address()
    ));
    let _ = std::fs::remove_file(&storage_path);
    let storage = LocalStorage::open(storage_path.to_str().context("storage path is not UTF-8")?)?;
    save_privacy_keys(&storage, &wallet, &config.network)?;

    let store = CircuitStore::open(network::repo_root().join("target/circuits-artifacts"));
    store
        .ensure()
        .await
        .context("ensure circuit artifacts (run `make circuits` first)")?;
    let artifacts = store
        .artifacts(&pool_entry.circuit_stem().to_string())
        .context("load circuit artifacts for the deployed pool")?;
    let prover = Handle::from_box(Box::new(
        LocalProver::from_artifacts(&[(pool_entry.circuit_stem(), artifacts)])
            .context("init local prover")?,
    ) as Box<dyn Prover>);

    let client = Client::init(network.rpc_url(), storage, prover, config, None)?;

    let signer = Handle::from_box(Box::new(LocalSigner::new(
        &wallet.secret(),
        NETWORK_PASSPHRASE,
        SignerAddress::new(wallet.address()),
    )?) as Box<dyn Signer>);
    let account = client.account(
        NoteOwnerAddress::new(wallet.address()),
        SignerAddress::new(wallet.address()),
        signer,
    )?;

    Ok(TestSession {
        account,
        wallet,
        pool_contract_id: pool_entry.pool_contract_id,
    })
}

fn save_privacy_keys(storage: &LocalStorage, wallet: &TestKeypair, network: &str) -> Result<()> {
    let signature = KeyDerivationSignature(wallet.sign(KEY_DERIVATION_MESSAGE.as_bytes()).to_vec());
    let (note_keypair, encryption_keypair) =
        encryption::derive_encryption_and_note_keypairs(signature.clone())?;
    let membership_blinding = encryption::derive_membership_blinding(&signature, network)?;
    storage.storage_mut().save_encryption_and_note_keypairs(
        &wallet.address(),
        &note_keypair,
        &encryption_keypair,
        &membership_blinding,
    )?;
    Ok(())
}
