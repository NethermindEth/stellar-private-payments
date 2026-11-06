//! Test fixtures for [`stellar_private_payments::blocking::PrivatePool`].

use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::Result;
use stellar_private_payments::{
    LocalProver, LocalSigner, LocalStorage, ProverHandle, SignerHandle,
    blocking::{Account, Client, PrivatePool},
    types::{
        CircuitStem, ContractConfig, EncryptionPublicKey, Field, GvkMode, NoteAmount,
        NoteOwnerAddress, NotePublicKey, PolicyFlags, SignerAddress, TransferRecipient,
    },
};

use crate::seed::{self, POOL_MERKLE_LEVELS};

static NOTE_SALT: AtomicUsize = AtomicUsize::new(0);

const TEST_CONFIG_JSON: &str = r#"{
    "network": "test",
    "kdf_domain": "tests",
    "deployer": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
    "admin": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
    "asp_membership": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
    "asp_non_membership": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
    "verifiers": {
        "AB": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
    },
    "public_key_registry": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
    "pools": [{
        "poolContractId": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
        "tokenContractId": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
        "deploymentLedger": 1,
        "enabled": true,
            "policyFlags": ["allowlist", "blocklist"],
        "asset": {"kind": "native"}
    }]
}"#;

const POOL_CONTRACT_ID: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";
const TOKEN_CONTRACT_ID: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";
const ASP_MEMBERSHIP_CONTRACT_ID: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";
const USER_ADDRESS: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
/// Ed25519 secret for `SigningKey::from_bytes(&[7u8; 32])` (stellar signer unit
/// tests).
const TEST_SIGNER_SECRET: &str = "SADQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQP54X";

pub use crate::seed::TEST_NETWORK;

pub fn test_account(wallet: Option<&[u64]>) -> Result<Account> {
    Ok(test_client_and_account(wallet)?.1)
}

pub fn test_pool(wallet: Option<&[u64]>) -> Result<PrivatePool> {
    Ok(test_client_and_account(wallet)?.1.pool(POOL_CONTRACT_ID)?)
}

fn test_client_and_account(wallet: Option<&[u64]>) -> Result<(Client, Account)> {
    static RUN: AtomicUsize = AtomicUsize::new(0);
    let db_path = std::env::temp_dir().join(format!(
        "stellar-sdk-test-{}-{}.sqlite",
        std::process::id(),
        RUN.fetch_add(1, Ordering::Relaxed),
    ));
    let _ = std::fs::remove_file(&db_path);

    let amounts: Vec<u64> = wallet.unwrap_or_default().to_vec();
    let setup_timing = FixtureTiming::new("wallet/database seeding");
    seed::seed_prove_wallet(
        &db_path,
        POOL_CONTRACT_ID,
        TOKEN_CONTRACT_ID,
        ASP_MEMBERSHIP_CONTRACT_ID,
        USER_ADDRESS,
        TEST_NETWORK,
        &amounts,
    )?;

    drop(setup_timing);

    let storage_path = db_path.to_string_lossy().into_owned();
    let storage = LocalStorage::open_encrypted(
        &storage_path,
        seed::database_key(),
        stellar_private_payments::state::database_key::OpenPurpose::OpenExisting,
    )?;
    let prover = test_prover()?;
    let contract_config: ContractConfig = serde_json::from_str(TEST_CONFIG_JSON)?;
    let mut client = Client::init(
        "https://soroban-testnet.stellar.org",
        storage,
        prover,
        contract_config,
        None,
    )?;
    // Mode flip only — tests do not run the indexer loop.
    #[allow(unused_must_use)]
    {
        let _ = client.background_sync()?;
    }
    let account = client.account(NoteOwnerAddress::new(USER_ADDRESS), test_signer()?)?;

    Ok((client, account))
}

pub fn test_recipient() -> TransferRecipient {
    TransferRecipient::keys(
        NotePublicKey::parse("0x0000000000000000000000000000000000000000000000000000000000000001")
            .expect("note public key"),
        EncryptionPublicKey::parse(
            "0x0000000000000000000000000000000000000000000000000000000000000002",
        )
        .expect("encryption public key"),
    )
}

fn test_signer() -> Result<SignerHandle> {
    Ok(SignerHandle::from(LocalSigner::new(
        TEST_SIGNER_SECRET,
        "Test SDF Network ; September 2015",
        SignerAddress::new(USER_ADDRESS),
    )?))
}

// Share the real engine, never wallet/database/client state. Dedicated
// constructor and artifact tests continue to initialize their own engines.
#[cfg(not(target_arch = "wasm32"))]
fn test_prover() -> Result<ProverHandle> {
    static PROVER: std::sync::OnceLock<Result<ProverHandle, String>> = std::sync::OnceLock::new();
    PROVER
        .get_or_init(|| new_test_prover().map_err(|error| format!("{error:#}")))
        .as_ref()
        .cloned()
        .map_err(|error| anyhow::anyhow!("{error}"))
}

#[cfg(target_arch = "wasm32")]
fn test_prover() -> Result<ProverHandle> {
    thread_local! {
        static PROVER: std::cell::LazyCell<Result<ProverHandle, String>> =
            std::cell::LazyCell::new(|| new_test_prover().map_err(|error| format!("{error:#}")));
    }
    PROVER.with(|prover| {
        prover
            .as_ref()
            .cloned()
            .map_err(|error| anyhow::anyhow!("{error}"))
    })
}

fn new_test_prover() -> Result<ProverHandle> {
    let _timing = FixtureTiming::new("prover initialization");
    let artifacts = test_prover_artifacts()?;
    let stem = CircuitStem::transact(
        PolicyFlags::ALLOWLIST | PolicyFlags::BLOCKLIST,
        GvkMode::Off,
    );
    Ok(ProverHandle::from(LocalProver::from_artifacts(&[(
        stem, artifacts,
    )])?))
}

// Opt-in timings stay in test fixtures and do not affect SDK behavior.
struct FixtureTiming {
    label: &'static str,
    start: Option<std::time::Instant>,
}

impl FixtureTiming {
    fn new(label: &'static str) -> Self {
        Self {
            label,
            start: std::env::var_os("SPP_TEST_TIMINGS").map(|_| std::time::Instant::now()),
        }
    }
}

impl Drop for FixtureTiming {
    fn drop(&mut self) {
        if let Some(start) = self.start {
            eprintln!("fixture timing: {}: {:?}", self.label, start.elapsed());
        }
    }
}

fn test_prover_artifacts() -> Result<stellar_private_payments::types::ProverArtifacts> {
    let _timing = FixtureTiming::new("artifact loading");
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let circuits = repo.join("target/circuits-artifacts");
    let keys = repo.join("deployments/testnet/circuit_keys");
    Ok(stellar_private_payments::types::ProverArtifacts {
        proving_key: std::fs::read(keys.join("policy_tx_2_2_AB_proving_key.bin"))?,
        circuit_graph: std::fs::read(keys.join("policy_tx_2_2_AB.graph.bin"))?,
        circuit_r1cs: std::fs::read(circuits.join("policy_tx_2_2_AB.r1cs"))?,
    })
}

#[allow(dead_code)]
fn test_note(amount: u64) -> (Field, NoteAmount) {
    let amount = NoteAmount::from(u128::from(amount));
    let salt = NOTE_SALT.fetch_add(1, Ordering::Relaxed);
    let commitment_value = u128::from(amount)
        .checked_add(1_000)
        .and_then(|base| base.checked_add(salt as u128))
        .expect("test note commitment value overflow");
    (Field::from(NoteAmount::from(commitment_value)), amount)
}

#[allow(dead_code)]
pub const TEST_POOL_MERKLE_LEVELS: u32 = POOL_MERKLE_LEVELS;
