//! Test fixtures for [`stellar_private_payments_sdk::blocking::PrivatePool`].

use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::Result;

use stellar_private_payments_sdk::{
    LocalSigner, PrivatePoolConfig, ProverArtifacts, Signer, TransferRecipient,
    blocking::PrivatePool,
    types::{NoteAmount, NotePublicKey},
};
use types::{EncryptionPublicKey, Field};

use crate::seed::{self, POOL_MERKLE_LEVELS};

static NOTE_SALT: AtomicUsize = AtomicUsize::new(0);

const TEST_CONFIG_JSON: &str = r#"{
    "network": "test",
    "deployer": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
    "admin": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
    "asp_membership": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
    "asp_non_membership": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
    "verifier": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
    "public_key_registry": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
    "pools": [{
        "poolContractId": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
        "tokenContractId": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
        "deploymentLedger": 1,
        "enabled": true,
        "asset": {"kind": "native"}
    }]
}"#;

const POOL_CONTRACT_ID: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";
const ASP_MEMBERSHIP_CONTRACT_ID: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";
const USER_ADDRESS: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
/// Ed25519 secret for `SigningKey::from_bytes(&[7u8; 32])` (stellar signer unit
/// tests).
const TEST_SIGNER_SECRET: &str = "SADQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQP54X";

pub use crate::seed::TEST_NETWORK;

pub fn test_session(wallet: Option<&[u64]>) -> Result<PrivatePool> {
    static RUN: AtomicUsize = AtomicUsize::new(0);
    let db_path = std::env::temp_dir().join(format!(
        "stellar-sdk-test-{}-{}.sqlite",
        std::process::id(),
        RUN.fetch_add(1, Ordering::Relaxed),
    ));
    let _ = std::fs::remove_file(&db_path);

    let amounts: Vec<u64> = wallet.unwrap_or_default().to_vec();
    seed::seed_prove_wallet(
        &db_path,
        POOL_CONTRACT_ID,
        ASP_MEMBERSHIP_CONTRACT_ID,
        USER_ADDRESS,
        TEST_NETWORK,
        &amounts,
    )?;

    let pool = PrivatePool::open_local(
        PrivatePoolConfig {
            rpc_url: "https://soroban-testnet.stellar.org".into(),
            contract_config: serde_json::from_str(TEST_CONFIG_JSON)?,
            pool_contract_id: POOL_CONTRACT_ID.into(),
            user_address: USER_ADDRESS.into(),
            storage_path: db_path.to_string_lossy().into_owned(),
            prover_artifacts: test_prover_artifacts()?,
        },
        test_signer()?,
    )?;

    Ok(pool)
}

pub fn test_pool(wallet: Option<&[u64]>) -> Result<PrivatePool> {
    test_session(wallet)
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

fn test_signer() -> Result<Box<dyn Signer>> {
    Ok(Box::new(LocalSigner::new(
        TEST_SIGNER_SECRET,
        "Test SDF Network ; September 2015",
        USER_ADDRESS,
    )?))
}

fn test_prover_artifacts() -> Result<ProverArtifacts> {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".into());
    let circuits = repo.join("target/circuits-artifacts").join(profile);
    Ok(ProverArtifacts {
        proving_key: std::fs::read(
            repo.join("deployments/testnet/circuit_keys/policy_tx_2_2_proving_key.bin"),
        )?,
        circuit_wasm: std::fs::read(circuits.join("policy_tx_2_2.wasm"))?,
        circuit_r1cs: std::fs::read(circuits.join("policy_tx_2_2.r1cs"))?,
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
