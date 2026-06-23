//! Test fixtures for [`PrivatePool`].

use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::Result;

use stellar_private_payments_sdk::{
    PrivatePool, PrivatePoolConfig, ProverArtifacts, TransferRecipient,
    types::{NoteAmount, NotePublicKey},
};
use types::{EncryptionPublicKey, Field};

use crate::seed;

static NOTE_SALT: AtomicUsize = AtomicUsize::new(0);

const TEST_CONFIG_JSON: &str = r#"{
    "network": "test",
    "deployer": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
    "admin": "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
    "asp_membership": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
    "asp_non_membership": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
    "verifier": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
    "pools": [{
        "poolContractId": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
        "tokenContractId": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
        "deploymentLedger": 1,
        "enabled": true,
        "asset": {"kind": "native"}
    }]
}"#;

const POOL_CONTRACT_ID: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";
const USER_ADDRESS: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

pub fn test_pool(wallet: Option<&[u64]>) -> Result<PrivatePool> {
    let db_path =
        std::env::temp_dir().join(format!("stellar-sdk-test-{}.sqlite", std::process::id()));
    let _ = std::fs::remove_file(&db_path);

    let notes: Vec<_> = wallet
        .unwrap_or_default()
        .iter()
        .copied()
        .map(test_note)
        .collect();
    seed::seed_notes(&db_path, POOL_CONTRACT_ID, USER_ADDRESS, &notes)?;

    let mut pool = PrivatePool::new(PrivatePoolConfig {
        rpc_url: "https://soroban-testnet.stellar.org".into(),
        contract_config: serde_json::from_str(TEST_CONFIG_JSON)?,
        pool_contract_id: POOL_CONTRACT_ID.into(),
        user_address: USER_ADDRESS.into(),
        storage_path: db_path.to_string_lossy().into_owned(),
        prover_artifacts: test_prover_artifacts()?,
    })?;
    pool.initialize()?;

    Ok(pool)
}

pub fn test_recipient() -> TransferRecipient {
    TransferRecipient {
        note_public_key: NotePublicKey::parse(
            "0x0000000000000000000000000000000000000000000000000000000000000001",
        )
        .expect("note public key"),
        encryption_public_key: EncryptionPublicKey::parse(
            "0x0000000000000000000000000000000000000000000000000000000000000002",
        )
        .expect("encryption public key"),
    }
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

fn test_note(amount: u64) -> (Field, NoteAmount) {
    let amount = NoteAmount::from(u128::from(amount));
    let salt = NOTE_SALT.fetch_add(1, Ordering::Relaxed);
    let commitment_value = u128::from(amount)
        .checked_add(1_000)
        .and_then(|base| base.checked_add(salt as u128))
        .expect("test note commitment value overflow");
    (Field::from(NoteAmount::from(commitment_value)), amount)
}
