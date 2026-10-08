mod common;

use bootnode::{Bootnode, DeploymentSpec, InMemory, messages::Event};
use common::*;
use serde_json::{Value, json};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use stellar_private_payments::{
    Client, LocalStorage, Storage, StorageHandle,
    types::{ContractConfig, Field, KeyDerivationSignature, NoteAmount},
    zk::{crypto, encryption},
};
use stellar_xdr::{Limits, ScMap, ScMapEntry, ScVal, UInt256Parts, WriteXdr};

fn symbol(name: &str) -> ScVal {
    ScVal::Symbol(name.try_into().expect("symbol"))
}
fn encoded(value: ScVal) -> String {
    value.to_xdr_base64(Limits::none()).expect("XDR")
}

// Exercise actual SDK filtering, bootnode HTTP, retention handoff, SQLite event
// processing and note decryption. Only the chain RPC and confirmed event are
// seeded.
#[tokio::test]
async fn deposited_note_recovers_through_bootnode_and_survives_reopen() {
    recover_deposit(true, 40430).await;
}

#[tokio::test]
async fn current_deployment_recovers_a_deposit_and_survives_reopen() {
    recover_deposit(false, 40431).await;
}

async fn recover_deposit(extra_pools: bool, port: u16) {
    let mut config: ContractConfig = serde_json::from_str(include_str!(
        "../../../deployments/testnet/deployments.json"
    ))
    .expect("deployment");
    // More than five IDs forces the SDK to send multiple filters.
    for id in config
        .verifiers
        .values()
        .filter(|_| extra_pools)
        .cloned()
        .collect::<Vec<_>>()
    {
        let mut pool = config.pools[0].clone();
        pool.pool_contract_id = id;
        config.pools.push(pool);
    }
    for pool in &mut config.pools {
        pool.deployment_ledger = GENESIS_LEDGER;
    }
    if extra_pools {
        assert!(config.all_contract_ids().len() > 5);
    }
    let signature = KeyDerivationSignature(vec![1; 64]);
    let (note_keys, enc_keys) =
        encryption::derive_encryption_and_note_keypairs(signature.clone()).expect("keys");
    let membership =
        encryption::derive_membership_blinding(&signature, "testnet").expect("membership");
    let amount = NoteAmount::from(5);
    let blinding = Field::from(NoteAmount::from(7));
    let commitment = crypto::compute_commitment(
        &Field::from(amount).to_le_bytes(),
        note_keys.public.as_ref(),
        &blinding.to_le_bytes(),
    )
    .expect("commitment");
    let commitment =
        Field::try_from_le_bytes(commitment.try_into().expect("32 bytes")).expect("field");
    let be = commitment.to_be_bytes();
    let commitment_xdr = ScVal::U256(UInt256Parts {
        hi_hi: u64::from_be_bytes(be[0..8].try_into().expect("limb")),
        hi_lo: u64::from_be_bytes(be[8..16].try_into().expect("limb")),
        lo_hi: u64::from_be_bytes(be[16..24].try_into().expect("limb")),
        lo_lo: u64::from_be_bytes(be[24..32].try_into().expect("limb")),
    });
    let encrypted =
        encryption::encrypt_output_note(&enc_keys.public, amount, &blinding).expect("encrypt");
    let event: Event = serde_json::from_value(json!({
        "type":"contract", "ledger": GENESIS_LEDGER + 100,
        "ledgerClosedAt":"2024-01-01T00:00:00Z", "contractId":config.pools[0].pool_contract_id,
        "id":"0000000000000000001-0000000000", "inSuccessfulContractCall":true,
        "topic":[encoded(symbol("new_commitment_event")), encoded(commitment_xdr)],
        "value":encoded(ScVal::Map(Some(ScMap(vec![
            ScMapEntry { key:symbol("encrypted_output"), val:ScVal::Bytes(encrypted.try_into().expect("bytes")) },
            ScMapEntry { key:symbol("index"), val:ScVal::U32(0) },
        ].try_into().expect("map")))))
    })).expect("event");
    let gap_requests = Arc::new(AtomicUsize::new(0));
    let gaps = gap_requests.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let upstream_url = format!("http://{}", listener.local_addr().expect("address"));
    let app = axum::Router::new().route("/", axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
        let gaps = gaps.clone();
        async move {
            let body = if request["method"] == "getLatestLedger" {
                json!({"result":{"id":"tip","protocolVersion":22,"sequence":NETWORK_TIP}})
            } else if request["params"]["startLedger"].as_u64().is_some_and(|l| l < u64::from(HANDOFF_FROM_LEDGER)) {
                gaps.fetch_add(1, Ordering::SeqCst);
                json!({"error":{"code":-32602,"message":format!("startLedger must be within the ledger range: {HANDOFF_FROM_LEDGER} - {NETWORK_TIP}")}})
            } else {
                json!({"result":{"events":[],"cursor":"rpc-tip","latestLedger":NETWORK_TIP,
                    "latestLedgerCloseTime":"","oldestLedger":HANDOFF_FROM_LEDGER,"oldestLedgerCloseTime":""}})
            };
            let mut body = body;
            body["jsonrpc"] = "2.0".into(); body["id"] = request["id"].clone();
            axum::Json(body)
        }
    }));
    let upstream = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("upstream");
    });
    let archive = Arc::new(InMemory::with_deployment_id("retention-test"));
    seed_events(&archive, &[event]).await;
    seed_tip(&archive, NETWORK_TIP).await;
    seed_archive_ready(&archive).await;
    let mut cfg = test_config(port, NETWORK_TIP);
    cfg.upstream_rpc_url = upstream_url.parse().expect("URL");
    let bootnode = Bootnode::setup_with_deployment(
        cfg,
        archive,
        prom_handle(),
        DeploymentSpec::from_config(&config).expect("spec"),
    )
    .await
    .expect("setup");
    let server = tokio::spawn(async move {
        bootnode.serve().await.expect("serve");
    });
    let bootnode_url = format!("http://127.0.0.1:{port}");
    wait_listening(&reqwest::Client::new(), &bootnode_url).await;
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let directory = std::env::temp_dir().join(format!(
        "spp-retention-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir(&directory).expect("directory");
    let _cleanup = Cleanup(directory.clone());
    let path = directory.join("wallet.db");
    for reopen in [false, true] {
        let storage = LocalStorage::open(path.to_str().expect("path")).expect("storage");
        if !reopen {
            storage
                .save_private_keys(
                    "GTESTACCOUNT",
                    &config.kdf_domain,
                    &note_keys,
                    &enc_keys,
                    &membership,
                )
                .await
                .expect("save keys");
        }
        let client = Client::init_readonly(
            &upstream_url,
            StorageHandle::from(storage),
            config.clone(),
            Some(bootnode_url.clone()),
        )
        .expect("client");
        let result = tokio::time::timeout(Duration::from_secs(5), client.sync()).await;
        if !matches!(result, Ok(Ok(()))) {
            server.abort();
            upstream.abort();
        }
        result
            .expect("sync must finish")
            .expect("recover from retention gap");
        let notes = client
            .storage()
            .notes(
                &config.pools[0].pool_contract_id,
                "GTESTACCOUNT",
                &config.kdf_domain,
            )
            .await
            .expect("notes");
        assert_eq!(notes.len(), 1, "one recovered note, including after reopen");
        let balances = client
            .storage()
            .list_portfolio_balances(
                "GTESTACCOUNT",
                &config.kdf_domain,
                &config.portfolio_pools(),
            )
            .await
            .expect("balances");
        assert_eq!(balances.len(), config.portfolio_pools().len());
        for balance in balances {
            if balance.pool_contract_id == config.pools[0].pool_contract_id {
                assert_eq!(balance.amount, amount);
                assert_eq!(balance.note_count, 1);
            } else {
                assert_eq!(balance.amount, NoteAmount::from(0));
                assert_eq!(balance.note_count, 0);
            }
        }
    }
    assert!(
        gap_requests.load(Ordering::SeqCst) > 0,
        "must exercise retention gap"
    );
    server.abort();
    upstream.abort();
}
