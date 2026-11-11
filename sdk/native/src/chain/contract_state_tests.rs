use super::*;
use crate::types::{AssetDescriptor, PoolConfigEntry};
use serde_json::{Value, json};
use stellar_xdr::{Limits, WriteXdr};
use wiremock::{Mock, MockServer, Request, ResponseTemplate, matchers::method};

fn contract_id(byte: u8) -> String {
    stellar_strkey::Contract([byte; 32])
        .to_string()
        .as_str()
        .to_owned()
}

fn address(byte: u8) -> xdr::ScVal {
    xdr::ScVal::Address(xdr::ScAddress::Contract(xdr::ContractId(xdr::Hash(
        [byte; 32],
    ))))
}

fn symbol(name: &str) -> xdr::ScVal {
    xdr::ScVal::Symbol(name.try_into().expect("symbol"))
}

fn enum_key(name: &str) -> xdr::ScVal {
    xdr::ScVal::Vec(Some(vec![symbol(name)].try_into().expect("key")))
}

fn map(fields: Vec<(&str, xdr::ScVal)>) -> xdr::ScVal {
    let mut entries: Vec<_> = fields
        .into_iter()
        .map(|(name, val)| xdr::ScMapEntry {
            key: symbol(name),
            val,
        })
        .collect();
    entries.sort_by(|a, b| a.key.cmp(&b.key));
    xdr::ScVal::Map(Some(entries.try_into().expect("map")))
}

/// Encode the persistent keys separately from the contract's instance settings.
fn ledger_entries(byte: u8, fields: Vec<(&str, xdr::ScVal)>) -> Vec<Value> {
    let xdr::ScVal::Address(contract) = address(byte) else {
        unreachable!("contract address");
    };
    let mut persistent = Vec::new();
    let mut instance = Vec::new();
    for (name, val) in fields {
        if matches!(name, "Admin" | "State" | "NextIndex") {
            persistent.push((enum_key(name), val));
        } else {
            instance.push((name, val));
        }
    }
    let mut storage: Vec<_> = instance
        .into_iter()
        .map(|(name, val)| xdr::ScMapEntry {
            key: enum_key(name),
            val,
        })
        .collect();
    storage.sort_by(|a, b| a.key.cmp(&b.key));
    persistent.push((
        xdr::ScVal::LedgerKeyContractInstance,
        xdr::ScVal::ContractInstance(xdr::ScContractInstance {
            executable: xdr::ContractExecutable::Wasm(xdr::Hash([0; 32])),
            storage: Some(storage.try_into().expect("instance storage")),
        }),
    ));
    persistent
        .into_iter()
        .map(|(key, val)| {
            let durability = xdr::ContractDataDurability::Persistent;
            let ledger_key = xdr::LedgerKey::ContractData(xdr::LedgerKeyContractData {
                contract: contract.clone(),
                key: key.clone(),
                durability,
            });
            let entry = xdr::LedgerEntryData::ContractData(xdr::ContractDataEntry {
                ext: xdr::ExtensionPoint::V0,
                contract: contract.clone(),
                key,
                durability,
                val,
            });
            json!({
                "key": ledger_key.to_xdr_base64(Limits::none()).expect("key XDR"),
                "xdr": entry.to_xdr_base64(Limits::none()).expect("entry XDR"),
                "lastModifiedLedgerSeq": 1,
            })
        })
        .collect()
}

/// Serve complete, valid pool and ASP state through the real RPC decoder.
async fn rpc_state(policies: &[(PolicyFlags, Option<xdr::ScVal>)]) -> (MockServer, StateFetcher) {
    let zero = || field_to_scval_u256(Field::ZERO);
    let mut entries = ledger_entries(
        101,
        vec![
            ("Admin", address(100)),
            ("NextIndex", xdr::ScVal::U64(0)),
            ("Levels", xdr::ScVal::U32(32)),
            ("Root", zero()),
        ],
    );
    entries.extend(ledger_entries(
        102,
        vec![("Admin", address(100)), ("Root", zero())],
    ));
    let mut pools = Vec::new();
    for (index, (configured, on_chain)) in policies.iter().enumerate() {
        let byte = u8::try_from(index.checked_add(1).expect("pool index")).expect("pool byte");
        pools.push(PoolConfigEntry {
            pool_contract_id: contract_id(byte),
            token_contract_id: contract_id(103),
            deployment_ledger: 1,
            enabled: true,
            asset: AssetDescriptor::Native,
            policy_flags: *configured,
            gvk_mode: GvkMode::Off,
            gvk_authority_pub_key: None,
        });
        let mut fields = vec![
            ("Admin", address(100)),
            ("Token", address(103)),
            ("Verifier", address(104)),
            ("ASPMembership", address(101)),
            ("ASPNonMembership", address(102)),
            ("Levels", xdr::ScVal::U32(32)),
            ("MaximumDepositAmount", zero()),
            (
                "State",
                map(vec![
                    ("next_index", xdr::ScVal::U64(0)),
                    (
                        "roots",
                        xdr::ScVal::Vec(Some(vec![zero()].try_into().expect("roots"))),
                    ),
                ]),
            ),
        ];
        if let Some(flags) = on_chain {
            fields.push(("PolicyFlags", flags.clone()));
        }
        entries.extend(ledger_entries(byte, fields));
    }
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(move |request: &Request| {
            let body: Value = request.body_json().expect("JSON-RPC request");
            assert_eq!(body["method"], "getLedgerEntries");
            let keys = body["params"]["keys"].as_array().expect("requested keys");
            let requested: Vec<_> = entries
                .iter()
                .filter(|entry| keys.contains(&entry["key"]))
                .collect();
            ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": { "latestLedger": 42, "entries": requested },
            }))
        })
        .mount(&server)
        .await;
    let config = ContractConfig {
        network: "test".to_string(),
        kdf_domain: "tests".to_string(),
        asp_membership: contract_id(101),
        asp_non_membership: contract_id(102),
        pools,
        ..Default::default()
    };
    let fetcher =
        StateFetcher::new(Client::new(&server.uri()).expect("RPC"), config).expect("state fetcher");
    (server, fetcher)
}

#[tokio::test]
async fn matching_policies_load_through_both_fetch_paths() {
    for flags in PolicyFlags::all_flags() {
        let (_server, fetcher) = rpc_state(&[(flags, Some(xdr::ScVal::U32(flags.bits())))]).await;
        let single = fetcher
            .contracts_data_for_pool(&contract_id(1))
            .await
            .expect("single pool");
        let all = fetcher.all_contracts_data().await.expect("all pools");
        for state in [single, all] {
            assert_eq!(state.pools.len(), 1);
            assert_eq!(state.pools[0].policy_flags, flags);
            assert_eq!(state.pools[0].ledger, 42);
        }
    }
}

#[tokio::test]
async fn policy_mismatches_propagate_through_both_fetch_paths() {
    for (configured, on_chain) in [
        (PolicyFlags::BLOCKLIST, PolicyFlags::ALLOWLIST),
        (
            PolicyFlags::BLOCKLIST,
            PolicyFlags::ALLOWLIST | PolicyFlags::BLOCKLIST,
        ),
        (PolicyFlags::EMPTY, PolicyFlags::BLOCKLIST),
        (PolicyFlags::BLOCKLIST, PolicyFlags::EMPTY),
    ] {
        let (_server, fetcher) =
            rpc_state(&[(configured, Some(xdr::ScVal::U32(on_chain.bits())))]).await;
        let expected = format!(
            "pool {} policy flags mismatch: config says {configured:?}, chain says {on_chain:?}",
            contract_id(1),
        );
        let single = fetcher
            .contracts_data_for_pool(&contract_id(1))
            .await
            .expect_err("single mismatch");
        let all = fetcher
            .all_contracts_data()
            .await
            .expect_err("aggregate mismatch");
        assert_eq!(single.to_string(), expected);
        assert_eq!(all.to_string(), expected);
    }
}

#[tokio::test]
async fn a_mismatching_pool_does_not_prevent_reading_another_pool() {
    let (_server, fetcher) = rpc_state(&[
        (PolicyFlags::EMPTY, Some(xdr::ScVal::U32(0))),
        (PolicyFlags::BLOCKLIST, Some(xdr::ScVal::U32(1))),
    ])
    .await;
    fetcher
        .contracts_data_for_pool(&contract_id(1))
        .await
        .expect("matching pool still reads");
    let error = fetcher
        .all_contracts_data()
        .await
        .expect_err("one mismatch fails aggregate read");
    assert!(
        error
            .to_string()
            .contains(&format!("pool {} policy flags mismatch", contract_id(2))),
        "{error}"
    );
}

#[tokio::test]
async fn invalid_policy_storage_keeps_existing_decode_errors() {
    for (stored, expected) in [
        (None, "missing PolicyFlags state key"),
        (Some(xdr::ScVal::U32(4)), "unsupported policy flags"),
        (Some(xdr::ScVal::Bool(false)), "Bool(false)"),
    ] {
        let (_server, fetcher) = rpc_state(&[(PolicyFlags::EMPTY, stored)]).await;
        let error = fetcher
            .contracts_data_for_pool(&contract_id(1))
            .await
            .expect_err("invalid policy state");
        assert!(error.to_string().contains(expected), "{error}");
        assert!(
            !error.to_string().contains("policy flags mismatch"),
            "{error}"
        );
    }
}

#[tokio::test]
async fn pool_info_preserves_the_mismatch_in_the_existing_error_type() {
    use crate::{
        Error,
        signer::{LocalSigner, SignerHandle},
        storage::StorageHandle,
        types::{NoteOwnerAddress, SignerAddress},
    };

    let (server, fetcher) = rpc_state(&[(PolicyFlags::BLOCKLIST, Some(xdr::ScVal::U32(1)))]).await;
    let dir = tempfile::tempdir().expect("wallet directory");
    let storage = crate::state::test_local_storage(
        dir.path()
            .join("wallet.sqlite")
            .to_str()
            .expect("wallet path"),
    )
    .expect("storage");
    let owner = stellar_strkey::ed25519::PublicKey([1; 32]).to_string();
    let signer = LocalSigner::new(
        "SADQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQP54X",
        "test",
        SignerAddress::new(owner.as_str()),
    )
    .expect("signer");
    let client = crate::Client::init_readonly(
        server.uri(),
        StorageHandle::from(storage),
        fetcher.config,
        None,
    )
    .expect("client");
    let pool = client
        .account(
            NoteOwnerAddress::new(owner.as_str()),
            SignerHandle::from(signer),
        )
        .expect("account")
        .pool(contract_id(1))
        .expect("pool");
    let error = pool.pool_info().await.expect_err("policy mismatch");
    assert!(matches!(&error, Error::Other(_)), "{error:?}");
    assert_eq!(
        error.to_string(),
        format!(
            "fetch pool state: pool {} policy flags mismatch: config says PolicyFlags(2), chain says PolicyFlags(1)",
            contract_id(1),
        )
    );
}
