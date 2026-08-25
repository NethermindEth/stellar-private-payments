//! Build and simulate pool contract transactions for signing/submission.

use crate::types::{ExtData, NoteOwnerAddress, SignerAddress};
use anyhow::{Result, anyhow};
use stellar_xdr::{self as xdr};

use super::{
    contract_state::{OnchainProofPublicInputs, PreparedSorobanTx, StateFetcher},
    soroban_encode::{
        BASE_FEE, pool_ext_data_to_scval, pool_gvk_proof_to_scval, pool_proof_to_scval,
        register_account_to_scval,
    },
};

/// Prover output needed to prepare a pool `transact` invocation.
#[derive(Debug, Clone)]
pub(crate) struct PoolTransactInput {
    pub proof_uncompressed: Vec<u8>,
    pub ext_data: ExtData,
    pub public: OnchainProofPublicInputs,
}

impl StateFetcher {
    /// Simulates `transact` and returns unsigned XDR + auth entries for the
    /// wallet.
    pub(crate) async fn prepare_pool_transact(
        &self,
        pool_contract_id: &str,
        input: &PoolTransactInput,
        source_account: &SignerAddress,
    ) -> Result<PreparedSorobanTx> {
        let source_account = source_account.as_str();
        self.enabled_pool_for(pool_contract_id)?;
        let proof_scval = if let Some(output_gvk_ciphertexts) = &input.public.output_gvk_ciphertexts
        {
            let input_gvk_ciphertexts =
                input.public.input_gvk_ciphertexts.as_deref().unwrap_or(&[]);
            pool_gvk_proof_to_scval(
                &input.proof_uncompressed,
                input.public.root,
                &input.public.input_nullifiers,
                input.public.output_commitment0,
                input.public.output_commitment1,
                input.public.public_amount,
                input.public.ext_data_hash_be,
                input.public.asp_membership_root,
                input.public.asp_non_membership_root,
                output_gvk_ciphertexts,
                input_gvk_ciphertexts,
            )?
        } else {
            pool_proof_to_scval(
                &input.proof_uncompressed,
                input.public.root,
                &input.public.input_nullifiers,
                input.public.output_commitment0,
                input.public.output_commitment1,
                input.public.public_amount,
                input.public.ext_data_hash_be,
                input.public.asp_membership_root,
                input.public.asp_non_membership_root,
            )?
        };
        let ext_scval = pool_ext_data_to_scval(&input.ext_data)?;
        let sender_scval = xdr::ScVal::Address(
            source_account
                .parse()
                .map_err(|e| anyhow!("invalid source account: {e}"))?,
        );

        let seq = self.account_sequence(source_account).await?;
        let raw = Self::build_invoke_contract_tx_envelope(
            source_account,
            seq,
            BASE_FEE,
            pool_contract_id,
            "transact",
            vec![proof_scval, ext_scval, sender_scval],
            Vec::new(),
        )?;

        let sim = self.client.simulate_transaction(&raw).await?;
        PreparedSorobanTx::from_simulation(&raw, &sim, Some(self.contract_config()))
    }

    /// Simulates `register` on the configured public key registry contract and
    /// returns unsigned XDR + auth entries for the wallet.
    ///
    /// `owner` is the registration itself: it becomes the `Account.owner`
    /// argument, which the registry uses as its storage key and, at
    /// `require_auth()`, as the address that must authorize the call. `payer`
    /// only carries the transaction: its sequence number is read and it
    /// sources the envelope, so it pays the fee.
    ///
    /// The two may differ, but a delegate cannot register on its own. When
    /// they do differ the simulation returns an auth entry for `owner`, and
    /// the wallet must collect that signature in addition to `payer`'s
    /// signature on the envelope.
    pub async fn prepare_register(
        &self,
        owner: &NoteOwnerAddress,
        payer: &SignerAddress,
        note_key: [u8; 32],
        encryption_key: [u8; 32],
    ) -> Result<PreparedSorobanTx> {
        let account_scval = register_account_to_scval(owner.as_str(), encryption_key, note_key)?;

        let payer = payer.as_str();
        let seq = self.account_sequence(payer).await?;
        let raw = Self::build_invoke_contract_tx_envelope(
            payer,
            seq,
            BASE_FEE,
            &self.contract_config().public_key_registry,
            "register",
            vec![account_scval],
            Vec::new(),
        )?;

        let sim = self.client.simulate_transaction(&raw).await?;
        PreparedSorobanTx::from_simulation(&raw, &sim, Some(self.contract_config()))
    }

    async fn account_sequence(&self, source_account: &str) -> Result<xdr::SequenceNumber> {
        let entry = self.client.get_account(source_account).await?;
        next_sequence(entry.seq_num)
    }
}

/// Computes the sequence number for a new transaction from the account's
/// current on-ledger sequence number.
///
/// Stellar requires `tx.seq_num == account.seq_num + 1`; submitting a tx with
/// the account's current sequence is rejected with `txBAD_SEQ`.
fn next_sequence(current: xdr::SequenceNumber) -> Result<xdr::SequenceNumber> {
    let next = current
        .0
        .checked_add(1)
        .ok_or_else(|| anyhow!("account sequence number overflow"))?;
    Ok(xdr::SequenceNumber(next))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::{
        chain::{
            RpcClient,
            rpc::{Error as RpcError, SimulateHostFunctionResult, SimulateTransactionResponse},
            tx_assemble::test_fixtures::{empty_envelope, empty_soroban_data},
        },
        types::{ContractConfig, NoteOwnerAddress, SignerAddress},
    };
    use futures::executor::block_on;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use stellar_strkey::ed25519;
    use stellar_xdr::{Limits, ReadXdr, WriteXdr};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_string_contains, method},
    };

    const TEST_CONFIG_JSON: &str = r#"{
        "network": "test",
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

    fn test_pool_contract_id() -> String {
        let config: ContractConfig = serde_json::from_str(TEST_CONFIG_JSON).expect("test config");
        config
            .pools
            .iter()
            .find(|p| p.enabled)
            .or_else(|| config.pools.first())
            .expect("pool in test config")
            .pool_contract_id
            .clone()
    }

    struct MockRpc {
        seq: xdr::SequenceNumber,
        sim: SimulateTransactionResponse,
        simulate_calls: AtomicUsize,
    }

    impl MockRpc {
        fn new(seq: i64, sim: SimulateTransactionResponse) -> Self {
            Self {
                seq: xdr::SequenceNumber(seq),
                sim,
                simulate_calls: AtomicUsize::new(0),
            }
        }

        async fn simulate_transaction(
            &self,
            _tx: &xdr::TransactionEnvelope,
        ) -> Result<SimulateTransactionResponse, RpcError> {
            self.simulate_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.sim.clone())
        }
    }

    fn fixture_sim(resource_fee: &str) -> SimulateTransactionResponse {
        let mut sim = SimulateTransactionResponse {
            latest_ledger: 1,
            result: None,
            results: vec![],
            transaction_data: Some(
                empty_soroban_data()
                    .to_xdr_base64(Limits::none())
                    .expect("xdr"),
            ),
            min_resource_fee: Some(resource_fee.to_string()),
            error: None,
        };
        sim.results.push(SimulateHostFunctionResult {
            auth: vec![],
            retval: None,
            ..Default::default()
        });
        sim
    }

    fn account_id(address: &str) -> xdr::AccountId {
        let pk = ed25519::PublicKey::from_string(address).expect("strkey");
        xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(pk.0)))
    }

    /// A minimal `AccountEntry` for `address`, sitting at `seq`, base64-encoded
    /// the way `getLedgerEntries` returns it.
    fn account_entry_xdr(address: &str, seq: i64) -> String {
        let entry = xdr::AccountEntry {
            account_id: account_id(address),
            balance: 0,
            seq_num: xdr::SequenceNumber(seq),
            num_sub_entries: 0,
            inflation_dest: None,
            flags: 0,
            home_domain: xdr::String32::default(),
            thresholds: xdr::Thresholds([1, 0, 0, 0]),
            signers: xdr::VecM::default(),
            ext: xdr::AccountEntryExt::V0,
        };
        xdr::LedgerEntryData::Account(entry)
            .to_xdr_base64(Limits::none())
            .expect("ledger entry xdr")
    }

    fn ledger_key_xdr(address: &str) -> String {
        xdr::LedgerKey::Account(xdr::LedgerKeyAccount {
            account_id: account_id(address),
        })
        .to_xdr_base64(Limits::none())
        .expect("ledger key xdr")
    }

    /// The `owner` entry of an encoded registry `Account` map.
    fn owner_of_register_arg(arg: &xdr::ScVal) -> xdr::ScAddress {
        let xdr::ScVal::Map(Some(map)) = arg else {
            panic!("expected the register argument to be a map");
        };
        for xdr::ScMapEntry { key, val } in map.iter() {
            let xdr::ScVal::Symbol(name) = key else {
                continue;
            };
            if name.to_utf8_string().expect("symbol") == "owner" {
                let xdr::ScVal::Address(addr) = val else {
                    panic!("owner should be an address");
                };
                return addr.clone();
            }
        }
        panic!("register argument has no owner entry");
    }

    #[test]
    fn prepared_tx_applies_simulation_fee_and_auth() {
        let raw = empty_envelope();
        let sim = fixture_sim("500");
        let prepared = PreparedSorobanTx::from_simulation(&raw, &sim, None).expect("prepare");
        assert!(prepared.auth_entries.is_empty());
        assert_eq!(prepared.latest_ledger, 1);
        assert!(!prepared.tx_xdr.is_empty());

        let assembled = xdr::TransactionEnvelope::from_xdr_base64(&prepared.tx_xdr, Limits::none())
            .expect("xdr");
        let xdr::TransactionEnvelope::Tx(v1) = assembled else {
            panic!("expected v1 envelope");
        };
        assert_eq!(v1.tx.fee, 600);
    }

    /// The owner is the registration; the payer only carries it. Drives the
    /// real `prepare_register` against a mocked RPC so the routing of each
    /// identity is asserted on production code, not on a re-implementation.
    #[tokio::test]
    async fn prepare_register_registers_owner_and_sources_from_payer() {
        let owner_key = ed25519::PublicKey([1u8; 32]).to_string();
        let payer_key = ed25519::PublicKey([2u8; 32]).to_string();
        let owner = NoteOwnerAddress::new(owner_key.as_str());
        let payer = SignerAddress::new(payer_key.as_str());
        assert_ne!(owner.as_str(), payer.as_str(), "the pair must differ");

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("getLedgerEntries"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "entries": [{
                        "key": ledger_key_xdr(payer.as_str()),
                        "xdr": account_entry_xdr(payer.as_str(), 41),
                        "lastModifiedLedgerSeq": 1,
                    }],
                    "latestLedger": 1,
                },
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(body_string_contains("simulateTransaction"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": fixture_sim("250"),
            })))
            .mount(&server)
            .await;

        let config: ContractConfig = serde_json::from_str(TEST_CONFIG_JSON).expect("test config");
        let fetcher = StateFetcher::new(RpcClient::new(&server.uri()).expect("rpc client"), config)
            .expect("state fetcher");

        let prepared = fetcher
            .prepare_register(&owner, &payer, [0xAB; 32], [0xEE; 32])
            .await
            .expect("prepare register");

        let env = xdr::TransactionEnvelope::from_xdr_base64(&prepared.tx_xdr, Limits::none())
            .expect("xdr");
        let xdr::TransactionEnvelope::Tx(v1) = env else {
            panic!("expected v1 envelope");
        };

        // The payer sources the envelope and pays the fee.
        assert_eq!(
            v1.tx.source_account,
            xdr::MuxedAccount::Ed25519(xdr::Uint256(
                ed25519::PublicKey::from_string(payer.as_str())
                    .expect("strkey")
                    .0
            )),
        );
        assert_eq!(v1.tx.fee, 350);

        // The payer's sequence number is the one that was read: the mocked
        // account sits at 41, so the tx must go out at 42 (txBAD_SEQ
        // otherwise).
        assert_eq!(v1.tx.seq_num, xdr::SequenceNumber(42));
        let seq_request = server
            .received_requests()
            .await
            .expect("recorded requests")
            .into_iter()
            .find(|r| String::from_utf8_lossy(&r.body).contains("getLedgerEntries"))
            .expect("a getLedgerEntries call");
        let body: serde_json::Value =
            serde_json::from_slice(&seq_request.body).expect("request json");
        assert_eq!(
            body["params"]["keys"][0].as_str().expect("ledger key"),
            ledger_key_xdr(payer.as_str()),
            "the sequence number must be read for the payer, not the owner",
        );

        // The owner is what gets registered.
        let xdr::OperationBody::InvokeHostFunction(invoke) = &v1.tx.operations[0].body else {
            panic!("expected invoke");
        };
        let xdr::HostFunction::InvokeContract(args) = &invoke.host_function else {
            panic!("expected contract invoke");
        };
        assert_eq!(args.function_name.to_string(), "register");
        assert_eq!(args.args.len(), 1);
        assert_eq!(
            owner_of_register_arg(&args.args[0]),
            owner.as_str().parse::<xdr::ScAddress>().expect("address"),
            "the registry key must be the owner, not the payer",
        );
    }

    #[test]
    fn prepare_pool_transact_builds_transact_invoke() {
        let pk = ed25519::PublicKey([8u8; 32]);
        let source = pk.to_string();
        let pool_id = test_pool_contract_id();
        let mock = MockRpc::new(3, fixture_sim("100"));

        let proof_uncompressed = vec![0u8; 256];
        let ext = ExtData {
            recipient: source.to_string(),
            ext_amount: crate::types::ExtAmount::from(0),
            encrypted_output0: vec![],
            encrypted_output1: vec![],
        };
        let public = OnchainProofPublicInputs {
            root: crate::types::Field(crate::types::U256::from(1)),
            input_nullifiers: [
                crate::types::Field(crate::types::U256::from(2)),
                crate::types::Field(crate::types::U256::from(3)),
            ],
            output_commitment0: crate::types::Field(crate::types::U256::from(4)),
            output_commitment1: crate::types::Field(crate::types::U256::from(5)),
            public_amount: crate::types::Field(crate::types::U256::from(6)),
            ext_data_hash_be: [0u8; 32],
            asp_membership_root: crate::types::Field(crate::types::U256::from(7)),
            asp_non_membership_root: crate::types::Field(crate::types::U256::from(8)),
            output_gvk_ciphertexts: None,
            input_gvk_ciphertexts: None,
        };

        let proof_scval = pool_proof_to_scval(
            &proof_uncompressed,
            public.root,
            &public.input_nullifiers,
            public.output_commitment0,
            public.output_commitment1,
            public.public_amount,
            public.ext_data_hash_be,
            public.asp_membership_root,
            public.asp_non_membership_root,
        )
        .expect("proof scval");
        let ext_scval = pool_ext_data_to_scval(&ext).expect("ext scval");
        let sender_scval = xdr::ScVal::Address(source.parse().expect("address"));

        let raw = StateFetcher::build_invoke_contract_tx_envelope(
            &source,
            next_sequence(mock.seq.clone()).expect("next seq"),
            BASE_FEE,
            &pool_id,
            "transact",
            vec![proof_scval, ext_scval, sender_scval],
            Vec::new(),
        )
        .expect("raw tx");

        let sim = block_on(mock.simulate_transaction(&raw)).expect("simulate");
        let prepared = PreparedSorobanTx::from_simulation(&raw, &sim, None).expect("prepare");

        let env = xdr::TransactionEnvelope::from_xdr_base64(&prepared.tx_xdr, Limits::none())
            .expect("xdr");
        let xdr::TransactionEnvelope::Tx(v1) = env else {
            panic!("expected v1 envelope");
        };
        assert_eq!(v1.tx.fee, 200);
        // Account is at seq 3; the new tx must use seq + 1 = 4.
        assert_eq!(v1.tx.seq_num, xdr::SequenceNumber(4));

        let xdr::OperationBody::InvokeHostFunction(invoke) = &v1.tx.operations[0].body else {
            panic!("expected invoke");
        };
        let xdr::HostFunction::InvokeContract(args) = &invoke.host_function else {
            panic!("expected contract invoke");
        };
        assert_eq!(args.function_name.to_string(), "transact");
        assert_eq!(args.args.len(), 3);
    }

    #[test]
    fn next_sequence_increments_by_one() {
        assert_eq!(
            next_sequence(xdr::SequenceNumber(0)).expect("next"),
            xdr::SequenceNumber(1)
        );
        assert_eq!(
            next_sequence(xdr::SequenceNumber(42)).expect("next"),
            xdr::SequenceNumber(43)
        );
    }

    #[test]
    fn next_sequence_rejects_overflow() {
        assert!(next_sequence(xdr::SequenceNumber(i64::MAX)).is_err());
    }
}
