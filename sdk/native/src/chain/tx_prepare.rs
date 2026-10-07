//! Build and simulate pool contract transactions for signing/submission.

use crate::types::{ExtData, NoteOwnerAddress, SignerAddress};
use anyhow::{Result, anyhow, bail, ensure};
use stellar_xdr::{self as xdr};

use super::{
    contract_state::{OnchainProofPublicInputs, PreparedSorobanTx, StateFetcher},
    soroban_encode::{
        BASE_FEE, pool_ext_data_to_scval, pool_gvk_proof_to_scval, pool_proof_to_scval,
        register_account_to_scval,
    },
    tx_assemble::{build_invoke_contract_tx_envelope, invoke_contract_args},
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
    ///
    /// Refuses any authorization beyond this `transact` and, for a deposit, its
    /// token transfer; see [`check_transact_auth`].
    pub(crate) async fn prepare_pool_transact(
        &self,
        pool_contract_id: &str,
        input: &PoolTransactInput,
        source_account: &SignerAddress,
    ) -> Result<PreparedSorobanTx> {
        let source_account = source_account.as_str();
        let token: xdr::ScAddress = self
            .enabled_pool_for(pool_contract_id)?
            .token_contract_id
            .parse()
            .map_err(|e| anyhow!("invalid token contract id: {e}"))?;
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
        let sender: xdr::ScAddress = source_account
            .parse()
            .map_err(|e| anyhow!("invalid source account: {e}"))?;

        let args = vec![proof_scval, ext_scval, xdr::ScVal::Address(sender.clone())];

        let seq = self.account_sequence(source_account).await?;
        let raw = build_invoke_contract_tx_envelope(
            source_account,
            seq,
            BASE_FEE,
            pool_contract_id,
            "transact",
            args.clone(),
            Vec::new(),
        )?;

        let sim = self.client.simulate_transaction(&raw).await?;
        let prepared = PreparedSorobanTx::from_simulation(&raw, &sim)?;
        check_transact_auth(
            &sim.auth_entries()?,
            &pool_contract_id.parse()?,
            args,
            &token,
            &sender,
            input.ext_data.ext_amount.into(),
        )?;
        Ok(prepared)
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
        let raw = build_invoke_contract_tx_envelope(
            payer,
            seq,
            BASE_FEE,
            &self.contract_config().public_key_registry,
            "register",
            vec![account_scval],
            Vec::new(),
        )?;

        let sim = self.client.simulate_transaction(&raw).await?;
        PreparedSorobanTx::from_simulation(&raw, &sim)
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

/// Refuses simulated authorization for a pool `transact` that reaches beyond
/// that call and, for a deposit, the token transfer into the pool.
///
/// The sender signs whatever tree the simulation returns, including calls the
/// RPC server or a contract adds. The root must be the exact `transact` built
/// from `args`, or an entry signed for another proof or `ExtData` could move
/// the deposit into someone else's notes. Entry and envelope signatures
/// authorize the same tree, so the credential type is not checked.
fn check_transact_auth(
    entries: &[xdr::SorobanAuthorizationEntry],
    pool: &xdr::ScAddress,
    args: Vec<xdr::ScVal>,
    token: &xdr::ScAddress,
    sender: &xdr::ScAddress,
    ext_amount: i128,
) -> Result<()> {
    let [entry] = entries else {
        bail!(
            "refusing to sign {} authorization entries for transact, which takes one",
            entries.len()
        );
    };
    let root = &entry.root_invocation;
    let transact = invoke_contract_args(pool.clone(), "transact", args)?;
    ensure!(
        root.function == xdr::SorobanAuthorizedFunction::ContractFn(transact),
        "refusing to sign a root call other than the transact built for the pool"
    );
    if ext_amount <= 0 {
        ensure!(
            root.sub_invocations.is_empty(),
            "refusing to sign a private transfer or withdrawal that authorizes a call under transact"
        );
        return Ok(());
    }
    let [transfer] = root.sub_invocations.as_slice() else {
        bail!(
            "refusing to sign a deposit that authorizes {} calls under transact instead of the token transfer",
            root.sub_invocations.len()
        );
    };
    let transfer_args = vec![
        xdr::ScVal::Address(sender.clone()),
        xdr::ScVal::Address(pool.clone()),
        xdr::ScVal::from(ext_amount),
    ];
    let token_transfer = invoke_contract_args(token.clone(), "transfer", transfer_args)?;
    ensure!(
        transfer.function == xdr::SorobanAuthorizedFunction::ContractFn(token_transfer),
        "refusing to sign a deposit whose authorized call is not the pool token's transfer of {ext_amount} from the sender to the pool"
    );
    ensure!(
        transfer.sub_invocations.is_empty(),
        "refusing to sign a deposit whose token transfer authorizes a call of its own"
    );
    Ok(())
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
        let prepared = PreparedSorobanTx::from_simulation(&raw, &sim).expect("prepare");
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

    /// A private transfer's external data, paying nothing out to `recipient`.
    fn ext_data_to(recipient: &str) -> ExtData {
        ExtData {
            recipient: recipient.to_string(),
            ext_amount: crate::types::ExtAmount::from(0),
            encrypted_output0: vec![],
            encrypted_output1: vec![],
        }
    }

    fn public_inputs() -> OnchainProofPublicInputs {
        OnchainProofPublicInputs {
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
        }
    }

    /// Drives the real `prepare_pool_transact` for a private transfer against
    /// an RPC whose `simulateTransaction` returns `simulation`.
    async fn prepare_pool_transact_with(
        simulation: serde_json::Value,
    ) -> Result<PreparedSorobanTx> {
        let source = ed25519::PublicKey([8u8; 32]).to_string();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("getLedgerEntries"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "entries": [{
                        "key": ledger_key_xdr(&source),
                        "xdr": account_entry_xdr(&source, 3),
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
                "result": simulation,
            })))
            .mount(&server)
            .await;

        let config: ContractConfig = serde_json::from_str(TEST_CONFIG_JSON).expect("test config");
        let fetcher = StateFetcher::new(RpcClient::new(&server.uri()).expect("rpc client"), config)
            .expect("state fetcher");
        let input = PoolTransactInput {
            proof_uncompressed: vec![0u8; 256],
            ext_data: ext_data_to(&source),
            public: public_inputs(),
        };
        fetcher
            .prepare_pool_transact(
                &test_pool_contract_id(),
                &input,
                &SignerAddress::new(source.as_str()),
            )
            .await
    }

    #[tokio::test]
    async fn prepare_pool_transact_refuses_a_second_authorization_entry() {
        let entry = xdr::SorobanAuthorizationEntry {
            credentials: xdr::SorobanCredentials::SourceAccount,
            root_invocation: transact_on(&POOL, vec![]),
        }
        .to_xdr_base64(Limits::none())
        .expect("auth entry xdr");
        let mut sim = fixture_sim("100");
        sim.results[0].auth = vec![entry.clone(), entry];

        let refused = prepare_pool_transact_with(json!(sim))
            .await
            .expect_err("the second entry must be refused");
        assert_eq!(
            refused.to_string(),
            "refusing to sign 2 authorization entries for transact, which takes one"
        );
    }

    /// A refused simulation has no auth entries, so its contract error must
    /// surface before the auth check: the app keys its messages on that code.
    #[tokio::test]
    async fn prepare_pool_transact_reports_the_simulation_error_before_the_auth_check() {
        let failed = prepare_pool_transact_with(json!({
            "latestLedger": 1,
            "error": "HostError: Error(Contract, #18)",
        }))
        .await
        .expect_err("a failed simulation must fail the preparation");
        assert_eq!(
            failed.to_string(),
            "transaction simulation failed: HostError: Error(Contract, #18)"
        );
    }

    #[test]
    fn prepare_pool_transact_builds_transact_invoke() {
        let pk = ed25519::PublicKey([8u8; 32]);
        let source = pk.to_string();
        let pool_id = test_pool_contract_id();
        let mock = MockRpc::new(3, fixture_sim("100"));

        let proof_uncompressed = vec![0u8; 256];
        let ext = ext_data_to(&source);
        let public = public_inputs();

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

        let raw = build_invoke_contract_tx_envelope(
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
        let prepared = PreparedSorobanTx::from_simulation(&raw, &sim).expect("prepare");

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

    const POOL: xdr::ScAddress = xdr::ScAddress::Contract(xdr::ContractId(xdr::Hash([1; 32])));
    const TOKEN: xdr::ScAddress = xdr::ScAddress::Contract(xdr::ContractId(xdr::Hash([2; 32])));
    const OTHER: xdr::ScAddress = xdr::ScAddress::Contract(xdr::ContractId(xdr::Hash([3; 32])));
    const SENDER: xdr::ScAddress = xdr::ScAddress::Account(xdr::AccountId(
        xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256([4; 32])),
    ));
    const DEPOSIT: i128 = 5;

    fn call(
        contract: &xdr::ScAddress,
        function: &str,
        args: Vec<xdr::ScVal>,
        sub_invocations: Vec<xdr::SorobanAuthorizedInvocation>,
    ) -> xdr::SorobanAuthorizedInvocation {
        xdr::SorobanAuthorizedInvocation {
            function: xdr::SorobanAuthorizedFunction::ContractFn(xdr::InvokeContractArgs {
                contract_address: contract.clone(),
                function_name: function.try_into().expect("symbol"),
                args: args.try_into().expect("args"),
            }),
            sub_invocations: sub_invocations.try_into().expect("sub-invocations"),
        }
    }

    /// The proof, `ExtData`, and sender arguments the check expects.
    fn transact_args() -> Vec<xdr::ScVal> {
        vec![
            xdr::ScVal::Void,
            xdr::ScVal::Void,
            xdr::ScVal::Address(SENDER),
        ]
    }

    fn transact_on(
        contract: &xdr::ScAddress,
        sub_invocations: Vec<xdr::SorobanAuthorizedInvocation>,
    ) -> xdr::SorobanAuthorizedInvocation {
        call(contract, "transact", transact_args(), sub_invocations)
    }

    fn token_transfer(
        token: &xdr::ScAddress,
        to: &xdr::ScAddress,
        sub_invocations: Vec<xdr::SorobanAuthorizedInvocation>,
    ) -> xdr::SorobanAuthorizedInvocation {
        let args = vec![
            xdr::ScVal::Address(SENDER),
            xdr::ScVal::Address(to.clone()),
            xdr::ScVal::from(DEPOSIT),
        ];
        call(token, "transfer", args, sub_invocations)
    }

    /// Runs the check on one source-account entry for each root.
    fn check(ext_amount: i128, roots: Vec<xdr::SorobanAuthorizedInvocation>) -> Result<()> {
        let entries: Vec<_> = roots
            .into_iter()
            .map(|root_invocation| xdr::SorobanAuthorizationEntry {
                credentials: xdr::SorobanCredentials::SourceAccount,
                root_invocation,
            })
            .collect();
        check_transact_auth(
            &entries,
            &POOL,
            transact_args(),
            &TOKEN,
            &SENDER,
            ext_amount,
        )
    }

    fn refusal(ext_amount: i128, roots: Vec<xdr::SorobanAuthorizedInvocation>) -> String {
        check(ext_amount, roots)
            .expect_err("the authorization must be refused")
            .to_string()
    }

    #[test]
    fn a_transfer_with_no_sub_invocation_is_accepted() {
        check(0, vec![transact_on(&POOL, vec![])]).expect("accepted");
    }

    #[test]
    fn a_deposit_with_its_token_transfer_is_accepted() {
        let deposit = transact_on(&POOL, vec![token_transfer(&TOKEN, &POOL, vec![])]);
        check(DEPOSIT, vec![deposit]).expect("accepted");
    }

    #[test]
    fn a_withdrawal_with_no_sub_invocation_is_accepted() {
        check(-DEPOSIT, vec![transact_on(&POOL, vec![])]).expect("accepted");
    }

    #[test]
    fn a_withdrawal_that_authorizes_a_transfer_is_refused() {
        let withdrawal = transact_on(&POOL, vec![token_transfer(&TOKEN, &POOL, vec![])]);
        assert_eq!(
            refusal(-DEPOSIT, vec![withdrawal]),
            "refusing to sign a private transfer or withdrawal that authorizes a call under \
             transact"
        );
    }

    #[test]
    fn a_second_entry_is_refused() {
        let roots = vec![transact_on(&POOL, vec![]), transact_on(&POOL, vec![])];
        assert_eq!(
            refusal(0, roots),
            "refusing to sign 2 authorization entries for transact, which takes one"
        );
    }

    #[test]
    fn a_sub_invocation_on_a_transfer_is_refused() {
        let transfer = transact_on(&POOL, vec![token_transfer(&TOKEN, &POOL, vec![])]);
        assert_eq!(
            refusal(0, vec![transfer]),
            "refusing to sign a private transfer or withdrawal that authorizes a call under \
             transact"
        );
    }

    #[test]
    fn a_deposit_transfer_to_another_recipient_is_refused() {
        let deposit = transact_on(&POOL, vec![token_transfer(&TOKEN, &OTHER, vec![])]);
        assert_eq!(
            refusal(DEPOSIT, vec![deposit]),
            "refusing to sign a deposit whose authorized call is not the pool token's transfer \
             of 5 from the sender to the pool"
        );
    }

    #[test]
    fn a_deposit_transfer_on_another_token_is_refused() {
        let deposit = transact_on(&POOL, vec![token_transfer(&OTHER, &POOL, vec![])]);
        assert_eq!(
            refusal(DEPOSIT, vec![deposit]),
            "refusing to sign a deposit whose authorized call is not the pool token's transfer \
             of 5 from the sender to the pool"
        );
    }

    #[test]
    fn a_call_nested_under_the_token_transfer_is_refused() {
        let nested = token_transfer(&TOKEN, &OTHER, vec![]);
        let deposit = transact_on(&POOL, vec![token_transfer(&TOKEN, &POOL, vec![nested])]);
        assert_eq!(
            refusal(DEPOSIT, vec![deposit]),
            "refusing to sign a deposit whose token transfer authorizes a call of its own"
        );
    }

    #[test]
    fn a_root_on_another_contract_is_refused() {
        assert_eq!(
            refusal(0, vec![transact_on(&OTHER, vec![])]),
            "refusing to sign a root call other than the transact built for the pool"
        );
    }

    #[test]
    fn a_root_with_other_transact_arguments_is_refused() {
        let args = vec![
            xdr::ScVal::U32(1),
            xdr::ScVal::Void,
            xdr::ScVal::Address(SENDER),
        ];
        assert_eq!(
            refusal(0, vec![call(&POOL, "transact", args, vec![])]),
            "refusing to sign a root call other than the transact built for the pool"
        );
    }

    #[test]
    fn a_root_calling_another_pool_function_is_refused() {
        assert_eq!(
            refusal(0, vec![call(&POOL, "withdraw", transact_args(), vec![])]),
            "refusing to sign a root call other than the transact built for the pool"
        );
    }

    #[test]
    fn a_transact_naming_another_sender_is_refused() {
        let args = vec![
            xdr::ScVal::Void,
            xdr::ScVal::Void,
            xdr::ScVal::Address(OTHER),
        ];
        assert_eq!(
            refusal(0, vec![call(&POOL, "transact", args, vec![])]),
            "refusing to sign a root call other than the transact built for the pool"
        );
    }

    #[test]
    fn a_deposit_without_its_token_transfer_is_refused() {
        assert_eq!(
            refusal(DEPOSIT, vec![transact_on(&POOL, vec![])]),
            "refusing to sign a deposit that authorizes 0 calls under transact instead of the \
             token transfer"
        );
    }

    #[test]
    fn a_deposit_transfer_from_another_address_is_refused() {
        let args = vec![
            xdr::ScVal::Address(OTHER),
            xdr::ScVal::Address(POOL),
            xdr::ScVal::from(DEPOSIT),
        ];
        let deposit = transact_on(&POOL, vec![call(&TOKEN, "transfer", args, vec![])]);
        assert_eq!(
            refusal(DEPOSIT, vec![deposit]),
            "refusing to sign a deposit whose authorized call is not the pool token's transfer \
             of 5 from the sender to the pool"
        );
    }

    #[test]
    fn a_deposit_transfer_of_another_amount_is_refused() {
        let args = vec![
            xdr::ScVal::Address(SENDER),
            xdr::ScVal::Address(POOL),
            xdr::ScVal::from(6_i128),
        ];
        let deposit = transact_on(&POOL, vec![call(&TOKEN, "transfer", args, vec![])]);
        assert_eq!(
            refusal(DEPOSIT, vec![deposit]),
            "refusing to sign a deposit whose authorized call is not the pool token's transfer \
             of 5 from the sender to the pool"
        );
    }
}
