//! A [`PrivatePool`] that runs offline, with every stage scriptable.
//!
//! The pool is opened through the public API (`Client::init` → `account` →
//! `pool`) against a pool deployed in the test host. A JSON-RPC server answers
//! from that deployment's real ledger entries and stands in for the network for
//! everything else a transact sends. The prover, the signer and the storage
//! wrap or replace the real ones so that a test can make any one stage fail:
//!
//! - [`ScriptedRpc`] answers each method a transact calls, takes one-off
//!   answers with [`ScriptedRpc::answer_next`], and lists the methods it was
//!   called with, in order, through [`ScriptedRpc::calls`].
//! - [`ScriptedProver`] returns a proof shaped like the request without
//!   proving, or the error [`ScriptedProver::fail_next`] queues. The simulation
//!   is scripted too, so the proof bytes never reach a verifier.
//! - [`ScriptedSigner`] signs with a [`LocalSigner`] unless
//!   [`ScriptedSigner::refuse_next`] tells it to refuse.
//! - [`FaultyStorage`] delegates to a seeded [`LocalStorage`] and replaces
//!   `build_transact_params` results with the ones
//!   [`FaultyStorage::script_build_transact_params`] queues.
//!
//! The wallet is seeded with `sdk_tests::seed`, and its membership leaf and
//! note commitments are inserted into the deployed contracts, so the real
//! storage builds the transact inputs against the chain's own roots.

use super::deployment::{
    Deployment, LEVELS, MEMBERSHIP_LEVELS, config_for, deploy, ledger_entries_as_rpc_results,
    strkey,
};
use anyhow::{Context, Result, ensure};
use asp_membership::ASPMembershipClient;
use pool_core::merkle_with_history::MerkleTreeWithHistory;
use serde_json::{Value, json};
use soroban_sdk::{Bytes, Env, U256};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};
use stellar_private_payments::{
    Client, Error, LocalSigner, LocalStorage, PreparedTransaction, PrivatePool, Prover,
    ProverHandle, Signer, SignerHandle, Storage, StorageHandle,
    chain::ContractDataStorage,
    disclosure::{DisclosureInputs, DisclosureInputsRequest, DisclosureProveParams},
    gvk::GvkEvent,
    planner::SpendableNote,
    registration::{RegistrationInputs, RegistrationRequest},
    state::database_key::OpenPurpose,
    transact::{PreparedTxPublic, TransactRequest},
    types::{
        AspMembershipSync, ContractConfig, ContractsEventData, DisclosureReceipt,
        EncryptionKeyPair, EncryptionPublicKey, ExtData, Field, NoteKeyPair, NoteOwnerAddress,
        NotePublicKey, OperationalFeedItem, PortfolioBalance, PortfolioPoolEntry, RecipientLookup,
        SignedTransaction, SignerAddress, SyncMetadata, UserNoteSummary,
    },
    zk::flows::TransactParams,
};
use stellar_xdr::{self as xdr, Limits, ReadXdr, WriteXdr};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate, matchers::method};

/// The wallet owner, who also signs and pays.
pub const OWNER: &str = "GDVEU3DD4KOFECV66VIHWEZOYX4ZKR3WV27L464SIIPOU2IUI3JCZA57";
/// Ed25519 secret of [`OWNER`].
const OWNER_SECRET: &str = "SADQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQP54X";
const NETWORK_PASSPHRASE: &str = "Test SDF Network ; September 2015";

/// Ledger the RPC reports as its tip, for both events and ledger entries.
const LEDGER: u32 = 100;
/// The owner's account sequence number on the scripted chain.
const OWNER_SEQUENCE: i64 = 41;

/// A [`PrivatePool`] and the handles that script and observe each stage.
pub struct OfflinePool {
    pub pool: PrivatePool,
    pub rpc: ScriptedRpc,
    pub prover: ScriptedProver,
    pub signer: ScriptedSigner,
    pub storage: FaultyStorage,
    _wallet: WalletFile,
}

#[derive(Default)]
pub struct OfflinePoolBuilder {
    notes: Vec<u64>,
    deposits_paused: bool,
}

impl OfflinePool {
    pub fn builder() -> OfflinePoolBuilder {
        OfflinePoolBuilder::default()
    }
}

impl OfflinePoolBuilder {
    /// Unspent notes the wallet holds, also inserted into the pool's tree.
    ///
    /// The pool inserts leaves in pairs, so the count must be even.
    pub fn notes(mut self, amounts: &[u64]) -> Self {
        self.notes = amounts.to_vec();
        self
    }

    /// Pauses deposits on the deployed pool.
    pub fn deposits_paused(mut self) -> Self {
        self.deposits_paused = true;
        self
    }

    pub async fn build(self) -> Result<OfflinePool> {
        // The wallet's trees and the contracts' trees must be the same depth,
        // or the roots the wallet computes never match the chain's.
        ensure!(
            LEVELS == sdk_tests::seed::POOL_MERKLE_LEVELS,
            "the deployed pool tree has {LEVELS} levels, the seeded wallet's has {}",
            sdk_tests::seed::POOL_MERKLE_LEVELS
        );
        ensure!(
            MEMBERSHIP_LEVELS == sdk_tests::seed::ASP_MEMBERSHIP_LEVELS,
            "the deployed membership tree has {MEMBERSHIP_LEVELS} levels, the seeded wallet's has {}",
            sdk_tests::seed::ASP_MEMBERSHIP_LEVELS
        );
        let deployment = deploy();
        if self.deposits_paused {
            pool::PoolContractClient::new(&deployment.env, &deployment.pool).pause_deposits();
        }
        let pool_id = strkey(&deployment.pool);
        let asp_membership_id = strkey(&deployment.asp_membership);

        let wallet = WalletFile::new();
        sdk_tests::seed::seed_prove_wallet(
            &wallet.0,
            &pool_id,
            &strkey(&deployment.token),
            &asp_membership_id,
            OWNER,
            sdk_tests::seed::TEST_NETWORK,
            &self.notes,
        )?;
        let local = LocalStorage::open_encrypted(
            wallet.path(),
            sdk_tests::seed::database_key(),
            OpenPurpose::OpenExisting,
        )?;
        let (membership_leaves, pool_leaves) = {
            let db = local.storage();
            (
                db.get_all_asp_membership_leaves_ordered(&asp_membership_id)?,
                db.get_pool_commitment_leaves_ordered(&pool_id)?,
            )
        };
        insert_leaves(&deployment, &membership_leaves, &pool_leaves)?;

        let rpc = ScriptedRpc::start(&deployment).await?;
        let (config, _) = config_for(&deployment, &rpc.uri());
        let prover = ScriptedProver::default();
        let signer = ScriptedSigner::new()?;
        let storage = FaultyStorage::new(StorageHandle::from(local));

        let client = Client::init(
            rpc.uri(),
            StorageHandle::from(storage.clone()),
            ProverHandle::from(prover.clone()),
            config,
            None,
        )?;
        let pool = client
            .account(
                NoteOwnerAddress::new(OWNER),
                SignerHandle::from(signer.clone()),
            )?
            .pool(pool_id)?;

        Ok(OfflinePool {
            pool,
            rpc,
            prover,
            signer,
            storage,
            _wallet: wallet,
        })
    }
}

/// Inserts the wallet's leaves with the contracts' own code, so the roots the
/// chain reports are the ones the wallet computes.
fn insert_leaves(deployment: &Deployment, membership: &[Field], pool: &[Field]) -> Result<()> {
    let env = &deployment.env;
    let membership_client = ASPMembershipClient::new(env, &deployment.asp_membership);
    for leaf in membership {
        membership_client.insert_leaf(&to_u256(env, *leaf));
    }

    ensure!(
        pool.len().is_multiple_of(2),
        "the pool inserts leaves in pairs"
    );
    env.as_contract(&deployment.pool, || {
        pool.chunks_exact(2).try_for_each(|pair| {
            let [first, second] = pair else {
                unreachable!("chunks_exact(2)")
            };
            MerkleTreeWithHistory::insert_two_leaves(
                env,
                to_u256(env, *first),
                to_u256(env, *second),
            )
            .map(|_| ())
            .map_err(|e| anyhow::anyhow!("insert pool leaves: {e:?}"))
        })
    })
}

fn to_u256(env: &Env, field: Field) -> U256 {
    U256::from_be_bytes(env, &Bytes::from_array(env, &field.to_be_bytes()))
}

/// A seeded wallet database, removed on drop.
struct WalletFile(PathBuf);

impl WalletFile {
    fn new() -> Self {
        static RUN: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "spp-offline-pool-{}-{}.sqlite",
            std::process::id(),
            RUN.fetch_add(1, Ordering::Relaxed),
        ));
        let _ = std::fs::remove_file(&path);
        Self(path)
    }

    fn path(&self) -> &str {
        self.0.to_str().expect("temp paths are UTF-8")
    }
}

impl Drop for WalletFile {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let mut path = self.0.clone().into_os_string();
            path.push(suffix);
            let _ = std::fs::remove_file(path);
        }
    }
}

/// A JSON-RPC server standing in for the network.
///
/// `getLedgerEntries` answers from the deployment's ledger snapshot plus the
/// owner's account, `getEvents` reports no events at [`LEDGER`],
/// `simulateTransaction` authorizes exactly the call it was given,
/// `sendTransaction` accepts with a fresh hash and `getTransaction` reports
/// success. Any other method is answered with a JSON-RPC error.
pub struct ScriptedRpc {
    server: MockServer,
    next_answers: Arc<Mutex<HashMap<String, VecDeque<Value>>>>,
}

impl ScriptedRpc {
    async fn start(deployment: &Deployment) -> Result<Self> {
        let mut entries: HashMap<String, Value> = ledger_entries_as_rpc_results(&deployment.env)
            .into_iter()
            .map(|entry| (entry["key"].as_str().expect("entry key").to_string(), entry))
            .collect();
        let (key, entry) = account_entry(OWNER, OWNER_SEQUENCE)?;
        entries.insert(key, entry);

        let next_answers = Arc::new(Mutex::new(HashMap::new()));
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(Chain {
                entries,
                token: strkey(&deployment.token)
                    .parse()
                    .context("token contract address")?,
                next_answers: next_answers.clone(),
                sent: AtomicU64::new(0),
            })
            .mount(&server)
            .await;
        Ok(Self {
            server,
            next_answers,
        })
    }

    pub fn uri(&self) -> String {
        self.server.uri()
    }

    /// Answers the next `method` call with `result` instead of the default.
    pub fn answer_next(&self, method: &str, result: Value) {
        self.next_answers
            .lock()
            .expect("answers lock")
            .entry(method.to_string())
            .or_default()
            .push_back(result);
    }

    /// The JSON-RPC methods called so far, in order.
    pub async fn calls(&self) -> Vec<String> {
        self.server
            .received_requests()
            .await
            .expect("request recording is on")
            .iter()
            .map(|request| {
                let body: Value = serde_json::from_slice(&request.body).expect("JSON-RPC body");
                body["method"].as_str().expect("method").to_string()
            })
            .collect()
    }

    /// How many times `method` was called.
    pub async fn count(&self, method: &str) -> usize {
        self.calls().await.iter().filter(|m| *m == method).count()
    }
}

struct Chain {
    entries: HashMap<String, Value>,
    token: xdr::ScAddress,
    next_answers: Arc<Mutex<HashMap<String, VecDeque<Value>>>>,
    sent: AtomicU64,
}

impl Respond for Chain {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).expect("JSON-RPC body");
        let method = body["method"].as_str().expect("method");
        let scripted = self
            .next_answers
            .lock()
            .expect("answers lock")
            .get_mut(method)
            .and_then(VecDeque::pop_front);
        let result = match scripted {
            Some(result) => Ok(result),
            None => self.answer(method, &body["params"]),
        };
        ResponseTemplate::new(200).set_body_json(match result {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": 1, "result": result }),
            Err(message) => json!({
                "jsonrpc": "2.0",
                "id": 1,
                "error": { "code": -32601, "message": message },
            }),
        })
    }
}

impl Chain {
    fn answer(&self, method: &str, params: &Value) -> Result<Value, String> {
        match method {
            "getLatestLedger" => Ok(json!({
                "id": "latest",
                "protocolVersion": 22,
                "sequence": LEDGER,
            })),
            "getEvents" => Ok(json!({
                "cursor": "tip",
                "events": [],
                "latestLedger": LEDGER,
                "latestLedgerCloseTime": "0",
                "oldestLedger": 1,
                "oldestLedgerCloseTime": "0",
            })),
            "getLedgerEntries" => {
                let keys = params["keys"].as_array().expect("ledger keys");
                let entries: Vec<&Value> = keys
                    .iter()
                    .filter_map(|key| self.entries.get(key.as_str().expect("ledger key")))
                    .collect();
                Ok(json!({ "entries": entries, "latestLedger": LEDGER }))
            }
            "simulateTransaction" => {
                let tx = params["transaction"].as_str().expect("transaction");
                self.simulate(tx).map_err(|e| format!("{e:#}"))
            }
            "sendTransaction" => {
                let sent = self.sent.fetch_add(1, Ordering::SeqCst);
                Ok(json!({
                    "hash": tx_hash(sent),
                    "status": "PENDING",
                    "latestLedger": LEDGER,
                }))
            }
            "getTransaction" => Ok(json!({ "status": "SUCCESS" })),
            other => Err(format!("the scripted RPC does not serve {other}")),
        }
    }

    /// A simulation authorizing the invoked call and, for a deposit, the token
    /// transfer under it: the only tree the SDK agrees to sign.
    fn simulate(&self, tx: &str) -> Result<Value> {
        let xdr::TransactionEnvelope::Tx(envelope) =
            xdr::TransactionEnvelope::from_xdr_base64(tx, Limits::none())?
        else {
            anyhow::bail!("expected a v1 envelope");
        };
        let [operation] = envelope.tx.operations.as_slice() else {
            anyhow::bail!("expected one operation");
        };
        let xdr::OperationBody::InvokeHostFunction(invoke) = &operation.body else {
            anyhow::bail!("expected a contract invocation");
        };
        let xdr::HostFunction::InvokeContract(call) = &invoke.host_function else {
            anyhow::bail!("expected a contract invocation");
        };
        let [_proof, ext_data, sender] = call.args.as_slice() else {
            anyhow::bail!("expected transact(proof, ext_data, sender)");
        };

        let mut sub_invocations = Vec::new();
        if let Some(amount) = deposit_amount(ext_data) {
            sub_invocations.push(xdr::SorobanAuthorizedInvocation {
                function: xdr::SorobanAuthorizedFunction::ContractFn(xdr::InvokeContractArgs {
                    contract_address: self.token.clone(),
                    function_name: xdr::ScSymbol::try_from("transfer")
                        .map_err(|_| anyhow::anyhow!("transfer is a symbol"))?,
                    args: vec![
                        sender.clone(),
                        xdr::ScVal::Address(call.contract_address.clone()),
                        xdr::ScVal::from(amount),
                    ]
                    .try_into()?,
                }),
                sub_invocations: xdr::VecM::default(),
            });
        }
        let auth = xdr::SorobanAuthorizationEntry {
            credentials: xdr::SorobanCredentials::SourceAccount,
            root_invocation: xdr::SorobanAuthorizedInvocation {
                function: xdr::SorobanAuthorizedFunction::ContractFn(call.clone()),
                sub_invocations: sub_invocations.try_into()?,
            },
        };
        let transaction_data = xdr::SorobanTransactionData {
            ext: xdr::SorobanTransactionDataExt::V0,
            resources: xdr::SorobanResources {
                footprint: xdr::LedgerFootprint {
                    read_only: xdr::VecM::default(),
                    read_write: xdr::VecM::default(),
                },
                instructions: 0,
                disk_read_bytes: 0,
                write_bytes: 0,
            },
            resource_fee: 0,
        };
        Ok(json!({
            "latestLedger": LEDGER,
            "results": [{
                "auth": [auth.to_xdr_base64(Limits::none())?],
                "xdr": xdr::ScVal::Void.to_xdr_base64(Limits::none())?,
            }],
            "transactionData": transaction_data.to_xdr_base64(Limits::none())?,
            "minResourceFee": "100",
        }))
    }
}

/// The hash `sendTransaction` reports for the `index`-th transaction sent,
/// counting from zero.
pub fn tx_hash(index: u64) -> String {
    format!("{:064x}", index.saturating_add(1))
}

/// The amount a deposit moves in, read from the `ext_amount` of the encoded
/// external data; `None` for a transfer or a withdrawal.
fn deposit_amount(ext_data: &xdr::ScVal) -> Option<i128> {
    let xdr::ScVal::Map(Some(map)) = ext_data else {
        return None;
    };
    map.iter().find_map(|entry| match (&entry.key, &entry.val) {
        (xdr::ScVal::Symbol(name), xdr::ScVal::I256(parts))
            if name.to_utf8_string_lossy() == "ext_amount"
                && parts.hi_hi == 0
                && parts.hi_lo == 0 =>
        {
            let amount = (u128::from(parts.lo_hi) << 64) | u128::from(parts.lo_lo);
            i128::try_from(amount).ok().filter(|amount| *amount > 0)
        }
        _ => None,
    })
}

/// The `getLedgerEntries` key and result for an account at `sequence`.
fn account_entry(address: &str, sequence: i64) -> Result<(String, Value)> {
    let account_id: xdr::AccountId = address.parse()?;
    let key = xdr::LedgerKey::Account(xdr::LedgerKeyAccount {
        account_id: account_id.clone(),
    })
    .to_xdr_base64(Limits::none())?;
    let entry = xdr::LedgerEntryData::Account(xdr::AccountEntry {
        account_id,
        balance: 0,
        seq_num: xdr::SequenceNumber(sequence),
        num_sub_entries: 0,
        inflation_dest: None,
        flags: 0,
        home_domain: xdr::String32::default(),
        thresholds: xdr::Thresholds([1, 0, 0, 0]),
        signers: xdr::VecM::default(),
        ext: xdr::AccountEntryExt::V0,
    })
    .to_xdr_base64(Limits::none())?;
    Ok((
        key.clone(),
        json!({ "key": key, "xdr": entry, "lastModifiedLedgerSeq": 1 }),
    ))
}

/// Proves without proving: returns public inputs taken from the request and
/// fresh output commitments, or a queued error.
#[derive(Clone, Default)]
pub struct ScriptedProver {
    failures: Arc<Mutex<VecDeque<String>>>,
    calls: Arc<AtomicU64>,
}

impl ScriptedProver {
    /// Fails the next `prove_transact` with `message`.
    pub fn fail_next(&self, message: &str) {
        self.failures
            .lock()
            .expect("failures lock")
            .push_back(message.to_string());
    }

    /// How many transacts were proved or refused.
    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl Prover for ScriptedProver {
    async fn prove_transact(&self, params: TransactParams) -> Result<PreparedTransaction, Error> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(message) = self.failures.lock().expect("failures lock").pop_front() {
            return Err(Error::Other(anyhow::anyhow!(message)));
        }
        // Distinct per call, so a multi-step plan never sees the same
        // commitment twice.
        let field = |n: u64| {
            let mut le = [0u8; 32];
            le[..8].copy_from_slice(&call.saturating_mul(4).saturating_add(n).to_le_bytes());
            Field::try_from_le_bytes(le).expect("a small field element")
        };
        Ok(PreparedTransaction {
            proof_uncompressed: vec![0; 256],
            ext_data: ExtData {
                recipient: params.ext_recipient,
                ext_amount: params.ext_amount,
                encrypted_output0: vec![],
                encrypted_output1: vec![],
            },
            prepared: PreparedTxPublic {
                pool_root: params.pool_root,
                input_nullifiers: [field(1), field(2)],
                output_commitments: [field(3), field(4)],
                public_amount: Field::ZERO,
                ext_data_hash_be: [0; 32],
                asp_membership_root: params
                    .membership_proof
                    .map_or(Field::ZERO, |proof| proof.root),
                asp_non_membership_root: params
                    .non_membership_proof
                    .map_or(Field::ZERO, |proof| proof.root),
                output_gvk_ciphertexts: None,
                input_gvk_ciphertexts: None,
            },
            soroban_tx: Default::default(),
        })
    }

    async fn prove_disclosure(
        &self,
        _params: DisclosureProveParams,
    ) -> Result<DisclosureReceipt, Error> {
        Err(Error::Other(anyhow::anyhow!(
            "the scripted prover does not prove disclosures"
        )))
    }

    async fn verify_disclosure_proof(
        &self,
        _receipt: &DisclosureReceipt,
        _expected_vk_hash: &str,
    ) -> Result<bool, Error> {
        Err(Error::Other(anyhow::anyhow!(
            "the scripted prover does not verify disclosures"
        )))
    }
}

/// Signs as [`OWNER`] with a [`LocalSigner`], or refuses as a wallet would.
#[derive(Clone)]
pub struct ScriptedSigner {
    inner: SignerHandle,
    refusals: Arc<AtomicUsize>,
    calls: Arc<AtomicU64>,
}

impl ScriptedSigner {
    fn new() -> Result<Self> {
        Ok(Self {
            inner: SignerHandle::from(LocalSigner::new(
                OWNER_SECRET,
                NETWORK_PASSPHRASE,
                SignerAddress::new(OWNER),
            )?),
            refusals: Arc::default(),
            calls: Arc::default(),
        })
    }

    /// Refuses the next transaction with [`Error::UserRejected`].
    pub fn refuse_next(&self) {
        self.refusals.fetch_add(1, Ordering::SeqCst);
    }

    /// How many transactions were signed or refused.
    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl Signer for ScriptedSigner {
    fn signer_address(&self) -> SignerAddress {
        self.inner.signer_address()
    }

    async fn sign_transaction(
        &self,
        prepared: &PreparedTransaction,
    ) -> Result<SignedTransaction, Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let refuse = self
            .refusals
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok();
        if refuse {
            return Err(Error::UserRejected("refused by the test".to_string()));
        }
        self.inner.sign_transaction(prepared).await
    }
}

/// What [`FaultyStorage`] answers one `build_transact_params` call with.
#[derive(Debug, Clone)]
pub enum BuildParams {
    /// Build them with the real storage.
    Real,
    /// Report that local state is behind the chain.
    SyncRequired,
    /// Fail with this message.
    Fail(&'static str),
}

/// Storage that delegates to a real one, with scripted
/// `build_transact_params` results.
///
/// Forks share the script, so it reaches the pool's own fork.
#[derive(Clone)]
pub struct FaultyStorage {
    inner: StorageHandle,
    build_params: Arc<Mutex<VecDeque<BuildParams>>>,
    build_params_calls: Arc<AtomicU64>,
}

impl FaultyStorage {
    fn new(inner: StorageHandle) -> Self {
        Self {
            inner,
            build_params: Arc::default(),
            build_params_calls: Arc::default(),
        }
    }

    /// Answers the next `build_transact_params` calls, one per item, then
    /// falls back to [`BuildParams::Real`].
    pub fn script_build_transact_params(&self, answers: impl IntoIterator<Item = BuildParams>) {
        self.build_params
            .lock()
            .expect("script lock")
            .extend(answers);
    }

    /// How many times `build_transact_params` was called.
    pub fn build_transact_params_calls(&self) -> u64 {
        self.build_params_calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl ContractDataStorage for FaultyStorage {
    async fn get_sync_state(&self) -> anyhow::Result<Vec<SyncMetadata>> {
        self.inner.get_sync_state().await
    }

    async fn save_events_batch(&self, batch: ContractsEventData) -> anyhow::Result<()> {
        self.inner.save_events_batch(batch).await
    }

    async fn save_sync_progress(
        &self,
        metadata: Vec<SyncMetadata>,
        fully_indexed: bool,
    ) -> anyhow::Result<()> {
        self.inner.save_sync_progress(metadata, fully_indexed).await
    }
}

#[async_trait::async_trait]
impl Storage for FaultyStorage {
    fn fork(&self) -> Result<StorageHandle, Error> {
        Ok(StorageHandle::from(Self {
            inner: self.inner.fork()?,
            build_params: self.build_params.clone(),
            build_params_calls: self.build_params_calls.clone(),
        }))
    }

    async fn ensure_ready(&self) -> Result<(), Error> {
        self.inner.ensure_ready().await
    }

    async fn spendable_notes(
        &self,
        pool_contract_id: &str,
        user_address: &str,
        kdf_domain: &str,
    ) -> Result<Vec<SpendableNote>, Error> {
        self.inner
            .spendable_notes(pool_contract_id, user_address, kdf_domain)
            .await
    }

    async fn notes(
        &self,
        pool_contract_id: &str,
        user_address: &str,
        kdf_domain: &str,
    ) -> Result<Vec<UserNoteSummary>, Error> {
        self.inner
            .notes(pool_contract_id, user_address, kdf_domain)
            .await
    }

    async fn list_portfolio_balances(
        &self,
        user_address: &str,
        kdf_domain: &str,
        enabled_pools: &[PortfolioPoolEntry],
    ) -> Result<Vec<PortfolioBalance>, Error> {
        self.inner
            .list_portfolio_balances(user_address, kdf_domain, enabled_pools)
            .await
    }

    async fn list_user_notes(
        &self,
        user_address: &str,
        kdf_domain: &str,
        limit: u32,
    ) -> Result<Vec<UserNoteSummary>, Error> {
        self.inner
            .list_user_notes(user_address, kdf_domain, limit)
            .await
    }

    async fn operational_feed(
        &self,
        limit: u32,
        config: &ContractConfig,
    ) -> Result<Vec<OperationalFeedItem>, Error> {
        self.inner.operational_feed(limit, config).await
    }

    async fn recipient_lookup(
        &self,
        address: &str,
        config: &ContractConfig,
    ) -> Result<RecipientLookup, Error> {
        self.inner.recipient_lookup(address, config).await
    }

    async fn build_transact_params(&self, req: &TransactRequest) -> Result<TransactParams, Error> {
        self.build_params_calls.fetch_add(1, Ordering::SeqCst);
        let answer = self
            .build_params
            .lock()
            .expect("script lock")
            .pop_front()
            .unwrap_or(BuildParams::Real);
        match answer {
            BuildParams::Real => self.inner.build_transact_params(req).await,
            BuildParams::SyncRequired => {
                Err(Error::MembershipSync(AspMembershipSync::SyncRequired(None)))
            }
            BuildParams::Fail(message) => Err(Error::Other(anyhow::anyhow!(message))),
        }
    }

    async fn build_disclosure_inputs(
        &self,
        req: &DisclosureInputsRequest,
    ) -> Result<Vec<DisclosureInputs>, Error> {
        self.inner.build_disclosure_inputs(req).await
    }

    async fn build_registration_inputs(
        &self,
        req: &RegistrationRequest,
    ) -> Result<RegistrationInputs, Error> {
        self.inner.build_registration_inputs(req).await
    }

    async fn privacy_keys_exist(
        &self,
        user_address: &str,
        kdf_domain: &str,
    ) -> Result<bool, Error> {
        self.inner
            .privacy_keys_exist(user_address, kdf_domain)
            .await
    }

    async fn save_private_keys(
        &self,
        user_address: &str,
        kdf_domain: &str,
        note_keypair: &NoteKeyPair,
        encryption_keypair: &EncryptionKeyPair,
        membership_blinding: &Field,
    ) -> Result<(), Error> {
        self.inner
            .save_private_keys(
                user_address,
                kdf_domain,
                note_keypair,
                encryption_keypair,
                membership_blinding,
            )
            .await
    }

    async fn asp_secret(&self, user_address: &str, kdf_domain: &str) -> Result<Field, Error> {
        self.inner.asp_secret(user_address, kdf_domain).await
    }

    async fn privacy_keys(
        &self,
        user_address: &str,
        kdf_domain: &str,
    ) -> Result<(NotePublicKey, EncryptionPublicKey), Error> {
        self.inner.privacy_keys(user_address, kdf_domain).await
    }

    async fn registered_privacy_keys(
        &self,
        address: &str,
        public_key_registry_contract_id: &str,
    ) -> Result<(NotePublicKey, EncryptionPublicKey), Error> {
        self.inner
            .registered_privacy_keys(address, public_key_registry_contract_id)
            .await
    }

    async fn process_pending_state(&self) -> Result<(), Error> {
        self.inner.process_pending_state().await
    }

    async fn clear_indexing_cursors(&self) -> Result<(), Error> {
        self.inner.clear_indexing_cursors().await
    }

    async fn clamp_last_fully_indexed_ledger(&self, max_ledger: u32) -> Result<(), Error> {
        self.inner.clamp_last_fully_indexed_ledger(max_ledger).await
    }

    async fn list_pool_gvk_events(
        &self,
        pool_contract_id: &str,
        after: Option<(u32, String)>,
        limit: u32,
    ) -> Result<Vec<GvkEvent>, Error> {
        self.inner
            .list_pool_gvk_events(pool_contract_id, after, limit)
            .await
    }

    async fn pool_has_commitments(
        &self,
        pool_contract_id: &str,
        commitments: &[Field],
    ) -> Result<HashSet<Field>, Error> {
        self.inner
            .pool_has_commitments(pool_contract_id, commitments)
            .await
    }
}
