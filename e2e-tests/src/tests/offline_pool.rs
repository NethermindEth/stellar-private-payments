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
use soroban_sdk::{Bytes, Env, IntoVal, Symbol, TryFromVal, U256, testutils::Events as _};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};
use stellar_private_payments::{
    BackgroundSync, Client, Error, LocalSigner, LocalStorage, PreparedTransaction, PrivatePool,
    Prover, ProverHandle, Signer, SignerHandle, Storage, StorageHandle,
    chain::{ContractDataStorage, EventChain, EventChainCheck, RpcClient, StateFetcher},
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
    /// The background sync task, when the pool syncs in the background; run
    /// it to sync.
    pub background: Option<BackgroundSync>,
    _wallet: WalletFile,
}

#[derive(Default)]
pub struct OfflinePoolBuilder {
    background_sync: bool,
    notes: Vec<u64>,
    spent_on_chain: Vec<u32>,
    replaced_on_chain: Vec<u32>,
    extra_on_chain: usize,
    unsynced_on_chain: usize,
    foreign_spent_on_chain: usize,
    garbled_outputs: Vec<u32>,
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

    /// Marks the notes at these leaf indices spent in the pool's storage
    /// without saving their nullifiers in the wallet, as when a bootnode
    /// withholds the `NewNullifierEvent`s.
    pub fn spent_on_chain(mut self, leaf_indices: &[u32]) -> Self {
        self.spent_on_chain = leaf_indices.to_vec();
        self
    }

    /// Puts a leaf the wallet never saw in the pool's tree in place of each
    /// seeded note at these leaf indices, as when a bootnode serves an altered
    /// `NewCommitmentEvent`.
    pub fn replaced_on_chain(mut self, leaf_indices: &[u32]) -> Self {
        self.replaced_on_chain = leaf_indices.to_vec();
        self
    }

    /// Appends `count` leaves the wallet never saw to the pool's tree, as when
    /// a bootnode withholds `NewCommitmentEvent`s.
    ///
    /// The pool inserts leaves in pairs, so the total must stay even.
    pub fn extra_on_chain(mut self, count: usize) -> Self {
        self.extra_on_chain = count;
        self
    }

    /// Appends `count` leaves the wallet has not synced yet to the pool's
    /// tree, and has the RPC serve their `NewCommitmentEvent`s, as for a
    /// wallet a few events behind an honest pool.
    ///
    /// The pool inserts leaves in pairs, so the total must stay even.
    pub fn unsynced_on_chain(mut self, count: usize) -> Self {
        self.unsynced_on_chain = count;
        self
    }

    /// Marks `count` nullifiers of no seeded note spent in the pool's storage,
    /// as when a bootnode withholds the `NewNullifierEvent`s of other users'
    /// spends.
    pub fn foreign_spent_on_chain(mut self, count: usize) -> Self {
        self.foreign_spent_on_chain = count;
        self
    }

    /// Garbles the `encrypted_output` of the seeded notes at these leaf
    /// indices in the wallet's history, and drops the notes, as when a
    /// bootnode serves altered ciphertexts: the commitments still match the
    /// pool's tree, but the wallet never finds the notes.
    pub fn garbled_outputs(mut self, leaf_indices: &[u32]) -> Self {
        self.garbled_outputs = leaf_indices.to_vec();
        self
    }

    /// Syncs in the background instead of inline; the task is
    /// [`OfflinePool::background`].
    pub fn background_sync(mut self) -> Self {
        self.background_sync = true;
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
        let seeded_outputs = sdk_tests::seed::seeded_encrypted_outputs(&wallet.0)?;
        sdk_tests::seed::garble_seeded_outputs(&wallet.0, &self.garbled_outputs)?;
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
        let mut chain_leaves = pool_leaves.clone();
        for &leaf_index in &self.replaced_on_chain {
            let leaf = chain_leaves
                .get_mut(leaf_index as usize)
                .with_context(|| format!("no seeded note at leaf {leaf_index}"))?;
            *leaf = foreign_leaf(leaf_index)?;
        }
        for leaf_index in pool_leaves.len()..pool_leaves.len().saturating_add(self.extra_on_chain) {
            chain_leaves.push(foreign_leaf(u32::try_from(leaf_index)?)?);
        }
        let unsynced_from = chain_leaves.len();
        for _ in 0..self.unsynced_on_chain {
            chain_leaves.push(foreign_leaf(u32::try_from(chain_leaves.len())?)?);
        }
        insert_leaves(&deployment, &membership_leaves, &chain_leaves)?;

        // The pool's own history: a commitment per leaf, the seeded ones with
        // the ciphertexts their notes were made with, then the spends.
        let mut history = chain_leaves
            .iter()
            .enumerate()
            .map(|(leaf_index, &leaf)| {
                let seeded = (leaf_index < pool_leaves.len()
                    && !self.replaced_on_chain.contains(&u32::try_from(leaf_index)?))
                .then(|| seeded_outputs.get(leaf_index).cloned())
                .flatten();
                Ok(PoolEvent::Commitment {
                    leaf,
                    index: u32::try_from(leaf_index)?,
                    encrypted_output: seeded.unwrap_or_else(|| vec![0x5a; 112]),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        for n in 0..self.foreign_spent_on_chain {
            let nullifier = foreign_nullifier(u32::try_from(n)?)?;
            mark_spent(&deployment, nullifier)?;
            history.push(PoolEvent::Nullifier(nullifier));
        }
        for &leaf_index in &self.spent_on_chain {
            let commitment = pool_leaves
                .get(leaf_index as usize)
                .with_context(|| format!("no seeded note at leaf {leaf_index}"))?;
            let nullifier = sdk_tests::seed::seeded_note_nullifier(commitment, leaf_index)?;
            mark_spent(&deployment, nullifier)?;
            history.push(PoolEvent::Nullifier(nullifier));
        }
        let published = publish_history(&deployment, &history)?;
        // The RPC serves the unsynced leaves' events, after the seeded ones.
        let mut served = published
            .get(unsynced_from..chain_leaves.len())
            .context("the unsynced leaves' events")?
            .to_vec();
        if self.deposits_paused {
            pool::PoolContractClient::new(&deployment.env, &deployment.pool).pause_deposits();
            served.extend(published_events(&deployment));
        }

        let rpc = ScriptedRpc::start(
            &deployment,
            rpc_events(&pool_id, &served),
            event_chains(&deployment)?,
        )
        .await?;
        let config = harness_config(&deployment, &rpc);
        let prover = ScriptedProver::default();
        let signer = ScriptedSigner::new()?;
        let storage = FaultyStorage::new(StorageHandle::from(local));

        let mut client = Client::init(
            rpc.uri(),
            StorageHandle::from(storage.clone()),
            ProverHandle::from(prover.clone()),
            config,
            None,
        )?;
        let background = self
            .background_sync
            .then(|| client.background_sync())
            .transpose()?;
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
            background,
            _wallet: wallet,
        })
    }
}

/// The deployment's config, with the owner as the source of read-only
/// simulations. The deployment's admin is a contract address in the test host,
/// and a transaction's source must be an account.
fn harness_config(deployment: &Deployment, rpc: &ScriptedRpc) -> ContractConfig {
    let (mut config, _) = config_for(deployment, &rpc.uri());
    config.deployer = OWNER.to_string();
    config
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

/// A leaf no seeded note has: the field element `leaf_index + 1`, far below
/// any Poseidon output the seed produces.
fn foreign_leaf(leaf_index: u32) -> Result<Field> {
    let mut le = [0u8; 32];
    le[..4].copy_from_slice(&leaf_index.saturating_add(1).to_le_bytes());
    Field::try_from_le_bytes(le)
}

/// A nullifier no seeded note has: the field element `2^32 + n`, distinct from
/// every [`foreign_leaf`] and far below any Poseidon output the seed produces.
fn foreign_nullifier(n: u32) -> Result<Field> {
    let mut le = [0u8; 32];
    le[..4].copy_from_slice(&n.to_le_bytes());
    le[4] = 1;
    Field::try_from_le_bytes(le)
}

/// An event the harness publishes as part of the pool's history.
enum PoolEvent {
    Commitment {
        leaf: Field,
        index: u32,
        encrypted_output: Vec<u8>,
    },
    Nullifier(Field),
}

/// Publishes `history` through the pool's own code, so the pool keeps the
/// event chain of a pool that emitted those events, and returns them as
/// `(topics, value)` in the base64 XDR an RPC serves.
fn publish_history(deployment: &Deployment, history: &[PoolEvent]) -> Result<Vec<RpcEvent>> {
    let env = &deployment.env;
    env.as_contract(&deployment.pool, || {
        for event in history {
            match event {
                PoolEvent::Commitment {
                    leaf,
                    index,
                    encrypted_output,
                } => soroban_utils::publish_event!(
                    env,
                    pool::NewCommitmentEvent {
                        commitment: to_u256(env, *leaf),
                        index: *index,
                        encrypted_output: Bytes::from_slice(env, encrypted_output),
                    }
                ),
                PoolEvent::Nullifier(nullifier) => soroban_utils::publish_event!(
                    env,
                    pool::NewNullifierEvent {
                        nullifier: to_u256(env, *nullifier),
                    }
                ),
            }
        }
    });
    let published = published_events(deployment);
    ensure!(
        published.len() == history.len(),
        "the pool published {} of {} events",
        published.len(),
        history.len()
    );
    Ok(published)
}

/// An event's topics and value in base64 XDR.
type RpcEvent = (Vec<String>, String);

/// The events the pool published in the host's last call, in base64 XDR.
fn published_events(deployment: &Deployment) -> Vec<RpcEvent> {
    let events = deployment
        .env
        .events()
        .all()
        .filter_by_contract(&deployment.pool);
    events
        .events()
        .iter()
        .map(|event| {
            let xdr::ContractEventBody::V0(body) = &event.body;
            (
                body.topics
                    .iter()
                    .map(|topic| topic.to_xdr_base64(Limits::none()).expect("topic xdr"))
                    .collect(),
                body.data.to_xdr_base64(Limits::none()).expect("data xdr"),
            )
        })
        .collect()
}

/// `events` as `getEvents` serves them, at [`LEDGER`] and in order.
fn rpc_events(pool_id: &str, events: &[RpcEvent]) -> Vec<Value> {
    events
        .iter()
        .enumerate()
        .map(|(n, (topics, value))| {
            json!({
                "type": "contract",
                "ledger": LEDGER,
                "ledgerClosedAt": "1970-01-01T00:00:00Z",
                "contractId": pool_id,
                "id": format!("{:019}-{n:010}", u64::from(LEDGER) << 32),
                "pagingToken": format!("{LEDGER}-{n}"),
                "inSuccessfulContractCall": true,
                "topic": topics,
                "value": value,
            })
        })
        .collect()
}

/// What `event_chain()` returns for the pool and the registry, in base64 XDR,
/// by contract.
fn event_chains(deployment: &Deployment) -> Result<Vec<(xdr::ScAddress, String)>> {
    let env = &deployment.env;
    let chains = [
        (
            &deployment.pool,
            pool::PoolContractClient::new(env, &deployment.pool).event_chain(),
        ),
        (
            &deployment.registry,
            public_key_registry::PublicKeyRegistryClient::new(env, &deployment.registry)
                .event_chain(),
        ),
    ];
    chains
        .into_iter()
        .map(|(contract, chain)| {
            let chain: soroban_sdk::Val = chain.into_val(env);
            let value = xdr::ScVal::try_from_val(env, &chain)
                .map_err(|e| anyhow::anyhow!("event chain to XDR: {e:?}"))?;
            Ok((
                strkey(contract).parse().context("contract address")?,
                value.to_xdr_base64(Limits::none())?,
            ))
        })
        .collect()
}

/// Stores the pool's spent marker for `nullifier`, the key `transact` writes.
fn mark_spent(deployment: &Deployment, nullifier: Field) -> Result<()> {
    let env = &deployment.env;
    let nullifier = to_u256(env, nullifier);
    // `pool::DataKey::Nullifier(n)` encodes as the vector `[Nullifier, n]`.
    let key = (Symbol::new(env, "Nullifier"), nullifier.clone());
    env.as_contract(&deployment.pool, || {
        env.storage().persistent().set(&key, &true);
    });
    ensure!(
        pool::PoolContractClient::new(env, &deployment.pool).is_spent(&nullifier),
        "the pool does not read the stored marker as spent"
    );
    Ok(())
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
/// owner's account, `getEvents` serves the pool's unsynced events to a request
/// from a start ledger and nothing past them, at [`LEDGER`],
/// `simulateTransaction` authorizes exactly the `transact` it was given and
/// answers the pool's `is_spent` from the snapshot, `sendTransaction` accepts
/// with a fresh hash and `getTransaction` reports success. Any other method is
/// answered with a JSON-RPC error.
pub struct ScriptedRpc {
    server: MockServer,
    next_answers: Arc<Mutex<HashMap<String, VecDeque<Value>>>>,
}

impl ScriptedRpc {
    async fn start(
        deployment: &Deployment,
        events: Vec<Value>,
        event_chains: Vec<(xdr::ScAddress, String)>,
    ) -> Result<Self> {
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
                events,
                event_chains,
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

    /// Answers the next `method` call with `result` instead of the default. A
    /// `simulateTransaction` answer goes to the next simulated `transact`.
    pub fn answer_next(&self, method: &str, result: Value) {
        self.next_answers
            .lock()
            .expect("answers lock")
            .entry(method.to_string())
            .or_default()
            .push_back(result);
    }

    /// The JSON-RPC methods called so far, in order. A simulation of a
    /// read-only function reads as `simulateTransaction:<function>`, so
    /// `simulateTransaction` names only simulations of a `transact`.
    pub async fn calls(&self) -> Vec<String> {
        self.server
            .received_requests()
            .await
            .expect("request recording is on")
            .iter()
            .map(|request| {
                let body: Value = serde_json::from_slice(&request.body).expect("JSON-RPC body");
                let method = body["method"].as_str().expect("method");
                match simulated_read(&body) {
                    Some(function) => format!("{method}:{function}"),
                    None => method.to_string(),
                }
            })
            .collect()
    }

    /// How many requests asked the pool about a nullifier: a
    /// `getLedgerEntries` key naming a `Nullifier` entry, or a simulated
    /// `is_spent` call.
    pub async fn nullifier_lookups(&self) -> usize {
        self.server
            .received_requests()
            .await
            .expect("request recording is on")
            .iter()
            .filter(|request| {
                let body: Value = serde_json::from_slice(&request.body).expect("JSON-RPC body");
                match body["method"].as_str() {
                    Some("getLedgerEntries") => body["params"]["keys"]
                        .as_array()
                        .expect("ledger keys")
                        .iter()
                        .any(|key| names_a_nullifier(key.as_str().expect("ledger key"))),
                    Some("simulateTransaction") => {
                        calls_is_spent(body["params"]["transaction"].as_str().expect("transaction"))
                    }
                    _ => false,
                }
            })
            .count()
    }

    /// How many times `method` was called.
    pub async fn count(&self, method: &str) -> usize {
        self.calls().await.iter().filter(|m| *m == method).count()
    }
}

struct Chain {
    entries: HashMap<String, Value>,
    /// Events served to a `getEvents` request from a start ledger; a request
    /// resuming from a cursor is past them.
    events: Vec<Value>,
    /// What each contract's `event_chain()` returns, in base64 XDR.
    event_chains: Vec<(xdr::ScAddress, String)>,
    token: xdr::ScAddress,
    next_answers: Arc<Mutex<HashMap<String, VecDeque<Value>>>>,
    sent: AtomicU64,
}

impl Respond for Chain {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).expect("JSON-RPC body");
        let method = body["method"].as_str().expect("method");
        // One-off answers stand in for a transaction's stages, so a read-only
        // simulation never takes one.
        let scripted = simulated_read(&body)
            .is_none()
            .then(|| {
                self.next_answers
                    .lock()
                    .expect("answers lock")
                    .get_mut(method)
                    .and_then(VecDeque::pop_front)
            })
            .flatten();
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
                "events": if params["startLedger"].is_null() {
                    &[][..]
                } else {
                    self.events.as_slice()
                },
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

    /// Simulates the one contract call in `tx`: `transact` or `is_spent`.
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
        match call.function_name.0.to_utf8_string_lossy().as_str() {
            "transact" => self.simulate_transact(call),
            "is_spent" => self.simulate_is_spent(call),
            "event_chain" => self.simulate_event_chain(call),
            other => anyhow::bail!("the scripted RPC does not simulate {other}"),
        }
    }

    /// Answers `event_chain()` with the chain the contract kept in the host.
    fn simulate_event_chain(&self, call: &xdr::InvokeContractArgs) -> Result<Value> {
        let (_, chain) = self
            .event_chains
            .iter()
            .find(|(contract, _)| *contract == call.contract_address)
            .context("event_chain() of a contract the harness did not deploy")?;
        Ok(json!({
            "latestLedger": LEDGER,
            "results": [{ "auth": [], "xdr": chain }],
            "transactionData": empty_transaction_data().to_xdr_base64(Limits::none())?,
            "minResourceFee": "100",
        }))
    }

    /// Answers `is_spent(n)` as the pool does: spent when the snapshot holds
    /// the pool's persistent `Nullifier(n)` entry.
    fn simulate_is_spent(&self, call: &xdr::InvokeContractArgs) -> Result<Value> {
        let [nullifier] = call.args.as_slice() else {
            anyhow::bail!("expected is_spent(nullifier)");
        };
        let name = xdr::ScSymbol::try_from("Nullifier")
            .map_err(|_| anyhow::anyhow!("Nullifier is a symbol"))?;
        let key = xdr::LedgerKey::ContractData(xdr::LedgerKeyContractData {
            contract: call.contract_address.clone(),
            key: xdr::ScVal::Vec(Some(xdr::ScVec(
                vec![xdr::ScVal::Symbol(name), nullifier.clone()].try_into()?,
            ))),
            durability: xdr::ContractDataDurability::Persistent,
        });
        let spent = self
            .entries
            .contains_key(&key.to_xdr_base64(Limits::none())?);
        Ok(json!({
            "latestLedger": LEDGER,
            "results": [{
                "auth": [],
                "xdr": xdr::ScVal::Bool(spent).to_xdr_base64(Limits::none())?,
            }],
            "transactionData": empty_transaction_data().to_xdr_base64(Limits::none())?,
            "minResourceFee": "100",
        }))
    }

    /// A simulation authorizing the invoked call and, for a deposit, the token
    /// transfer under it: the only tree the SDK agrees to sign.
    fn simulate_transact(&self, call: &xdr::InvokeContractArgs) -> Result<Value> {
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
        Ok(json!({
            "latestLedger": LEDGER,
            "results": [{
                "auth": [auth.to_xdr_base64(Limits::none())?],
                "xdr": xdr::ScVal::Void.to_xdr_base64(Limits::none())?,
            }],
            "transactionData": empty_transaction_data().to_xdr_base64(Limits::none())?,
            "minResourceFee": "100",
        }))
    }
}

fn empty_transaction_data() -> xdr::SorobanTransactionData {
    xdr::SorobanTransactionData {
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
    }
}

fn names_a_nullifier(key: &str) -> bool {
    let Ok(xdr::LedgerKey::ContractData(data)) =
        xdr::LedgerKey::from_xdr_base64(key, Limits::none())
    else {
        return false;
    };
    let xdr::ScVal::Vec(Some(parts)) = &data.key else {
        return false;
    };
    matches!(
        parts.first(),
        Some(xdr::ScVal::Symbol(name)) if name.0.to_utf8_string_lossy() == "Nullifier"
    )
}

fn calls_is_spent(tx: &str) -> bool {
    invoked_function(tx).as_deref() == Some("is_spent")
}

/// The contract function a transaction envelope invokes, if it invokes one.
fn invoked_function(tx: &str) -> Option<String> {
    let Ok(xdr::TransactionEnvelope::Tx(envelope)) =
        xdr::TransactionEnvelope::from_xdr_base64(tx, Limits::none())
    else {
        return None;
    };
    envelope
        .tx
        .operations
        .iter()
        .find_map(|operation| match &operation.body {
            xdr::OperationBody::InvokeHostFunction(invoke) => match &invoke.host_function {
                xdr::HostFunction::InvokeContract(call) => {
                    Some(call.function_name.0.to_utf8_string_lossy())
                }
                _ => None,
            },
            _ => None,
        })
}

/// A simulation of a read-only contract function, such as `event_chain` or
/// `is_spent`, rather than of a `transact`: the function, or `None`.
fn simulated_read(body: &Value) -> Option<String> {
    if body["method"].as_str() != Some("simulateTransaction") {
        return None;
    }
    invoked_function(body["params"]["transaction"].as_str()?)
        .filter(|function| function != "transact")
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

    async fn check_event_chain(
        &self,
        contract_id: &str,
        published: EventChain,
    ) -> Result<EventChainCheck, Error> {
        self.inner.check_event_chain(contract_id, published).await
    }

    async fn forget_contract_history(&self, contract_id: &str) -> Result<(), Error> {
        self.inner.forget_contract_history(contract_id).await
    }
}

/// The probe behind [`ScriptedRpc::nullifier_lookups`] must recognise the
/// key of a real spent marker, or a test relying on it passes vacuously.
#[test]
fn the_nullifier_probe_recognises_a_stored_spent_marker() -> Result<()> {
    let deployment = deploy();
    let is_marker = |entries: &[Value]| {
        entries
            .iter()
            .any(|entry| names_a_nullifier(entry["key"].as_str().expect("entry key")))
    };
    assert!(!is_marker(&ledger_entries_as_rpc_results(&deployment.env)));

    mark_spent(&deployment, foreign_leaf(0)?)?;

    assert!(is_marker(&ledger_entries_as_rpc_results(&deployment.env)));
    Ok(())
}

/// The SDK's own `is_spent` read reaches the scripted RPC, is answered from
/// the pool's state, and is counted by the probe.
#[tokio::test]
async fn the_sdk_is_spent_read_is_answered_from_the_pool_and_counted() -> Result<()> {
    let deployment = deploy();
    mark_spent(&deployment, foreign_leaf(0)?)?;
    let rpc = ScriptedRpc::start(&deployment, Vec::new(), Vec::new()).await?;
    let config = harness_config(&deployment, &rpc);
    let fetcher = StateFetcher::new(RpcClient::new(&rpc.uri())?, config)?;
    let pool_id = strkey(&deployment.pool);

    assert!(
        fetcher
            .is_nullifier_spent(&pool_id, foreign_leaf(0)?)
            .await?
    );
    assert!(
        !fetcher
            .is_nullifier_spent(&pool_id, foreign_leaf(1)?)
            .await?
    );
    assert_eq!(rpc.nullifier_lookups().await, 2);
    Ok(())
}
