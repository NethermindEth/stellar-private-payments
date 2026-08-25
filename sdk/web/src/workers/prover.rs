use crate::{
    circuits::{fetch_lockfile_artifact, get_or_derive_uncompressed, verify_lockfile_artifact},
    protocol::{CorrelatedRequest, ProverWorkerRequest, ProverWorkerResponse},
};
use anyhow::{Context as _, Result, anyhow};
use futures::{FutureExt, try_join};
use gloo_timers::future::TimeoutFuture;
use gloo_worker::{
    Registrable,
    oneshot::{OneshotBridge, oneshot},
};
use std::{cell::RefCell, collections::HashMap, fmt::Write as _};
use stellar_private_payments::{
    ArtifactKind, Error, PreparedProverTx, Prover, ProverEngine, artifact_file_name,
    artifact_sha256_bytes, disclosure,
    types::{
        CircuitStem, DISCLOSURE_RECEIPT_VERSION, DisclosureCircuitMetadata, DisclosurePublicInputs,
        DisclosureReceipt, SELECTIVE_DISCLOSURE_1_CIRCUIT, SELECTIVE_DISCLOSURE_1_LEVELS,
        SELECTIVE_DISCLOSURE_1_N_NOTES, SELECTIVE_DISCLOSURE_2_CIRCUIT,
        SELECTIVE_DISCLOSURE_2_LEVELS, SELECTIVE_DISCLOSURE_2_N_NOTES,
        SELECTIVE_DISCLOSURE_3_CIRCUIT, SELECTIVE_DISCLOSURE_3_LEVELS,
        SELECTIVE_DISCLOSURE_3_N_NOTES, SELECTIVE_DISCLOSURE_4_CIRCUIT,
        SELECTIVE_DISCLOSURE_4_LEVELS, SELECTIVE_DISCLOSURE_4_N_NOTES,
    },
    zk::{
        flows::{DisclosureNote, SelectiveDisclosureParams, TransactParams, selective_disclosure},
        prover::Prover as Groth16Prover,
        witness::WitnessCalculator,
    },
};
use tracing::Instrument;
use wasm_bindgen::JsError;
use wasm_bindgen_futures::spawn_local;

const WORKER_NAME: &str = "WORKER-PROVER";

#[derive(Clone, Debug)]
enum InitState {
    Pending,
    Ready,
    Failed(String),
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().wrapping_mul(2));
    for b in bytes {
        write!(&mut out, "{:02x}", b).expect("writing to String should not fail");
    }
    out
}

// TODO for now it is a mix of async (because we want an async bridge for the
// main thread) and sync (blocking) code in the future we should refactor to use
// wasm threads?

thread_local! {
    static TRANSACT_PROVERS: RefCell<HashMap<String, ProverEngine>> =
        RefCell::new(HashMap::new());
    static DISCLOSURE_WITNESS_CALCS: RefCell<[Option<WitnessCalculator>; 4]> =
        const { RefCell::new([None, None, None, None]) };
    static DISCLOSURE_PROVERS: RefCell<[Option<Groth16Prover>; 4]> =
        const { RefCell::new([None, None, None, None]) };
    static INIT_STATE: RefCell<InitState> = const { RefCell::new(InitState::Pending) };
}

fn init_transact_prover(
    stem: &str,
    proving_key: &[u8],
    graph_bytes: &[u8],
    r1cs_bytes: &[u8],
) -> Result<ProverEngine, JsError> {
    verify_lockfile_artifact(stem, ArtifactKind::ProvingKey, proving_key)?;
    verify_lockfile_artifact(stem, ArtifactKind::Graph, graph_bytes)?;
    verify_lockfile_artifact(stem, ArtifactKind::R1cs, r1cs_bytes)?;

    ProverEngine::new(proving_key, graph_bytes, r1cs_bytes)
        .map_err(|e| JsError::new(&format!("failed to init {stem} transact prover: {e:#}")))
}

fn disclosure_stem(n_notes: usize) -> String {
    format!("selectiveDisclosure_{n_notes}")
}

fn disclosure_index(n_notes: usize) -> Result<usize, JsError> {
    if n_notes == 0 || n_notes > 4 {
        return Err(JsError::new("selective disclosure supports 1..=4 notes"));
    }
    n_notes
        .checked_sub(1)
        .ok_or_else(|| JsError::new("selective disclosure supports 1..=4 notes"))
}

async fn ensure_disclosure_prover(n_notes: usize) -> Result<(), JsError> {
    let idx = disclosure_index(n_notes)?;
    let is_ready = DISCLOSURE_PROVERS.with(|s| s.borrow()[idx].is_some())
        && DISCLOSURE_WITNESS_CALCS.with(|s| s.borrow()[idx].is_some());

    if is_ready {
        return Ok(());
    }

    let stem = disclosure_stem(n_notes);

    let (graph_bytes, r1cs_bytes) = try_join!(
        fetch_lockfile_artifact(&stem, ArtifactKind::Graph),
        fetch_lockfile_artifact(&stem, ArtifactKind::R1cs)
    )?;

    let witness_calc = WitnessCalculator::from_graph(&graph_bytes).map_err(|e| {
        JsError::new(&format!(
            "failed to init selectiveDisclosure_{n_notes} witness calculator: {e:#}"
        ))
    })?;

    // Warm fast path: build from cached/derived uncompressed bytes (no point
    // decompression). Any failure degrades to the original compressed path so a
    // cache problem can never break proving.
    let prover = match uncompressed_pk_bytes(&stem, &r1cs_bytes).await {
        Ok(uncompressed_pk) => {
            match Groth16Prover::new_from_uncompressed_pk(&uncompressed_pk, &r1cs_bytes) {
                Ok(prover) => prover,
                Err(e) => {
                    tracing::warn!(
                        "[{WORKER_NAME}] uncompressed disclosure({n_notes}) prover build failed ({e:#}), falling back to compressed"
                    );
                    build_disclosure_from_compressed(&stem, &r1cs_bytes).await?
                }
            }
        }
        Err(e) => {
            tracing::warn!(
                "[{WORKER_NAME}] uncompressed disclosure({n_notes}) proving key unavailable ({e:?}), falling back to compressed"
            );
            build_disclosure_from_compressed(&stem, &r1cs_bytes).await?
        }
    };

    DISCLOSURE_WITNESS_CALCS.with(|cell| {
        cell.borrow_mut()[idx] = Some(witness_calc);
    });
    DISCLOSURE_PROVERS.with(|cell| {
        cell.borrow_mut()[idx] = Some(prover);
    });

    Ok(())
}

/// Fallback disclosure builder: fetch the compressed proving key and build the
/// prover via the original [`Groth16Prover::new`] (with point decompression).
async fn build_disclosure_from_compressed(
    stem: &str,
    r1cs_bytes: &[u8],
) -> Result<Groth16Prover, JsError> {
    let compressed = fetch_lockfile_artifact(stem, ArtifactKind::ProvingKey).await?;
    Groth16Prover::new(&compressed, r1cs_bytes)
        .map_err(|e| JsError::new(&format!("failed to init disclosure prover: {e:#}")))
}

async fn uncompressed_pk_bytes(stem: &str, r1cs_bytes: &[u8]) -> Result<Vec<u8>, JsError> {
    let pk_name = artifact_file_name(stem, ArtifactKind::ProvingKey);
    let pk_name_for_closure = pk_name.clone();
    let stem = stem.to_string();
    let r1cs_bytes = r1cs_bytes.to_vec();
    let pk_sha256 = artifact_sha256_bytes(&stem, ArtifactKind::ProvingKey)
        .map_err(|e| JsError::new(&e.to_string()))?;
    get_or_derive_uncompressed(&pk_name, pk_sha256, move || async move {
        let compressed = fetch_lockfile_artifact(&stem, ArtifactKind::ProvingKey).await?;
        let tmp = Groth16Prover::new(&compressed, &r1cs_bytes).map_err(|e| {
            JsError::new(&format!(
                "failed to build prover for uncompressed export ({pk_name_for_closure}): {e:#}"
            ))
        })?;
        tmp.get_uncompressed_proving_key().map_err(|e| {
            JsError::new(&format!(
                "failed to export uncompressed proving key ({pk_name_for_closure}): {e:#}"
            ))
        })
    })
    .await
}

async fn load_circuit_artifacts() -> Result<(), JsError> {
    let policy_stems: Vec<String> = CircuitStem::all_transact_stems()
        .into_iter()
        .map(|stem| stem.to_string())
        .collect();

    let transact_ready = TRANSACT_PROVERS.with(|s| {
        policy_stems
            .iter()
            .all(|stem| s.borrow().contains_key(stem))
    });
    let all_ready = transact_ready
        && DISCLOSURE_WITNESS_CALCS.with(|s| s.borrow().iter().all(|c| c.is_some()))
        && DISCLOSURE_PROVERS.with(|s| s.borrow().iter().all(|p| p.is_some()));
    if all_ready {
        return Ok(());
    }

    let to_load: Vec<(&str, &[u8])> = policy_stems
        .iter()
        .filter_map(|stem| {
            if TRANSACT_PROVERS.with(|s| s.borrow().contains_key(stem)) {
                return None;
            }
            crate::bundled_proving_keys::bundled_policy_proving_key(stem)
                .map(|proving_key| (stem.as_str(), proving_key))
        })
        .collect();

    if !to_load.is_empty() {
        let transact_artifacts: Vec<(Vec<u8>, Vec<u8>)> =
            futures::future::try_join_all(to_load.iter().map(|&(stem, _)| async move {
                let graph = fetch_lockfile_artifact(stem, ArtifactKind::Graph).await?;
                let r1cs = fetch_lockfile_artifact(stem, ArtifactKind::R1cs).await?;
                Ok::<_, JsError>((graph, r1cs))
            }))
            .await?;

        let mut loaded = Vec::with_capacity(to_load.len());
        for (&(stem, proving_key), (graph_bytes, r1cs_bytes)) in
            to_load.iter().zip(transact_artifacts.iter())
        {
            let prover = build_transact_prover(stem, proving_key, graph_bytes, r1cs_bytes).await?;
            loaded.push((stem.to_owned(), prover));
        }

        TRANSACT_PROVERS.with(|cell| {
            let mut borrow = cell.borrow_mut();
            for (stem, prover) in loaded {
                borrow.insert(stem, prover);
            }
        });
    }

    Ok(())
}

/// Build the transact [`ProverEngine`] for `stem`, preferring the uncompressed
/// Cache-API fast path (skips point decompression) and falling back to
/// [`init_transact_prover`] (full verification, compressed decompression) on
/// any cache or build failure.
///
/// `bundled_compressed_pk` is the compile-time embedded proving key for `stem`
/// (see `crate::bundled_proving_keys::bundled_policy_proving_key`) — it is
/// never fetched over the network, so the fast path derives its uncompressed
/// cache entry directly from it with no additional I/O; only the CPU cost of
/// point decompression is skipped on a warm cache, not a network round trip.
async fn build_transact_prover(
    stem: &str,
    bundled_compressed_pk: &[u8],
    graph_bytes: &[u8],
    r1cs_bytes: &[u8],
) -> Result<ProverEngine, JsError> {
    let pk_name = artifact_file_name(stem, ArtifactKind::ProvingKey);
    let pk_name_for_log = pk_name.clone();
    let pk_name_for_closure = pk_name.clone();
    let pk_sha256 = artifact_sha256_bytes(stem, ArtifactKind::ProvingKey)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let r1cs_bytes_for_closure = r1cs_bytes.to_vec();
    let bundled_for_closure = bundled_compressed_pk.to_vec();

    let fast_path = get_or_derive_uncompressed(&pk_name, pk_sha256, move || async move {
        let tmp =
            Groth16Prover::new(&bundled_for_closure, &r1cs_bytes_for_closure).map_err(|e| {
                JsError::new(&format!(
                    "failed to build prover for uncompressed export ({pk_name_for_closure}): {e:#}"
                ))
            })?;
        tmp.get_uncompressed_proving_key().map_err(|e| {
            JsError::new(&format!(
                "failed to export uncompressed proving key ({pk_name_for_closure}): {e:#}"
            ))
        })
    })
    .await;

    match fast_path {
        Ok(uncompressed_pk) => {
            match ProverEngine::new_from_uncompressed_pk(&uncompressed_pk, graph_bytes, r1cs_bytes)
            {
                Ok(engine) => return Ok(engine),
                Err(e) => {
                    tracing::warn!(
                        "[{WORKER_NAME}] uncompressed transact({pk_name_for_log}) prover build failed ({e:#}), falling back to compressed"
                    );
                }
            }
        }
        Err(e) => {
            tracing::warn!(
                "[{WORKER_NAME}] uncompressed transact({pk_name_for_log}) proving key unavailable ({e:?}), falling back to compressed"
            );
        }
    }

    init_transact_prover(stem, bundled_compressed_pk, graph_bytes, r1cs_bytes)
}

pub fn worker_main() {
    let worker_span = tracing::info_span!("worker", worker = "prover");
    {
        let _guard = worker_span.enter();
        crate::telemetry::init_telemetry(None);
        crate::telemetry::install_panic_hook();
        tracing::debug!("[{WORKER_NAME}] starting...");
    }
    ProverWorker::registrar().register();
    spawn_local(
        async move {
            if let Err(e) = init().await {
                tracing::error!("[{WORKER_NAME}] init failed: {e:?}");
            }
        }
        .instrument(worker_span),
    );
}

async fn init() -> Result<(), JsError> {
    INIT_STATE.with(|s| *s.borrow_mut() = InitState::Pending);

    match load_circuit_artifacts().await {
        Ok(()) => {
            INIT_STATE.with(|s| *s.borrow_mut() = InitState::Ready);
            tracing::debug!("[{WORKER_NAME}] initialized");
            Ok(())
        }
        Err(e) => {
            let msg = format!("{e:?}");
            INIT_STATE.with(|s| *s.borrow_mut() = InitState::Failed(msg.clone()));
            Err(e)
        }
    }
}

#[oneshot]
pub(crate) async fn ProverWorker(
    req: CorrelatedRequest<ProverWorkerRequest>,
) -> ProverWorkerResponse {
    let correlation_id = req.correlation_id;
    let worker_span = tracing::info_span!(
        "worker_request",
        worker = "prover",
        correlation_id = correlation_id.as_str()
    );
    async move {
        match router(req.payload).await {
            Ok(r) => r,
            Err(e) => ProverWorkerResponse::Error(e.to_string()),
        }
    }
    .instrument(worker_span)
    .await
}

// Main router of worker requests
pub(crate) async fn router(req: ProverWorkerRequest) -> Result<ProverWorkerResponse> {
    let resp = match req {
        ProverWorkerRequest::Ping => {
            tracing::trace!("[{WORKER_NAME}] ping");
            loop {
                match INIT_STATE.with(|s| s.borrow().clone()) {
                    InitState::Ready => {
                        tracing::trace!("[{WORKER_NAME}] pong");
                        return Ok(ProverWorkerResponse::Pong);
                    }
                    InitState::Failed(msg) => {
                        tracing::debug!("[{WORKER_NAME}] ping -> init failed");
                        return Ok(ProverWorkerResponse::Error(msg));
                    }
                    InitState::Pending => {}
                }

                TimeoutFuture::new(50).await;
            }
        }
        ProverWorkerRequest::Transact(params) => {
            tracing::debug!("[{WORKER_NAME}] transact");
            let stem = CircuitStem::transact(params.policy_flags, params.gvk_mode).to_string();
            let prepared = TRANSACT_PROVERS.with(|cell| {
                let mut borrow = cell.borrow_mut();
                let engine = borrow.get_mut(&stem).ok_or_else(|| {
                    anyhow::anyhow!("transact prover for {stem} is not initialized")
                })?;
                engine.prove_transact(params)
            })?;
            ProverWorkerResponse::TransactPrepared(prepared)
        }
        ProverWorkerRequest::Disclosure(req) => {
            tracing::debug!("[{WORKER_NAME}] disclosure");

            let context = req.context;
            let ext_context_hash = disclosure::derive_ext_context_hash(&context)?;

            let n_notes = req.notes.len();
            ensure_disclosure_prover(n_notes)
                .await
                .map_err(|e| anyhow::anyhow!("{e:?}"))?;
            let idx = disclosure_index(n_notes).map_err(|e| anyhow::anyhow!("{e:?}"))?;

            let roots: Vec<_> = req.notes.iter().map(|input| input.root).collect();
            let note_commitments: Vec<_> = req
                .notes
                .iter()
                .map(|input| input.note_commitment)
                .collect();

            let notes: Vec<DisclosureNote> = req
                .notes
                .into_iter()
                .map(|input| DisclosureNote {
                    root: input.root,
                    note_commitment: input.note_commitment,
                    note_amount: input.note_amount,
                    note_private_key: input.note_private_key,
                    note_blinding: input.note_blinding,
                    merkle_path_indices: input.merkle_path_indices,
                    merkle_path_elements: input.merkle_path_elements,
                })
                .collect();

            let params = SelectiveDisclosureParams {
                notes,
                ext_context_hash,
            };

            let artifacts = selective_disclosure(params)?;
            let nullifiers = artifacts.nullifiers.clone();
            let amounts = artifacts.amounts.clone();
            let circuit_inputs_json = serde_json::to_string(&artifacts.circuit_inputs)?;

            let witness_bytes = DISCLOSURE_WITNESS_CALCS.with(|cell| {
                let mut borrow = cell.borrow_mut();
                let calc = borrow[idx].as_mut().ok_or_else(|| {
                    anyhow::anyhow!("disclosure witness calculator is not initialized")
                })?;
                calc.compute_witness(&circuit_inputs_json)
                    .context("disclosure witness calculation failed")
            })?;

            let (proof_compressed, vk_hash_hex) = DISCLOSURE_PROVERS.with(|cell| {
                let borrow = cell.borrow();
                let prover = borrow[idx]
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("disclosure prover is not initialized"))?;
                let proved = disclosure::prove_receipt_proof_with_prover(prover, &witness_bytes)?;

                let vk_bytes = prover.get_verifying_key()?;
                let vk_hash_hex = disclosure::vk_hash_hex(&vk_bytes);

                Ok::<_, anyhow::Error>((proved.proof_compressed, vk_hash_hex))
            })?;

            let proof_compressed_hex = format!("0x{}", to_hex(&proof_compressed));

            let (circuit_name, levels, n_notes_const) = match n_notes {
                1 => (
                    SELECTIVE_DISCLOSURE_1_CIRCUIT,
                    SELECTIVE_DISCLOSURE_1_LEVELS,
                    SELECTIVE_DISCLOSURE_1_N_NOTES,
                ),
                2 => (
                    SELECTIVE_DISCLOSURE_2_CIRCUIT,
                    SELECTIVE_DISCLOSURE_2_LEVELS,
                    SELECTIVE_DISCLOSURE_2_N_NOTES,
                ),
                3 => (
                    SELECTIVE_DISCLOSURE_3_CIRCUIT,
                    SELECTIVE_DISCLOSURE_3_LEVELS,
                    SELECTIVE_DISCLOSURE_3_N_NOTES,
                ),
                4 => (
                    SELECTIVE_DISCLOSURE_4_CIRCUIT,
                    SELECTIVE_DISCLOSURE_4_LEVELS,
                    SELECTIVE_DISCLOSURE_4_N_NOTES,
                ),
                _ => anyhow::bail!("unsupported disclosure note count: {n_notes}"),
            };

            let receipt = DisclosureReceipt {
                version: DISCLOSURE_RECEIPT_VERSION,
                circuit: DisclosureCircuitMetadata {
                    name: circuit_name.to_string(),
                    levels,
                    n_notes: n_notes_const,
                    vk_hash: vk_hash_hex,
                },
                context,
                public_inputs: DisclosurePublicInputs {
                    roots,
                    note_commitments,
                    ext_context_hash,
                    nullifiers,
                    amounts,
                },
                proof_compressed_hex,
                issued_at: disclosure::current_issued_at()?,
            };

            ProverWorkerResponse::Disclosure(receipt)
        }
        ProverWorkerRequest::ConfigureTelemetry(config) => {
            let _ = crate::telemetry::set_log_level(&config.level);
            stellar_private_payments::types::set_reveal_sensitive(config.reveal_sensitive);
            ProverWorkerResponse::Pong
        }
        ProverWorkerRequest::DumpLogs => {
            ProverWorkerResponse::Logs(crate::telemetry::dump_recent_logs())
        }
        ProverWorkerRequest::VerifyDisclosureProof(receipt, expected_vk_hash) => {
            tracing::debug!("[{WORKER_NAME}] verify disclosure proof");

            disclosure::validate_registered_receipt(&receipt, &expected_vk_hash)?;

            let n_notes = usize::try_from(receipt.circuit.n_notes)
                .map_err(|e| anyhow::anyhow!("invalid n_notes: {e}"))?;
            ensure_disclosure_prover(n_notes)
                .await
                .map_err(|e| anyhow::anyhow!("{e:?}"))?;
            let idx = disclosure_index(n_notes).map_err(|e| anyhow::anyhow!("{e:?}"))?;

            let proof_verified = DISCLOSURE_PROVERS.with(|cell| {
                let borrow = cell.borrow();
                let prover = borrow[idx]
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("disclosure prover is not initialized"))?;

                let vk_bytes = prover.get_verifying_key()?;
                disclosure::verify_receipt_proof(&receipt, &vk_bytes, &expected_vk_hash)
            })?;

            ProverWorkerResponse::DisclosureProofVerified(proof_verified)
        }
    };
    Ok(resp)
}

const PROVE_TIMEOUT_MS: u32 = 30_000;

/// Prover worker bridge — main-thread ↔ worker I/O for Groth16 proving.
pub(crate) struct ProverBridge {
    bridge: OneshotBridge<ProverWorker>,
}

impl Clone for ProverBridge {
    fn clone(&self) -> Self {
        Self {
            bridge: self.bridge.fork(),
        }
    }
}

impl ProverBridge {
    pub(crate) fn new(bridge: OneshotBridge<ProverWorker>) -> Self {
        Self { bridge }
    }

    pub(crate) async fn call(
        &self,
        req: ProverWorkerRequest,
        timeout_ms: u32,
    ) -> anyhow::Result<ProverWorkerResponse> {
        let correlated_req = CorrelatedRequest {
            correlation_id: crate::correlation::current_correlation_id()
                .unwrap_or_else(|| "-".to_string()),
            payload: req,
        };
        let mut bridge = self.bridge.fork();
        let fut = bridge.run(correlated_req).fuse();
        let timeout = TimeoutFuture::new(timeout_ms).fuse();

        futures::pin_mut!(fut, timeout);

        let resp = futures::select! {
            value = fut => value,
            _ = timeout => {
                return Err(anyhow!("operation timed out after {timeout_ms} ms"));
            }
        };

        match resp {
            ProverWorkerResponse::Error(e) => Err(anyhow!(e)),
            other => Ok(other),
        }
    }

    pub(crate) async fn ping(&self) -> anyhow::Result<()> {
        match self
            .call(ProverWorkerRequest::Ping, PROVE_TIMEOUT_MS)
            .await?
        {
            ProverWorkerResponse::Pong => Ok(()),
            other => Err(anyhow!("unexpected response: {other:?}")),
        }
    }
}

#[async_trait::async_trait(?Send)]
impl Prover for ProverBridge {
    async fn prove_transact(&self, params: TransactParams) -> Result<PreparedProverTx, Error> {
        match self
            .call(ProverWorkerRequest::Transact(params), PROVE_TIMEOUT_MS)
            .await
        {
            Ok(ProverWorkerResponse::TransactPrepared(prepared)) => Ok(prepared),
            Ok(other) => Err(Error::Other(format!(
                "unexpected prover worker response: {other:?}"
            ))),
            Err(e) => Err(Error::Other(e.to_string())),
        }
    }

    async fn prove_disclosure(
        &self,
        params: stellar_private_payments::DisclosureProveParams,
    ) -> Result<DisclosureReceipt, Error> {
        match self
            .call(ProverWorkerRequest::Disclosure(params), PROVE_TIMEOUT_MS)
            .await
        {
            Ok(ProverWorkerResponse::Disclosure(receipt)) => Ok(receipt),
            Ok(other) => Err(Error::Other(format!(
                "unexpected prover worker response: {other:?}"
            ))),
            Err(e) => Err(Error::Other(e.to_string())),
        }
    }

    async fn verify_disclosure_proof(
        &self,
        receipt: &DisclosureReceipt,
        expected_vk_hash: &str,
    ) -> Result<bool, Error> {
        match self
            .call(
                ProverWorkerRequest::VerifyDisclosureProof(
                    receipt.clone(),
                    expected_vk_hash.to_string(),
                ),
                PROVE_TIMEOUT_MS,
            )
            .await
        {
            Ok(ProverWorkerResponse::DisclosureProofVerified(v)) => Ok(v),
            Ok(other) => Err(Error::Other(format!(
                "unexpected prover worker response: {other:?}"
            ))),
            Err(e) => Err(Error::Other(e.to_string())),
        }
    }
}
