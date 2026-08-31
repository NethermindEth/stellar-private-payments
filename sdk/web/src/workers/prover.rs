use crate::{
    circuits::{fetch_circuit_artifact, get_or_derive_uncompressed},
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
    CircuitLockfile, Error, Prover, circuit_lock, disclosure,
    prover::ProverEngine,
    transact::PreparedProverTx,
    types::{
        DISCLOSURE_RECEIPT_VERSION, DisclosureCircuitMetadata, DisclosurePublicInputs,
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

const WORKER_NAME: &str = "WORKER-PROVER";

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
}

fn circuit_err(error: Error) -> JsError {
    JsError::new(&error.to_string())
}

fn init_transact_prover(
    stem: &str,
    proving_key: &[u8],
    graph_bytes: &[u8],
    r1cs_bytes: &[u8],
) -> Result<ProverEngine, JsError> {
    ProverEngine::new(proving_key, graph_bytes, r1cs_bytes)
        .map_err(|e| JsError::new(&format!("failed to init {stem} transact prover: {e:#}")))
}

fn disclosure_stem(n_notes: usize) -> Result<&'static str, JsError> {
    match n_notes {
        1 => Ok(SELECTIVE_DISCLOSURE_1_CIRCUIT),
        2 => Ok(SELECTIVE_DISCLOSURE_2_CIRCUIT),
        3 => Ok(SELECTIVE_DISCLOSURE_3_CIRCUIT),
        4 => Ok(SELECTIVE_DISCLOSURE_4_CIRCUIT),
        _ => Err(JsError::new("selective disclosure supports 1..=4 notes")),
    }
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

    let stem = disclosure_stem(n_notes)?;

    let (graph_bytes, r1cs_bytes) = try_join!(
        fetch_circuit_artifact(stem, "graph.bin"),
        fetch_circuit_artifact(stem, "r1cs")
    )?;

    let witness_calc = WitnessCalculator::from_graph(&graph_bytes).map_err(|e| {
        JsError::new(&format!(
            "failed to init selectiveDisclosure_{n_notes} witness calculator: {e:#}"
        ))
    })?;

    let prover = match uncompressed_pk_bytes(stem, &r1cs_bytes).await {
        Ok(uncompressed_pk) => {
            match Groth16Prover::new_from_uncompressed_pk(&uncompressed_pk, &r1cs_bytes) {
                Ok(prover) => prover,
                Err(e) => {
                    tracing::warn!(
                        "[{WORKER_NAME}] uncompressed disclosure({n_notes}) prover build failed ({e:#}), falling back to compressed"
                    );
                    build_disclosure_from_compressed(stem, &r1cs_bytes).await?
                }
            }
        }
        Err(e) => {
            tracing::warn!(
                "[{WORKER_NAME}] uncompressed disclosure({n_notes}) proving key unavailable ({e:?}), falling back to compressed"
            );
            build_disclosure_from_compressed(stem, &r1cs_bytes).await?
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

async fn build_disclosure_from_compressed(
    stem: &str,
    r1cs_bytes: &[u8],
) -> Result<Groth16Prover, JsError> {
    let compressed = fetch_circuit_artifact(stem, "proving_key.bin").await?;
    Groth16Prover::new(&compressed, r1cs_bytes)
        .map_err(|e| JsError::new(&format!("failed to init disclosure prover: {e:#}")))
}

async fn build_transact_from_compressed(
    stem: &str,
    graph_bytes: &[u8],
    r1cs_bytes: &[u8],
) -> Result<ProverEngine, JsError> {
    let compressed = fetch_circuit_artifact(stem, "proving_key.bin").await?;
    init_transact_prover(stem, &compressed, graph_bytes, r1cs_bytes)
}

async fn uncompressed_pk_bytes(stem: &str, r1cs_bytes: &[u8]) -> Result<Vec<u8>, JsError> {
    let lock = circuit_lock().map_err(circuit_err)?;
    let pk_name = CircuitLockfile::artifact_file_name(stem, "proving_key.bin");
    let pk_sha256 = lock
        .artifact_sha256(stem, "proving_key.bin")
        .map_err(circuit_err)?;
    let pk_name_for_log = pk_name.clone();
    let stem_owned = stem.to_owned();
    let r1cs_bytes = r1cs_bytes.to_vec();
    get_or_derive_uncompressed(&pk_name, pk_sha256, move || {
        let stem = stem_owned.clone();
        let r1cs_bytes = r1cs_bytes.clone();
        let pk_name = pk_name_for_log.clone();
        async move {
            let compressed = fetch_circuit_artifact(&stem, "proving_key.bin").await?;
            let tmp = Groth16Prover::new(&compressed, &r1cs_bytes).map_err(|e| {
                JsError::new(&format!(
                    "failed to build prover for uncompressed export ({pk_name}): {e:#}"
                ))
            })?;
            tmp.get_uncompressed_proving_key().map_err(|e| {
                JsError::new(&format!(
                    "failed to export uncompressed proving key ({pk_name}): {e:#}"
                ))
            })
        }
    })
    .await
}

async fn ensure_transact_prover(stem: &str) -> Result<(), JsError> {
    if TRANSACT_PROVERS.with(|s| s.borrow().contains_key(stem)) {
        return Ok(());
    }

    let (graph_bytes, r1cs_bytes) = try_join!(
        fetch_circuit_artifact(stem, "graph.bin"),
        fetch_circuit_artifact(stem, "r1cs")
    )?;

    let engine = build_transact_prover(stem, &graph_bytes, &r1cs_bytes).await?;

    TRANSACT_PROVERS.with(|cell| {
        cell.borrow_mut().insert(stem.to_owned(), engine);
    });

    Ok(())
}

async fn build_transact_prover(
    stem: &str,
    graph_bytes: &[u8],
    r1cs_bytes: &[u8],
) -> Result<ProverEngine, JsError> {
    let graph_bytes = graph_bytes.to_vec();
    let pk_name_for_log = CircuitLockfile::artifact_file_name(stem, "proving_key.bin");

    match uncompressed_pk_bytes(stem, r1cs_bytes).await {
        Ok(uncompressed_pk) => {
            match ProverEngine::new_from_uncompressed_pk(&uncompressed_pk, &graph_bytes, r1cs_bytes)
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

    build_transact_from_compressed(stem, &graph_bytes, r1cs_bytes).await
}

pub fn worker_main() {
    let worker_span = tracing::info_span!("worker", worker = "prover");
    {
        let _guard = worker_span.enter();
        crate::telemetry::init_telemetry(None);
        crate::telemetry::install_panic_hook();
        tracing::debug!("[{WORKER_NAME}] ready");
    }
    ProverWorker::registrar().register();
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
            tracing::trace!("[{WORKER_NAME}] ping/pong");
            ProverWorkerResponse::Pong
        }
        ProverWorkerRequest::ConfigureCircuitsBase(base_url) => {
            crate::circuits::set_circuits_base_url(base_url);
            ProverWorkerResponse::Saved
        }
        ProverWorkerRequest::Transact(params) => {
            tracing::debug!("[{WORKER_NAME}] transact");
            let stem = stellar_private_payments::types::CircuitStem::transact(
                params.policy_flags,
                params.gvk_mode,
            )
            .to_string();
            ensure_transact_prover(&stem)
                .await
                .map_err(|e| anyhow::anyhow!("{e:?}"))?;
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

    pub(crate) async fn configure_circuits_base(&self, base_url: String) -> anyhow::Result<()> {
        match self
            .call(ProverWorkerRequest::ConfigureCircuitsBase(base_url), 5_000)
            .await?
        {
            ProverWorkerResponse::Saved => Ok(()),
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
        params: stellar_private_payments::disclosure::DisclosureProveParams,
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
