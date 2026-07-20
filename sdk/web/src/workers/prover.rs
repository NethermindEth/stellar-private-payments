use crate::{
    circuits::{
        ensure_sha256_matches, fetch_circuit_file, fetch_circuit_file_verified,
        get_or_derive_uncompressed,
    },
    protocol::{ProverWorkerRequest, ProverWorkerResponse},
};
use anyhow::{Context as _, Result, anyhow};
use futures::{FutureExt, try_join};
use gloo_timers::future::TimeoutFuture;
use gloo_worker::{
    Registrable,
    oneshot::{OneshotBridge, oneshot},
};
use std::{cell::RefCell, collections::HashMap, fmt::Write as _};
use stellar_private_payments_sdk::{
    PoolError, PreparedProverTx, Prover, ProverEngine, disclosure,
    proving::{Prover as Groth16Prover, WitnessCalculator},
    tx::flows::{DisclosureNote, SelectiveDisclosureParams, TransactParams, selective_disclosure},
    types::{
        DISCLOSURE_RECEIPT_VERSION, DisclosureCircuitMetadata, DisclosurePublicInputs,
        DisclosureReceipt, SELECTIVE_DISCLOSURE_1_CIRCUIT, SELECTIVE_DISCLOSURE_1_LEVELS,
        SELECTIVE_DISCLOSURE_1_N_NOTES, SELECTIVE_DISCLOSURE_2_CIRCUIT,
        SELECTIVE_DISCLOSURE_2_LEVELS, SELECTIVE_DISCLOSURE_2_N_NOTES,
        SELECTIVE_DISCLOSURE_3_CIRCUIT, SELECTIVE_DISCLOSURE_3_LEVELS,
        SELECTIVE_DISCLOSURE_3_N_NOTES, SELECTIVE_DISCLOSURE_4_CIRCUIT,
        SELECTIVE_DISCLOSURE_4_LEVELS, SELECTIVE_DISCLOSURE_4_N_NOTES,
    },
};
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
    wasm_bytes: &[u8],
    r1cs_bytes: &[u8],
) -> Result<ProverEngine, JsError> {
    let hashes = crate::artifact_hashes::policy_transact_artifact_hashes(stem)
        .unwrap_or_else(|| panic!("unsupported transact circuit stem: {stem}"));

    ensure_sha256_matches(
        &format!("{stem}_proving_key.bin"),
        proving_key,
        hashes.proving_key_len,
        hashes.proving_key_sha256,
    )?;
    ensure_sha256_matches(
        &format!("{stem}.wasm"),
        wasm_bytes,
        hashes.wasm_len,
        hashes.wasm_sha256,
    )?;
    ensure_sha256_matches(
        &format!("{stem}.r1cs"),
        r1cs_bytes,
        hashes.r1cs_len,
        hashes.r1cs_sha256,
    )?;

    ProverEngine::new(proving_key, wasm_bytes, r1cs_bytes)
        .map_err(|e| JsError::new(&format!("failed to init {stem} transact prover: {e:#}")))
}

struct DisclosureArtifactHashes {
    proving_key_len: usize,
    proving_key_sha256: [u8; 32],
    wasm_len: usize,
    wasm_sha256: [u8; 32],
    r1cs_len: usize,
    r1cs_sha256: [u8; 32],
}

fn disclosure_hashes(n_notes: usize) -> DisclosureArtifactHashes {
    match n_notes {
        1 => DisclosureArtifactHashes {
            proving_key_len:
                crate::artifact_hashes::EXPECTED_SELECTIVE_DISCLOSURE_1_PROVING_KEY_LEN,
            proving_key_sha256:
                crate::artifact_hashes::EXPECTED_SELECTIVE_DISCLOSURE_1_PROVING_KEY_SHA256,
            wasm_len: crate::artifact_hashes::EXPECTED_SELECTIVE_DISCLOSURE_1_WASM_LEN,
            wasm_sha256: crate::artifact_hashes::EXPECTED_SELECTIVE_DISCLOSURE_1_WASM_SHA256,
            r1cs_len: crate::artifact_hashes::EXPECTED_SELECTIVE_DISCLOSURE_1_R1CS_LEN,
            r1cs_sha256: crate::artifact_hashes::EXPECTED_SELECTIVE_DISCLOSURE_1_R1CS_SHA256,
        },
        2 => DisclosureArtifactHashes {
            proving_key_len:
                crate::artifact_hashes::EXPECTED_SELECTIVE_DISCLOSURE_2_PROVING_KEY_LEN,
            proving_key_sha256:
                crate::artifact_hashes::EXPECTED_SELECTIVE_DISCLOSURE_2_PROVING_KEY_SHA256,
            wasm_len: crate::artifact_hashes::EXPECTED_SELECTIVE_DISCLOSURE_2_WASM_LEN,
            wasm_sha256: crate::artifact_hashes::EXPECTED_SELECTIVE_DISCLOSURE_2_WASM_SHA256,
            r1cs_len: crate::artifact_hashes::EXPECTED_SELECTIVE_DISCLOSURE_2_R1CS_LEN,
            r1cs_sha256: crate::artifact_hashes::EXPECTED_SELECTIVE_DISCLOSURE_2_R1CS_SHA256,
        },
        3 => DisclosureArtifactHashes {
            proving_key_len:
                crate::artifact_hashes::EXPECTED_SELECTIVE_DISCLOSURE_3_PROVING_KEY_LEN,
            proving_key_sha256:
                crate::artifact_hashes::EXPECTED_SELECTIVE_DISCLOSURE_3_PROVING_KEY_SHA256,
            wasm_len: crate::artifact_hashes::EXPECTED_SELECTIVE_DISCLOSURE_3_WASM_LEN,
            wasm_sha256: crate::artifact_hashes::EXPECTED_SELECTIVE_DISCLOSURE_3_WASM_SHA256,
            r1cs_len: crate::artifact_hashes::EXPECTED_SELECTIVE_DISCLOSURE_3_R1CS_LEN,
            r1cs_sha256: crate::artifact_hashes::EXPECTED_SELECTIVE_DISCLOSURE_3_R1CS_SHA256,
        },
        4 => DisclosureArtifactHashes {
            proving_key_len:
                crate::artifact_hashes::EXPECTED_SELECTIVE_DISCLOSURE_4_PROVING_KEY_LEN,
            proving_key_sha256:
                crate::artifact_hashes::EXPECTED_SELECTIVE_DISCLOSURE_4_PROVING_KEY_SHA256,
            wasm_len: crate::artifact_hashes::EXPECTED_SELECTIVE_DISCLOSURE_4_WASM_LEN,
            wasm_sha256: crate::artifact_hashes::EXPECTED_SELECTIVE_DISCLOSURE_4_WASM_SHA256,
            r1cs_len: crate::artifact_hashes::EXPECTED_SELECTIVE_DISCLOSURE_4_R1CS_LEN,
            r1cs_sha256: crate::artifact_hashes::EXPECTED_SELECTIVE_DISCLOSURE_4_R1CS_SHA256,
        },
        _ => panic!("unsupported disclosure note count: {n_notes}"),
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

    let pk_name = format!("selectiveDisclosure_{n_notes}_proving_key.bin");
    let wasm_name = format!("selectiveDisclosure_{n_notes}.wasm");
    let r1cs_name = format!("selectiveDisclosure_{n_notes}.r1cs");

    let hashes = disclosure_hashes(n_notes);

    // wasm + r1cs are needed on both the warm and the fallback path, so fetch
    // them concurrently up front. The (large) proving key is fetched lazily —
    // only on an uncompressed-cache miss or during fallback.
    let (wasm_bytes, r1cs_bytes) = try_join!(
        fetch_circuit_file_verified(&wasm_name, hashes.wasm_len, hashes.wasm_sha256),
        fetch_circuit_file_verified(&r1cs_name, hashes.r1cs_len, hashes.r1cs_sha256)
    )?;

    let witness_calc = WitnessCalculator::new(&wasm_bytes, &r1cs_bytes).map_err(|e| {
        JsError::new(&format!(
            "failed to init selectiveDisclosure_{n_notes} witness calculator: {e:#}"
        ))
    })?;

    // Warm fast path: build from cached/derived uncompressed bytes (no point
    // decompression). Any failure degrades to the original compressed path so a
    // cache problem can never break proving.
    let prover = match uncompressed_pk_bytes(
        &pk_name,
        hashes.proving_key_len,
        hashes.proving_key_sha256,
        &r1cs_bytes,
    )
    .await
    {
        Ok(uncompressed_pk) => {
            match Groth16Prover::new_from_uncompressed_pk(&uncompressed_pk, &r1cs_bytes) {
                Ok(prover) => prover,
                Err(e) => {
                    log::warn!(
                        "[{WORKER_NAME}] uncompressed disclosure({n_notes}) prover build failed ({e:#}), falling back to compressed"
                    );
                    build_disclosure_from_compressed(&pk_name, &hashes, &r1cs_bytes).await?
                }
            }
        }
        Err(e) => {
            log::warn!(
                "[{WORKER_NAME}] uncompressed disclosure({n_notes}) proving key unavailable ({e:?}), falling back to compressed"
            );
            build_disclosure_from_compressed(&pk_name, &hashes, &r1cs_bytes).await?
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
    pk_name: &str,
    hashes: &DisclosureArtifactHashes,
    r1cs_bytes: &[u8],
) -> Result<Groth16Prover, JsError> {
    let compressed =
        fetch_circuit_file_verified(pk_name, hashes.proving_key_len, hashes.proving_key_sha256)
            .await?;
    Groth16Prover::new(&compressed, r1cs_bytes)
        .map_err(|e| JsError::new(&format!("failed to init disclosure prover: {e:#}")))
}

/// Return uncompressed proving-key bytes for `pk_name`, served from the Cache
/// API when warm and derived from the compressed artifact on a miss.
///
/// The derive path (miss only) fetches the compressed proving key, builds a
/// throwaway [`Groth16Prover`] purely to re-serialize the key in arkworks
/// uncompressed form, and lets [`get_or_derive_uncompressed`] store it. On a
/// warm cache neither the compressed fetch nor the point-decompression happens.
/// Any error (cache, fetch, or build) is returned so the caller can fall back
/// to the compressed constructor. Shared by the transact and disclosure
/// loaders.
async fn uncompressed_pk_bytes(
    pk_name: &str,
    pk_len: usize,
    pk_sha256: [u8; 32],
    r1cs_bytes: &[u8],
) -> Result<Vec<u8>, JsError> {
    get_or_derive_uncompressed(pk_name, pk_sha256, move || async move {
        let compressed = fetch_circuit_file_verified(pk_name, pk_len, pk_sha256).await?;
        let tmp = Groth16Prover::new(&compressed, r1cs_bytes).map_err(|e| {
            JsError::new(&format!(
                "failed to build prover for uncompressed export ({pk_name}): {e:#}"
            ))
        })?;
        tmp.get_uncompressed_proving_key().map_err(|e| {
            JsError::new(&format!(
                "failed to export uncompressed proving key ({pk_name}): {e:#}"
            ))
        })
    })
    .await
}

async fn load_circuit_artifacts() -> Result<(), JsError> {
    let transact_ready = TRANSACT_PROVERS.with(|s| {
        crate::artifact_hashes::POLICY_TRANSACT_CIRCUIT_STEMS
            .iter()
            .all(|stem| s.borrow().contains_key(*stem))
    });
    let all_ready = transact_ready
        && DISCLOSURE_WITNESS_CALCS.with(|s| s.borrow().iter().all(|c| c.is_some()))
        && DISCLOSURE_PROVERS.with(|s| s.borrow().iter().all(|p| p.is_some()));
    if all_ready {
        return Ok(());
    }

    let to_load: Vec<(&str, &[u8])> = crate::artifact_hashes::POLICY_TRANSACT_CIRCUIT_STEMS
        .iter()
        .filter_map(|&stem| {
            if TRANSACT_PROVERS.with(|s| s.borrow().contains_key(stem)) {
                return None;
            }
            crate::artifact_hashes::bundled_policy_proving_key(stem)
                .map(|proving_key| (stem, proving_key))
        })
        .collect();

    if !to_load.is_empty() {
        let transact_artifacts: Vec<(Vec<u8>, Vec<u8>)> =
            futures::future::try_join_all(to_load.iter().map(|&(stem, _)| async move {
                let wasm = fetch_circuit_file(&format!("{stem}.wasm")).await?;
                let r1cs = fetch_circuit_file(&format!("{stem}.r1cs")).await?;
                Ok::<_, JsError>((wasm, r1cs))
            }))
            .await?;

        let mut loaded = Vec::with_capacity(to_load.len());
        for (&(stem, proving_key), (wasm_bytes, r1cs_bytes)) in
            to_load.iter().zip(transact_artifacts.iter())
        {
            let prover = build_transact_prover(stem, proving_key, wasm_bytes, r1cs_bytes).await?;
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
/// (see `crate::artifact_hashes::bundled_policy_proving_key`) — it is never
/// fetched over the network, so the fast path derives its uncompressed cache
/// entry directly from it with no additional I/O; only the CPU cost of point
/// decompression is skipped on a warm cache, not a network round trip.
async fn build_transact_prover(
    stem: &str,
    bundled_compressed_pk: &[u8],
    wasm_bytes: &[u8],
    r1cs_bytes: &[u8],
) -> Result<ProverEngine, JsError> {
    let hashes = crate::artifact_hashes::policy_transact_artifact_hashes(stem)
        .unwrap_or_else(|| panic!("unsupported transact circuit stem: {stem}"));
    let pk_name = format!("{stem}_proving_key.bin");
    let pk_name_for_log = pk_name.clone();
    let pk_name_for_closure = pk_name.clone();

    let fast_path =
        get_or_derive_uncompressed(&pk_name, hashes.proving_key_sha256, move || async move {
            let tmp = Groth16Prover::new(bundled_compressed_pk, r1cs_bytes).map_err(|e| {
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
            match ProverEngine::new_from_uncompressed_pk(&uncompressed_pk, wasm_bytes, r1cs_bytes) {
                Ok(engine) => return Ok(engine),
                Err(e) => {
                    log::warn!(
                        "[{WORKER_NAME}] uncompressed transact({pk_name_for_log}) prover build failed ({e:#}), falling back to compressed"
                    );
                }
            }
        }
        Err(e) => {
            log::warn!(
                "[{WORKER_NAME}] uncompressed transact({pk_name_for_log}) proving key unavailable ({e:?}), falling back to compressed"
            );
        }
    }

    init_transact_prover(stem, bundled_compressed_pk, wasm_bytes, r1cs_bytes)
}

pub fn worker_main() {
    console_error_panic_hook::set_once();
    wasm_log::init(wasm_log::Config::default());
    log::debug!("[{WORKER_NAME}] starting...");
    ProverWorker::registrar().register();
    spawn_local(async {
        if let Err(e) = init().await {
            log::error!("[{WORKER_NAME}] init failed: {e:?}");
        }
    });
}

async fn init() -> Result<(), JsError> {
    INIT_STATE.with(|s| *s.borrow_mut() = InitState::Pending);

    match load_circuit_artifacts().await {
        Ok(()) => {
            INIT_STATE.with(|s| *s.borrow_mut() = InitState::Ready);
            log::debug!("[{WORKER_NAME}] initialized");
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
pub(crate) async fn ProverWorker(req: ProverWorkerRequest) -> ProverWorkerResponse {
    match router(req).await {
        Ok(r) => r,
        Err(e) => ProverWorkerResponse::Error(e.to_string()),
    }
}

// Main router of worker requests
pub(crate) async fn router(req: ProverWorkerRequest) -> Result<ProverWorkerResponse> {
    let resp = match req {
        ProverWorkerRequest::Ping => {
            log::trace!("[{WORKER_NAME}] ping");
            loop {
                match INIT_STATE.with(|s| s.borrow().clone()) {
                    InitState::Ready => {
                        log::trace!("[{WORKER_NAME}] pong");
                        return Ok(ProverWorkerResponse::Pong);
                    }
                    InitState::Failed(msg) => {
                        log::debug!("[{WORKER_NAME}] ping -> init failed");
                        return Ok(ProverWorkerResponse::Error(msg));
                    }
                    InitState::Pending => {}
                }

                TimeoutFuture::new(50).await;
            }
        }
        ProverWorkerRequest::Transact(params) => {
            log::debug!("[{WORKER_NAME}] transact");
            let stem = params.policy_flags.circuit_stem();
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
            log::debug!("[{WORKER_NAME}] disclosure");

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
                issued_at: js_sys::Date::new_0()
                    .to_iso_string()
                    .as_string()
                    .ok_or_else(|| anyhow::anyhow!("failed to get current ISO date"))?,
            };

            ProverWorkerResponse::Disclosure(receipt)
        }
        ProverWorkerRequest::VerifyDisclosureProof(receipt, expected_vk_hash) => {
            log::debug!("[{WORKER_NAME}] verify disclosure proof");

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
        let mut bridge = self.bridge.fork();
        let fut = bridge.run(req).fuse();
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
    async fn prove_transact(&self, params: TransactParams) -> Result<PreparedProverTx, PoolError> {
        match self
            .call(ProverWorkerRequest::Transact(params), PROVE_TIMEOUT_MS)
            .await
        {
            Ok(ProverWorkerResponse::TransactPrepared(prepared)) => Ok(prepared),
            Ok(other) => Err(PoolError::Other(format!(
                "unexpected prover worker response: {other:?}"
            ))),
            Err(e) => Err(PoolError::Other(e.to_string())),
        }
    }

    async fn prove_disclosure(
        &self,
        params: stellar_private_payments_sdk::DisclosureProveParams,
    ) -> Result<DisclosureReceipt, PoolError> {
        match self
            .call(ProverWorkerRequest::Disclosure(params), PROVE_TIMEOUT_MS)
            .await
        {
            Ok(ProverWorkerResponse::Disclosure(receipt)) => Ok(receipt),
            Ok(other) => Err(PoolError::Other(format!(
                "unexpected prover worker response: {other:?}"
            ))),
            Err(e) => Err(PoolError::Other(e.to_string())),
        }
    }

    async fn verify_disclosure_proof(
        &self,
        receipt: &DisclosureReceipt,
        expected_vk_hash: &str,
    ) -> Result<bool, PoolError> {
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
            Ok(other) => Err(PoolError::Other(format!(
                "unexpected prover worker response: {other:?}"
            ))),
            Err(e) => Err(PoolError::Other(e.to_string())),
        }
    }
}
