use crate::{
    circuits::fetch_circuit_file,
    protocol::{ProverWorkerRequest, ProverWorkerResponse},
};
use anyhow::{Context as _, Result, anyhow};
use futures::{FutureExt, try_join};
use gloo_timers::future::TimeoutFuture;
use gloo_worker::{
    Registrable,
    oneshot::{OneshotBridge, oneshot},
};
use sha2::{Digest as _, Sha256};
use std::{cell::RefCell, fmt::Write as _};
use stellar_private_payments_sdk::{
    PoolError, PreparedProverTx, Prover, ProverEngine, disclosure,
    proving::{Prover as Groth16Prover, WitnessCalculator},
    tx::flows::{SelectiveDisclosure1Params, TransactParams, selective_disclosure_1},
    types::{
        DISCLOSURE_RECEIPT_VERSION, DisclosureCircuitMetadata, DisclosurePublicInputs,
        DisclosureReceipt, SELECTIVE_DISCLOSURE_1_CIRCUIT, SELECTIVE_DISCLOSURE_1_LEVELS,
        SELECTIVE_DISCLOSURE_1_N_NOTES,
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

// TODO make it dependent on the network during the compilation
const PROVING_KEY: &[u8] =
    include_bytes!("../../../../deployments/testnet/circuit_keys/policy_tx_2_2_proving_key.bin");
const DISCLOSURE_PROVING_KEY: &[u8] = include_bytes!(
    "../../../../deployments/testnet/circuit_keys/selectiveDisclosure_1_proving_key.bin"
);

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..]);
    out
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().wrapping_mul(2));
    for b in bytes {
        write!(&mut out, "{:02x}", b).expect("writing to String should not fail");
    }
    out
}

fn ensure_sha256_matches(
    name: &str,
    bytes: &[u8],
    expected_len: usize,
    expected_sha256: [u8; 32],
) -> Result<(), JsError> {
    if bytes.len() != expected_len {
        return Err(JsError::new(&format!(
            "{name} length mismatch: expected={}, got={}",
            expected_len,
            bytes.len(),
        )));
    }
    let actual = sha256(bytes);
    if actual != expected_sha256 {
        return Err(JsError::new(&format!(
            "{name} SHA256 mismatch: expected={}, got={}",
            to_hex(&expected_sha256),
            to_hex(&actual),
        )));
    }
    Ok(())
}

// TODO for now it is a mix of async (because we want an async bridge for the
// main thread) and sync (blocking) code in the future we should refactor to use
// wasm threads?

thread_local! {
    static TRANSACT_PROVER: RefCell<Option<ProverEngine>> = const { RefCell::new(None) };
    static DISCLOSURE_WITNESS_CALC: RefCell<Option<WitnessCalculator>> = const { RefCell::new(None) };
    static DISCLOSURE_PROVER: RefCell<Option<Groth16Prover>> = const { RefCell::new(None) };
    static INIT_STATE: RefCell<InitState> = const { RefCell::new(InitState::Pending) };
}

async fn load_circuit_artifacts() -> Result<(), JsError> {
    if TRANSACT_PROVER.with(|s| s.borrow().is_some())
        && DISCLOSURE_WITNESS_CALC.with(|s| s.borrow().is_some())
        && DISCLOSURE_PROVER.with(|s| s.borrow().is_some())
    {
        return Ok(());
    }

    let (wasm_bytes, r1cs_bytes, disc_wasm_bytes, disc_r1cs_bytes) = try_join!(
        async {
            let wasm_bytes: Vec<u8> = fetch_circuit_file("policy_tx_2_2.wasm").await?;
            log::debug!(
                "[{WORKER_NAME}] fetched policy_tx_2_2.wasm: {} bytes",
                wasm_bytes.len()
            );
            Ok::<Vec<u8>, JsError>(wasm_bytes)
        },
        async {
            let r1cs_bytes: Vec<u8> = fetch_circuit_file("policy_tx_2_2.r1cs").await?;
            log::debug!(
                "[{WORKER_NAME}] fetched policy_tx_2_2.r1cs: {} bytes",
                r1cs_bytes.len()
            );
            Ok::<Vec<u8>, JsError>(r1cs_bytes)
        },
        async {
            let wasm_bytes: Vec<u8> = fetch_circuit_file("selectiveDisclosure_1.wasm").await?;
            log::debug!(
                "[{WORKER_NAME}] fetched selectiveDisclosure_1.wasm: {} bytes",
                wasm_bytes.len()
            );
            Ok::<Vec<u8>, JsError>(wasm_bytes)
        },
        async {
            let r1cs_bytes: Vec<u8> = fetch_circuit_file("selectiveDisclosure_1.r1cs").await?;
            log::debug!(
                "[{WORKER_NAME}] fetched selectiveDisclosure_1.r1cs: {} bytes",
                r1cs_bytes.len()
            );
            Ok::<Vec<u8>, JsError>(r1cs_bytes)
        }
    )?;

    // Integrity checks (regular builds): ensure we are using the exact
    // artifact versions this binary was built against.
    ensure_sha256_matches(
        "policy_tx_2_2_proving_key.bin",
        PROVING_KEY,
        crate::artifact_hashes::EXPECTED_POLICY_TX_2_2_PROVING_KEY_LEN,
        crate::artifact_hashes::EXPECTED_POLICY_TX_2_2_PROVING_KEY_SHA256,
    )?;
    ensure_sha256_matches(
        "policy_tx_2_2.wasm",
        &wasm_bytes,
        crate::artifact_hashes::EXPECTED_POLICY_TX_2_2_WASM_LEN,
        crate::artifact_hashes::EXPECTED_POLICY_TX_2_2_WASM_SHA256,
    )?;
    ensure_sha256_matches(
        "policy_tx_2_2.r1cs",
        &r1cs_bytes,
        crate::artifact_hashes::EXPECTED_POLICY_TX_2_2_R1CS_LEN,
        crate::artifact_hashes::EXPECTED_POLICY_TX_2_2_R1CS_SHA256,
    )?;

    ensure_sha256_matches(
        "selectiveDisclosure_1_proving_key.bin",
        DISCLOSURE_PROVING_KEY,
        crate::artifact_hashes::EXPECTED_SELECTIVE_DISCLOSURE_1_PROVING_KEY_LEN,
        crate::artifact_hashes::EXPECTED_SELECTIVE_DISCLOSURE_1_PROVING_KEY_SHA256,
    )?;
    ensure_sha256_matches(
        "selectiveDisclosure_1.wasm",
        &disc_wasm_bytes,
        crate::artifact_hashes::EXPECTED_SELECTIVE_DISCLOSURE_1_WASM_LEN,
        crate::artifact_hashes::EXPECTED_SELECTIVE_DISCLOSURE_1_WASM_SHA256,
    )?;
    ensure_sha256_matches(
        "selectiveDisclosure_1.r1cs",
        &disc_r1cs_bytes,
        crate::artifact_hashes::EXPECTED_SELECTIVE_DISCLOSURE_1_R1CS_LEN,
        crate::artifact_hashes::EXPECTED_SELECTIVE_DISCLOSURE_1_R1CS_SHA256,
    )?;

    let transact_prover = ProverEngine::new(PROVING_KEY, &wasm_bytes, &r1cs_bytes)
        .map_err(|e| JsError::new(&format!("failed to init transact prover: {e:#}")))?;

    let disc_witness_calc =
        WitnessCalculator::new(&disc_wasm_bytes, &disc_r1cs_bytes).map_err(|e| {
            JsError::new(&format!(
                "failed to init disclosure witness calculator: {e:#}"
            ))
        })?;
    let disc_prover = Groth16Prover::new(DISCLOSURE_PROVING_KEY, &disc_r1cs_bytes)
        .map_err(|e| JsError::new(&format!("failed to init disclosure prover: {e:#}")))?;

    TRANSACT_PROVER.with(|cell| {
        *cell.borrow_mut() = Some(transact_prover);
    });
    DISCLOSURE_WITNESS_CALC.with(|cell| {
        *cell.borrow_mut() = Some(disc_witness_calc);
    });
    DISCLOSURE_PROVER.with(|cell| {
        *cell.borrow_mut() = Some(disc_prover);
    });
    Ok(())
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
            let prepared = TRANSACT_PROVER.with(|cell| {
                let mut borrow = cell.borrow_mut();
                let engine = borrow
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("transact prover is not initialized"))?;
                engine.prove_transact(params)
            })?;
            ProverWorkerResponse::TransactPrepared(prepared)
        }
        ProverWorkerRequest::Disclosure(req) => {
            log::debug!("[{WORKER_NAME}] disclosure");

            let context = req.context;
            let ext_context_hash = disclosure::derive_ext_context_hash(&context)?;

            let params = SelectiveDisclosure1Params {
                root: req.inputs.root,
                note_commitment: req.inputs.note_commitment,
                note_amount: req.inputs.note_amount,
                note_private_key: req.inputs.note_private_key,
                note_blinding: req.inputs.note_blinding,
                merkle_path_indices: req.inputs.merkle_path_indices,
                merkle_path_elements: req.inputs.merkle_path_elements,
                ext_context_hash,
            };

            let artifacts = selective_disclosure_1(params)?;
            let circuit_inputs_json = serde_json::to_string(&artifacts.circuit_inputs)?;

            let witness_bytes = DISCLOSURE_WITNESS_CALC.with(|cell| {
                let mut borrow = cell.borrow_mut();
                let calc = borrow.as_mut().ok_or_else(|| {
                    anyhow::anyhow!("disclosure witness calculator is not initialized")
                })?;
                calc.compute_witness(&circuit_inputs_json)
                    .context("disclosure witness calculation failed")
            })?;

            let (proof_compressed, vk_hash_hex) = DISCLOSURE_PROVER.with(|cell| {
                let borrow = cell.borrow();
                let prover = borrow
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("disclosure prover is not initialized"))?;
                let proved = disclosure::prove_receipt_proof_with_prover(prover, &witness_bytes)?;

                let vk_bytes = prover.get_verifying_key()?;
                let vk_hash_hex = disclosure::vk_hash_hex(&vk_bytes);

                Ok::<_, anyhow::Error>((proved.proof_compressed, vk_hash_hex))
            })?;

            let proof_compressed_hex = format!("0x{}", to_hex(&proof_compressed));

            let receipt = DisclosureReceipt {
                version: DISCLOSURE_RECEIPT_VERSION,
                circuit: DisclosureCircuitMetadata {
                    name: SELECTIVE_DISCLOSURE_1_CIRCUIT.to_string(),
                    levels: SELECTIVE_DISCLOSURE_1_LEVELS,
                    n_notes: SELECTIVE_DISCLOSURE_1_N_NOTES,
                    vk_hash: vk_hash_hex,
                },
                context,
                public_inputs: DisclosurePublicInputs {
                    roots: vec![req.inputs.root],
                    note_commitments: vec![req.inputs.note_commitment],
                    ext_context_hash,
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

            let proof_verified = DISCLOSURE_PROVER.with(|cell| {
                let borrow = cell.borrow();
                let prover = borrow
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

const PROVE_TIMEOUT_MS: u32 = 20_000;

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
        match self.call(ProverWorkerRequest::Ping, 5_000).await? {
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
