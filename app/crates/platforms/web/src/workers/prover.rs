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

// TODO make it dependent on the network during the compilation
const PROVING_KEY: &[u8] = include_bytes!(
    "../../../../../../deployments/testnet/circuit_keys/policy_tx_2_2_proving_key.bin"
);

const DISCLOSURE_PROVING_KEYS: [&[u8]; 4] = [
    include_bytes!(
        "../../../../../../deployments/testnet/circuit_keys/selectiveDisclosure_1_proving_key.bin"
    ),
    include_bytes!(
        "../../../../../../deployments/testnet/circuit_keys/selectiveDisclosure_2_proving_key.bin"
    ),
    include_bytes!(
        "../../../../../../deployments/testnet/circuit_keys/selectiveDisclosure_3_proving_key.bin"
    ),
    include_bytes!(
        "../../../../../../deployments/testnet/circuit_keys/selectiveDisclosure_4_proving_key.bin"
    ),
];

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
    static DISCLOSURE_WITNESS_CALCS: RefCell<[Option<WitnessCalculator>; 4]> =
        const { RefCell::new([None, None, None, None]) };
    static DISCLOSURE_PROVERS: RefCell<[Option<Groth16Prover>; 4]> =
        const { RefCell::new([None, None, None, None]) };
}

/// Expected artifact hashes and lengths for a disclosure circuit variant.
struct DisclosureArtifactHashes {
    proving_key_len: usize,
    proving_key_sha256: [u8; 32],
    wasm_len: usize,
    wasm_sha256: [u8; 32],
    r1cs_len: usize,
    r1cs_sha256: [u8; 32],
}

/// Returns the artifact-hash constants for `selectiveDisclosure_N` (1-indexed).
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

/// Zero-based index into the disclosure arrays for a given note count.
fn disclosure_index(n_notes: usize) -> Result<usize, JsError> {
    if n_notes == 0 || n_notes > 4 {
        return Err(JsError::new("selective disclosure supports 1..=4 notes"));
    }
    n_notes
        .checked_sub(1)
        .ok_or_else(|| JsError::new("selective disclosure supports 1..=4 notes"))
}

async fn load_circuit_artifacts() -> Result<(), JsError> {
    let all_ready = TRANSACT_PROVER.with(|s| s.borrow().is_some())
        && DISCLOSURE_WITNESS_CALCS.with(|s| s.borrow().iter().all(|c| c.is_some()))
        && DISCLOSURE_PROVERS.with(|s| s.borrow().iter().all(|p| p.is_some()));
    if all_ready {
        return Ok(());
    }
    let (wasm_bytes, r1cs_bytes) = try_join!(
        async {
            let wasm_bytes: Vec<u8> = fetch_circuit_file("circuits/policy_tx_2_2.wasm").await?;
            log::debug!(
                "[{WORKER_NAME}] fetched policy_tx_2_2.wasm: {} bytes",
                wasm_bytes.len()
            );
            Ok::<Vec<u8>, JsError>(wasm_bytes)
        },
        async {
            let r1cs_bytes: Vec<u8> = fetch_circuit_file("circuits/policy_tx_2_2.r1cs").await?;
            log::debug!(
                "[{WORKER_NAME}] fetched policy_tx_2_2.r1cs: {} bytes",
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

    let transact_prover = ProverEngine::new(PROVING_KEY, &wasm_bytes, &r1cs_bytes)
        .map_err(|e| JsError::new(&format!("failed to init transact prover: {e:#}")))?;

    TRANSACT_PROVER.with(|cell| {
        *cell.borrow_mut() = Some(transact_prover);
    });

    // Load all disclosure circuit variants in parallel.
    let paths: [(String, String); 4] = [
        (
            "circuits/selectiveDisclosure_1.wasm".to_string(),
            "circuits/selectiveDisclosure_1.r1cs".to_string(),
        ),
        (
            "circuits/selectiveDisclosure_2.wasm".to_string(),
            "circuits/selectiveDisclosure_2.r1cs".to_string(),
        ),
        (
            "circuits/selectiveDisclosure_3.wasm".to_string(),
            "circuits/selectiveDisclosure_3.r1cs".to_string(),
        ),
        (
            "circuits/selectiveDisclosure_4.wasm".to_string(),
            "circuits/selectiveDisclosure_4.r1cs".to_string(),
        ),
    ];
    let disclosure_artifacts: Vec<(Vec<u8>, Vec<u8>)> =
        futures::future::try_join_all(paths.into_iter().map(|(wasm_path, r1cs_path)| async move {
            let wasm = fetch_circuit_file(&wasm_path).await?;
            let r1cs = fetch_circuit_file(&r1cs_path).await?;
            Ok::<_, JsError>((wasm, r1cs))
        }))
        .await?;

    let mut witness_calcs: [Option<WitnessCalculator>; 4] = [None, None, None, None];
    let mut provers: [Option<Groth16Prover>; 4] = [None, None, None, None];

    for (idx, (wasm_bytes, r1cs_bytes)) in disclosure_artifacts.iter().enumerate() {
        let n_notes = idx
            .checked_add(1)
            .expect("disclosure artifacts index is at most 3");
        let hashes = disclosure_hashes(n_notes);

        log::debug!(
            "[{WORKER_NAME}] fetched selectiveDisclosure_{n_notes}.wasm: {} bytes, .r1cs: {} bytes",
            wasm_bytes.len(),
            r1cs_bytes.len(),
        );

        ensure_sha256_matches(
            &format!("selectiveDisclosure_{n_notes}_proving_key.bin"),
            DISCLOSURE_PROVING_KEYS[idx],
            hashes.proving_key_len,
            hashes.proving_key_sha256,
        )?;
        ensure_sha256_matches(
            &format!("selectiveDisclosure_{n_notes}.wasm"),
            wasm_bytes,
            hashes.wasm_len,
            hashes.wasm_sha256,
        )?;
        ensure_sha256_matches(
            &format!("selectiveDisclosure_{n_notes}.r1cs"),
            r1cs_bytes,
            hashes.r1cs_len,
            hashes.r1cs_sha256,
        )?;

        let witness_calc = WitnessCalculator::new(wasm_bytes, r1cs_bytes).map_err(|e| {
            JsError::new(&format!(
                "failed to init selectiveDisclosure_{n_notes} witness calculator: {e:#}"
            ))
        })?;
        let prover = Groth16Prover::new(DISCLOSURE_PROVING_KEYS[idx], r1cs_bytes)
            .map_err(|e| JsError::new(&format!("failed to init disclosure prover: {e:#}")))?;

        witness_calcs[idx] = Some(witness_calc);
        provers[idx] = Some(prover);
    }

    DISCLOSURE_WITNESS_CALCS.with(|cell| {
        *cell.borrow_mut() = witness_calcs;
    });
    DISCLOSURE_PROVERS.with(|cell| {
        *cell.borrow_mut() = provers;
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
    load_circuit_artifacts().await?;
    log::debug!("[{WORKER_NAME}] initialized");

    Ok(())
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
                let ready = TRANSACT_PROVER.with(|s| s.borrow().is_some())
                    && DISCLOSURE_WITNESS_CALCS.with(|s| s.borrow().iter().all(|c| c.is_some()))
                    && DISCLOSURE_PROVERS.with(|s| s.borrow().iter().all(|p| p.is_some()));

                if ready {
                    log::trace!("[{WORKER_NAME}] pong");
                    return Ok(ProverWorkerResponse::Pong);
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

            let context = disclosure::DisclosureContext {
                network: req.network,
                pool_address: req.pool_address,
                authority_label: req.authority_label,
                authority_identity_payload_hex: req.authority_identity_payload_hex,
                purpose: req.purpose,
                context_nonce: req.context_nonce,
            };
            let ext_context_hash = disclosure::derive_ext_context_hash(&context)?;

            let n_notes = req.inputs.len();
            let idx = disclosure_index(n_notes).map_err(|e| anyhow::anyhow!("{e:?}"))?;

            let roots: Vec<_> = req.inputs.iter().map(|input| input.root).collect();
            let note_commitments: Vec<_> = req
                .inputs
                .iter()
                .map(|input| input.note_commitment)
                .collect();

            let notes: Vec<DisclosureNote> = req
                .inputs
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
        let prover_req = crate::protocol::DisclosureProverRequest {
            inputs: vec![crate::protocol::DisclosureNoteInputs {
                root: params.inputs.root,
                note_commitment: params.inputs.note_commitment,
                note_amount: params.inputs.note_amount,
                note_private_key: params.inputs.note_private_key,
                note_blinding: params.inputs.note_blinding,
                merkle_path_indices: params.inputs.merkle_path_indices,
                merkle_path_elements: params.inputs.merkle_path_elements,
            }],
            network: params.context.network,
            pool_address: params.context.pool_address,
            authority_label: params.context.authority_label,
            authority_identity_payload_hex: params.context.authority_identity_payload_hex,
            purpose: params.context.purpose,
            context_nonce: params.context.context_nonce,
        };
        match self
            .call(
                ProverWorkerRequest::Disclosure(prover_req),
                PROVE_TIMEOUT_MS,
            )
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
