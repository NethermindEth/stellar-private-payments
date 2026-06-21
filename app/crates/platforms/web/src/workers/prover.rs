use crate::protocol::{
    PreparedProverTx, PreparedTxPublic, ProverWorkerRequest, ProverWorkerResponse,
};
use anyhow::{Context as _, Result};
use futures::try_join;
use gloo_timers::future::TimeoutFuture;
use gloo_worker::{Registrable, oneshot::oneshot};
use prover::{
    flows::{TransactArtifacts, transact},
    prover::Prover,
};
use sha2::{Digest as _, Sha256};
use std::{cell::RefCell, fmt::Write as _};
use stellar::hash_ext_data_offchain;
use types::{SELECTIVE_DISCLOSURE_1_LEVELS, SELECTIVE_DISCLOSURE_1_N_NOTES};
use wasm_bindgen::{JsCast, JsError, JsValue};
use wasm_bindgen_futures::{JsFuture, spawn_local};
use web_sys::{Request, RequestInit, RequestMode};
use witness::WitnessCalculator;

const WORKER_NAME: &str = "WORKER-PROVER";

// TODO make it dependent on the network during the compilation
const PROVING_KEY: &[u8] = include_bytes!(
    "../../../../../../deployments/testnet/circuit_keys/policy_tx_2_2_proving_key.bin"
);
const DISCLOSURE_PROVING_KEY: &[u8] = include_bytes!(
    "../../../../../../deployments/testnet/circuit_keys/selectiveDisclosure_1_proving_key.bin"
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
    static WITNESS_CALC: RefCell<Option<WitnessCalculator>> = const { RefCell::new(None) };
    static PROVER: RefCell<Option<Prover>> = const { RefCell::new(None) };
    static DISCLOSURE_WITNESS_CALC: RefCell<Option<WitnessCalculator>> = const { RefCell::new(None) };
    static DISCLOSURE_PROVER: RefCell<Option<Prover>> = const { RefCell::new(None) };
}

async fn load_circuit_artifacts() -> Result<(), JsError> {
    if WITNESS_CALC.with(|s| s.borrow().is_some()) && PROVER.with(|s| s.borrow().is_some()) {
        return Ok(());
    }
    let (graph_bytes, r1cs_bytes, disc_wasm_bytes, disc_r1cs_bytes) = try_join!(
        async {
            let graph_bytes: Vec<u8> =
                fetch_circuit_file("circuits/policy_tx_2_2.graph.bin").await?;
            log::debug!(
                "[{WORKER_NAME}] fetched policy_tx_2_2.graph.bin: {} bytes",
                graph_bytes.len()
            );
            Ok::<Vec<u8>, JsError>(graph_bytes)
        },
        async {
            let r1cs_bytes: Vec<u8> = fetch_circuit_file("circuits/policy_tx_2_2.r1cs").await?;
            log::debug!(
                "[{WORKER_NAME}] fetched policy_tx_2_2.r1cs: {} bytes",
                r1cs_bytes.len()
            );
            Ok::<Vec<u8>, JsError>(r1cs_bytes)
        },
        async {
            let wasm_bytes: Vec<u8> =
                fetch_circuit_file("circuits/selectiveDisclosure_1.wasm").await?;
            log::debug!(
                "[{WORKER_NAME}] fetched selectiveDisclosure_1.wasm: {} bytes",
                wasm_bytes.len()
            );
            Ok::<Vec<u8>, JsError>(wasm_bytes)
        },
        async {
            let r1cs_bytes: Vec<u8> =
                fetch_circuit_file("circuits/selectiveDisclosure_1.r1cs").await?;
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
        "policy_tx_2_2.graph.bin",
        &graph_bytes,
        crate::artifact_hashes::EXPECTED_POLICY_TX_2_2_GRAPH_LEN,
        crate::artifact_hashes::EXPECTED_POLICY_TX_2_2_GRAPH_SHA256,
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

    let witness_calc = WitnessCalculator::new(&graph_bytes, &r1cs_bytes)
        .map_err(|e| JsError::new(&format!("failed to init witness calculator: {e:#}")))?;
    let prover = Prover::new(PROVING_KEY, &r1cs_bytes).expect("FAILED Prover");

    let disc_witness_calc =
        WitnessCalculator::new(&disc_wasm_bytes, &disc_r1cs_bytes).map_err(|e| {
            JsError::new(&format!(
                "failed to init disclosure witness calculator: {e:#}"
            ))
        })?;
    let disc_prover =
        Prover::new(DISCLOSURE_PROVING_KEY, &disc_r1cs_bytes).expect("FAILED Disclosure Prover");

    WITNESS_CALC.with(|cell| {
        *cell.borrow_mut() = Some(witness_calc);
    });
    PROVER.with(|cell| {
        *cell.borrow_mut() = Some(prover);
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
                let ready = WITNESS_CALC.with(|s| s.borrow().is_some())
                    && PROVER.with(|s| s.borrow().is_some());

                if ready {
                    log::trace!("[{WORKER_NAME}] pong");
                    return Ok(ProverWorkerResponse::Pong);
                }

                TimeoutFuture::new(50).await;
            }
        }
        ProverWorkerRequest::Transact(params) => {
            log::debug!("[{WORKER_NAME}] transact");
            let artifacts = transact(params, hash_ext_data_offchain)?;
            log::debug!("[{WORKER_NAME}] prove_from_artifacts");
            ProverWorkerResponse::TransactPrepared(prove_from_artifacts(artifacts)?)
        }
        ProverWorkerRequest::Disclosure(req) => {
            log::debug!("[{WORKER_NAME}] disclosure");

            let context = types::DisclosureContext {
                network: req.network,
                pool_address: req.pool_address,
                authority_label: req.authority_label,
                authority_identity_payload_hex: req.authority_identity_payload_hex,
                purpose: req.purpose,
                context_nonce: req.context_nonce,
            };
            let ext_context_hash = disclosure::derive_ext_context_hash(&context)?;

            let params = prover::flows::SelectiveDisclosure1Params {
                root: req.inputs.root,
                note_commitment: req.inputs.note_commitment,
                note_amount: req.inputs.note_amount,
                note_private_key: req.inputs.note_private_key,
                note_blinding: req.inputs.note_blinding,
                merkle_path_indices: req.inputs.merkle_path_indices,
                merkle_path_elements: req.inputs.merkle_path_elements,
                ext_context_hash,
            };

            let artifacts = prover::flows::selective_disclosure_1(params)?;
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

            let receipt = types::DisclosureReceipt {
                version: types::DISCLOSURE_RECEIPT_VERSION,
                circuit: types::DisclosureCircuitMetadata {
                    name: types::SELECTIVE_DISCLOSURE_1_CIRCUIT.to_string(),
                    levels: SELECTIVE_DISCLOSURE_1_LEVELS,
                    n_notes: SELECTIVE_DISCLOSURE_1_N_NOTES,
                    vk_hash: vk_hash_hex,
                },
                context,
                public_inputs: types::DisclosurePublicInputs {
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
        // TODO: Consider extracting disclosure proof verification into a separate
        // interface/crate. Verification is initiated by a receipt holder outside
        // the app, while proving is app-initiated, so the responsibilities differ.
        ProverWorkerRequest::VerifyDisclosureProof(receipt, expected_vk_hash) => {
            log::debug!("[{WORKER_NAME}] verify disclosure proof");

            // Early metadata validation for clear error messages. The actual
            // VK-byte trust binding lives inside disclosure::verify_receipt_proof.
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

fn prove_from_artifacts(transact_artifacts: TransactArtifacts) -> Result<PreparedProverTx> {
    let circuit_inputs_json = serde_json::to_string(&transact_artifacts.circuit_inputs)?;
    let ext_data = transact_artifacts.ext_data.clone();
    log::debug!("[{WORKER_NAME}] compute witness");
    let witness_bytes = WITNESS_CALC.with(|cell| {
        let mut borrow = cell.borrow_mut();
        let calc = borrow
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("witness calculator is not initialized"))?;
        calc.compute_witness(&circuit_inputs_json)
            .context("witness calculation failed")
    })?;

    let (proof_uncompressed, prepared_public) = PROVER.with(|cell| {
        let borrow = cell.borrow();
        let prover = borrow
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("prover is not initialized"))?;

        log::debug!("[{WORKER_NAME}] prove");
        let proof_compressed = prover.prove_bytes(&witness_bytes)?;
        let public_inputs = prover.extract_public_inputs(&witness_bytes)?;
        log::debug!("[{WORKER_NAME}] verify");
        let ok = prover.verify(&proof_compressed, &public_inputs)?;
        if !ok {
            return Err(anyhow::anyhow!("proof verification failed"));
        }

        let proof_uncompressed = prover.proof_bytes_to_uncompressed(&proof_compressed)?;
        if proof_uncompressed.len() != 256 {
            return Err(anyhow::anyhow!(
                "unexpected uncompressed proof length: {}",
                proof_uncompressed.len()
            ));
        }

        let p = transact_artifacts.prepared;
        let prepared_public = PreparedTxPublic {
            pool_root: p.pool_root,
            input_nullifiers: p.input_nullifiers,
            output_commitments: p.output_commitments,
            public_amount: p.public_amount_field,
            ext_data_hash_be: p.ext_data_hash_be,
            asp_membership_root: p.asp_membership_root,
            asp_non_membership_root: p.asp_non_membership_root,
        };

        Ok::<_, anyhow::Error>((proof_uncompressed, prepared_public))
    })?;

    Ok(PreparedProverTx {
        proof_uncompressed,
        ext_data,
        prepared: prepared_public,
        soroban_tx: Default::default(),
    })
}

async fn fetch_circuit_file(path: &str) -> Result<Vec<u8>, JsError> {
    const PUBLIC_URL: Option<&str> = option_env!("PUBLIC_URL");
    let global = js_sys::global();

    let location = js_sys::Reflect::get(&global, &JsValue::from_str("location"))
        .map_err(|_| JsError::new("Accessing self.location failed"))?;

    let origin = js_sys::Reflect::get(&location, &JsValue::from_str("origin"))
        .map_err(|_| JsError::new("Accessing self.location.origin failed"))?
        .as_string()
        .ok_or_else(|| JsError::new("Origin is not a string"))?;

    let public_url = PUBLIC_URL.unwrap_or("/");
    let path = path.trim_start_matches('/');

    let url_string = if public_url.starts_with("http://") || public_url.starts_with("https://") {
        format!("{}/{path}", public_url.trim_end_matches('/'))
    } else if public_url == "/" {
        format!("{origin}/{path}")
    } else if public_url.starts_with('/') {
        format!("{origin}/{}/{path}", public_url.trim_matches('/'))
    } else {
        return Err(JsError::new(
            "PUBLIC_URL must be an absolute URL or root-relative path",
        ));
    };

    log::debug!("[{WORKER_NAME}] Fetching from: {}", url_string);

    let opts = RequestInit::new();
    opts.set_method("GET");
    opts.set_mode(RequestMode::Cors);

    let request = Request::new_with_str_and_init(&url_string, &opts)
        .map_err(|e| JsError::new(&format!("Request failed for {}: {:?}", url_string, e)))?;

    let global_scope = global.unchecked_into::<web_sys::WorkerGlobalScope>();
    let resp_value = JsFuture::from(global_scope.fetch_with_request(&request))
        .await
        .map_err(|e| JsError::new(&format!("Network error: {:?}", e)))?;

    let resp: web_sys::Response = resp_value
        .dyn_into()
        .map_err(|_| JsError::new("Failed to cast response"))?;

    if !resp.ok() {
        return Err(JsError::new(&format!(
            "HTTP {} for {}",
            resp.status(),
            url_string
        )));
    }

    let array_buffer_promise = resp
        .array_buffer()
        .map_err(|e| JsError::new(&format!("{:?}", e)))?;
    let array_buffer_value = JsFuture::from(array_buffer_promise)
        .await
        .map_err(|e| JsError::new(&format!("{:?}", e)))?;

    let type_array = js_sys::Uint8Array::new(&array_buffer_value);
    Ok(type_array.to_vec())
}
