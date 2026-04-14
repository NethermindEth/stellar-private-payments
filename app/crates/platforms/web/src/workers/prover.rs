use anyhow::{Context as _, Result};
use wasm_bindgen::JsError;
use gloo_worker::oneshot::oneshot;
use gloo_timers::future::TimeoutFuture;
use std::cell::RefCell;
use crate::protocol::{DepositPrepared, PreparedTxPublic, ProverWorkerRequest, ProverWorkerResponse};
use wasm_bindgen_futures::spawn_local;
use gloo_worker::Registrable;
use prover::{
    flows::{deposit},
    prover::Prover,
};
use futures::try_join;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode};
use witness::WitnessCalculator;
use wasm_bindgen::JsValue;
use stellar::hash_ext_data_offchain;

const WORKER_NAME: &str = "WORKER-PROVER";

// TODO make it dependent on the network during the compilation
const PROVING_KEY: &[u8] = include_bytes!("../../../../../../scripts/testdata/policy_tx_2_2_proving_key.bin");
const VERIFICATION_KEY: &str = include_str!("../../../../../../scripts/testdata/policy_tx_2_2_vk.json");

// TODO for now it is a mix of async (because we want an async bridge for the main thread) and sync (blocking) code
// in the future we should refactor to use wasm threads?

thread_local! {
    static WITNESS_CALC: RefCell<Option<WitnessCalculator>> = RefCell::new(None);
    static PROVER: RefCell<Option<Prover>> = RefCell::new(None);
}

async fn load_circuit_artifacts() -> Result<(), JsError> {
    if WITNESS_CALC.with(|s| s.borrow().is_some()) && PROVER.with(|s| s.borrow().is_some()) {
        return Ok(());
    }
    let (wasm_bytes, r1cs_bytes) = try_join!(
        async {
            let wasm_bytes: Vec<u8> = fetch_circuit_file("/circuits/policy_tx_2_2.wasm").await?;
            log::debug!("[{WORKER_NAME}] fetched policy_tx_2_2.wasm: {} bytes", wasm_bytes.len());
            Ok::<Vec<u8>, JsError>(wasm_bytes)
        },
        async {
            let r1cs_bytes: Vec<u8> = fetch_circuit_file("/circuits/policy_tx_2_2.r1cs").await?;
            log::debug!("[{WORKER_NAME}] fetched policy_tx_2_2.r1cs: {} bytes", r1cs_bytes.len());
            Ok::<Vec<u8>, JsError>(r1cs_bytes)
        }
    )?;

    let witness_calc = WitnessCalculator::new(&wasm_bytes, &r1cs_bytes)
        .map_err(|e| JsError::new(&format!("failed to init witness calculator: {e:#}")))?;
    let prover = Prover::new(PROVING_KEY, &r1cs_bytes).expect("FAILED Prover");

    WITNESS_CALC.with(|cell| {
        *cell.borrow_mut() = Some(witness_calc);
    });
    PROVER.with(|cell| {
        *cell.borrow_mut() = Some(prover);
    });
    Ok(())
}

pub fn worker_main() {
    console_error_panic_hook::set_once();
    wasm_log::init(wasm_log::Config::default());
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
        Err(e) => ProverWorkerResponse::Error(e.to_string())
    }
}

// Main router of worker requests
pub(crate) async fn router(req: ProverWorkerRequest) -> Result<ProverWorkerResponse> {
    let resp = match req {
        ProverWorkerRequest::Ping => {
            log::debug!("[{WORKER_NAME}] ping");
            loop {
                let ready = WITNESS_CALC.with(|s| s.borrow().is_some()) && PROVER.with(|s| s.borrow().is_some());

                if ready {
                    log::debug!("[{WORKER_NAME}] pong");
                    return Ok(ProverWorkerResponse::Pong);
                }

                TimeoutFuture::new(50).await;
            }
        }
        ProverWorkerRequest::Deposit(params) => {
            log::debug!("[{WORKER_NAME}] deposit");

            let transact_artifacts = deposit(params, hash_ext_data_offchain)?;

            let circuit_inputs_json = serde_json::to_string(&transact_artifacts.circuit_inputs)?;
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

                let proof_compressed = prover.prove_bytes(&witness_bytes)?;
                let public_inputs = prover.extract_public_inputs(&witness_bytes)?;
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

                let p = transact_artifacts.prepared.clone();
                let input_nullifiers = [
                    types::Field::try_from_le_bytes(p.input_nullifiers[0])?,
                    types::Field::try_from_le_bytes(p.input_nullifiers[1])?,
                ];
                let output_commitments = [
                    types::Field::try_from_le_bytes(p.output_commitments[0])?,
                    types::Field::try_from_le_bytes(p.output_commitments[1])?,
                ];
                let public_amount = types::Field::try_from_le_bytes(p.public_amount_field)?;
                let asp_membership_root = types::Field::try_from_le_bytes(p.asp_membership_root)?;
                let asp_non_membership_root =
                    types::Field::try_from_le_bytes(p.asp_non_membership_root)?;

                let prepared_public = PreparedTxPublic {
                    pool_root: p.pool_root,
                    input_nullifiers,
                    output_commitments,
                    public_amount,
                    ext_data_hash_be: p.ext_data_hash_be,
                    asp_membership_root,
                    asp_non_membership_root,
                };

                Ok::<_, anyhow::Error>((proof_uncompressed, prepared_public))
            })?;

            let prepared = DepositPrepared {
                proof_uncompressed,
                ext_data: transact_artifacts.ext_data,
                prepared: prepared_public,
            };

            ProverWorkerResponse::DepositPrepared(prepared)
        }
    };
    Ok(resp)
}

async fn fetch_circuit_file(path: &str) -> Result<Vec<u8>, JsError> {
    let global = js_sys::global();

    let location = js_sys::Reflect::get(&global, &JsValue::from_str("location"))
        .map_err(|_| JsError::new("Accessing self.location failed"))?;

    let origin = js_sys::Reflect::get(&location, &JsValue::from_str("origin"))
        .map_err(|_| JsError::new("Accessing self.location.origin failed"))?
        .as_string()
        .ok_or_else(|| JsError::new("Origin is not a string"))?;


    let url_string = if path.starts_with("http") {
        path.to_string()
    } else {
        format!("{}{}", origin, path)
    };

    log::debug!("[{WORKER_NAME}] Fetching from: {}", url_string);

    let mut opts = RequestInit::new();
    opts.set_method("GET");
    opts.set_mode(RequestMode::Cors);

    let request = Request::new_with_str_and_init(&url_string, &opts)
        .map_err(|e| JsError::new(&format!("Request failed for {}: {:?}", url_string, e)))?;

    let global_scope = global.unchecked_into::<web_sys::WorkerGlobalScope>();
    let resp_value = JsFuture::from(global_scope.fetch_with_request(&request))
        .await
        .map_err(|e| JsError::new(&format!("Network error: {:?}", e)))?;

    let resp: web_sys::Response = resp_value.dyn_into().map_err(|_| {
        JsError::new("Failed to cast response")
    })?;

    if !resp.ok() {
        return Err(JsError::new(&format!("HTTP {} for {}", resp.status(), url_string)));
    }

    let array_buffer_promise = resp.array_buffer().map_err(|e| JsError::new(&format!("{:?}", e)))?;
    let array_buffer_value = JsFuture::from(array_buffer_promise).await
        .map_err(|e| JsError::new(&format!("{:?}", e)))?;

    let type_array = js_sys::Uint8Array::new(&array_buffer_value);
    Ok(type_array.to_vec())
}
