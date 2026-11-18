//! Drives a built prover worker from a page, for
//! `scripts/test-prover-threads.js` and `scripts/bench-prover-threads.js`. Not
//! part of the SDK: the facade offers no way to prove without a network, and
//! these scripts need one proof on a worker they choose.
//!
//! Built by `scripts/prover-browser.js`. Its `main` does nothing: the page
//! uses the exported `ProverDriver`.

fn main() {}

#[cfg(target_arch = "wasm32")]
mod driver {
    use stellar_private_payments::{
        Prover as _,
        types::{
            EncryptionPublicKey, ExtAmount, Field, GvkMode, NoteAmount, NotePrivateKey, PolicyFlags,
        },
        zk::flows::{TransactOutput, TransactParams},
    };
    use stellar_private_payments_web::ProverBridge;
    use wasm_bindgen::prelude::*;

    fn js_error(e: impl std::fmt::Display) -> JsError {
        JsError::new(&e.to_string())
    }

    /// One prover worker, serial or threaded, spawned from its URL.
    #[wasm_bindgen]
    pub struct ProverDriver {
        bridge: ProverBridge,
    }

    #[wasm_bindgen]
    impl ProverDriver {
        #[wasm_bindgen(constructor)]
        pub fn new(worker_url: String) -> ProverDriver {
            ProverDriver {
                bridge: ProverBridge::spawn_js(worker_url),
            }
        }

        /// Pool size of a threaded worker; see `ProverBridge.configureThreads`.
        #[wasm_bindgen(js_name = configureThreads)]
        pub async fn configure_threads(&self, threads: u32) -> Result<u32, JsError> {
            self.bridge.configure_threads_js(threads).await
        }

        pub async fn configure(
            &self,
            circuits_base: String,
            lock_json: String,
        ) -> Result<(), JsError> {
            self.bridge
                .configure_circuits_base_js(circuits_base, lock_json)
                .await
        }

        /// Proves the deposit-shaped `policy_tx_2_2` transaction of the CLI's
        /// offline proof test and returns the 256-byte uncompressed proof. The
        /// worker verifies every proof against the circuit's verifying key and
        /// fails the request if it does not verify.
        #[wasm_bindgen(js_name = proveTransact)]
        pub async fn prove_transact(
            &self,
            pool: String,
            token: String,
        ) -> Result<Vec<u8>, JsError> {
            let params = TransactParams {
                priv_key: NotePrivateKey([1; 32]),
                encryption_pubkey: EncryptionPublicKey([2; 32]),
                pool_root: Field::ZERO,
                pool_address: pool.clone(),
                token_address: token,
                ext_recipient: pool,
                ext_amount: ExtAmount::from(10),
                fee: NoteAmount::ZERO,
                inputs: Vec::new(),
                outputs: vec![TransactOutput {
                    amount: NoteAmount::from(10),
                    blinding: Field::try_from_le_bytes([3; 32]).map_err(js_error)?,
                    recipient_note_pubkey: None,
                    recipient_encryption_pubkey: None,
                }],
                membership_proof: None,
                non_membership_proof: None,
                tree_depth: 20,
                asp_depth: 10,
                smt_depth: 10,
                policy_flags: PolicyFlags::EMPTY,
                gvk_mode: GvkMode::Off,
                admin_view_key: None,
            };
            let prepared = self.bridge.prove_transact(params).await.map_err(js_error)?;
            Ok(prepared.proof_uncompressed)
        }

        /// Recent logs of this page and of the worker, which say how many
        /// threads the pool started with.
        pub async fn logs(&self) -> String {
            let _sink = stellar_private_payments_web::register_telemetry_sinks(
                None,
                Some(self.bridge.fork()),
            );
            stellar_private_payments_web::dump_recent_logs().await
        }
    }
}
