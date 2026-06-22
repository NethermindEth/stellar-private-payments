//! Wallet signing (Freighter) and RPC submit.

use super::{WebClient, emit_progress};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use js_sys::{Array, Function, Object, Promise, Reflect};
use stellar::{
    PreparedSorobanTx, Signature, auth_sign_steps, parse_transaction_envelope_xdr,
    submit_and_confirm, unsigned_tx_xdr_for_signing,
};
use wasm_bindgen::{JsCast, JsError, JsValue};
use wasm_bindgen_futures::JsFuture;

const WALLET_BRIDGE_KEY: &str = "__walletSignBridge";

fn wallet_opts(address: &str, network_passphrase: &str) -> Object {
    let opts = Object::new();
    let _ = Reflect::set(&opts, &"address".into(), &address.into());
    let _ = Reflect::set(
        &opts,
        &"networkPassphrase".into(),
        &network_passphrase.into(),
    );
    opts
}

async fn wallet_call(method: &str, args: &[JsValue]) -> Result<String, JsError> {
    let window = web_sys::window().ok_or_else(|| JsError::new("no window"))?;
    let bridge = Reflect::get(&window, &WALLET_BRIDGE_KEY.into())
        .map_err(|_| JsError::new("wallet bridge not installed; reload the page"))?;
    let func: Function = Reflect::get(&bridge, &method.into())
        .map_err(|e| JsError::new(&format!("wallet.{method} missing: {e:?}")))?
        .dyn_into()
        .map_err(|_| JsError::new(&format!("wallet.{method} is not a function")))?;

    let js_args = Array::new();
    for arg in args {
        js_args.push(arg);
    }
    let promise_val = func
        .apply(&bridge, &js_args)
        .map_err(|e| JsError::new(&format!("wallet.{method} failed: {e:?}")))?;
    let promise: Promise = promise_val
        .dyn_into()
        .map_err(|_| JsError::new(&format!("wallet.{method} must return a Promise")))?;
    let result = JsFuture::from(promise)
        .await
        .map_err(|e| JsError::new(&format!("wallet.{method} rejected: {e:?}")))?;
    result
        .as_string()
        .ok_or_else(|| JsError::new(&format!("wallet.{method} must return a string")))
}

fn signature_from_base64(s: &str) -> Result<Signature, JsError> {
    let bytes = STANDARD
        .decode(s)
        .map_err(|e| JsError::new(&format!("base64 decode failed: {e}")))?;
    let sig: [u8; 64] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| JsError::new("wallet auth signature must be 64 bytes"))?;
    Ok(Signature::from_bytes(sig))
}

/// Signs a prepared Soroban transaction via Freighter; returns signed tx XDR
/// (base64).
pub async fn sign_prepared_tx_xdr(
    prepared: &PreparedSorobanTx,
    network_passphrase: &str,
    user_address: &str,
    flow: &'static str,
    on_status: &Option<Function>,
) -> Result<String, JsError> {
    let steps = auth_sign_steps(prepared, network_passphrase, user_address)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let total = u32::try_from(steps.len()).map_err(|_| JsError::new("too many auth steps"))?;

    let mut auth_signatures = Vec::with_capacity(steps.len());
    for (i, step) in steps.iter().enumerate() {
        let current = u32::try_from(i.saturating_add(1))
            .map_err(|_| JsError::new("auth step exceeds u32"))?;
        emit_progress(
            on_status,
            flow,
            "sign_auth",
            format!("Approve authorization ({current}/{total})…"),
            Some(current),
            Some(total),
        );
        let sig_b64 = wallet_call(
            "signAuthEntry",
            &[
                step.preimage_b64.as_str().into(),
                wallet_opts(user_address, network_passphrase).into(),
            ],
        )
        .await?;
        auth_signatures.push((step.entry_index, signature_from_base64(&sig_b64)?));
    }

    let tx_xdr = unsigned_tx_xdr_for_signing(prepared, user_address, &auth_signatures)
        .map_err(|e| JsError::new(&e.to_string()))?;

    emit_progress(
        on_status,
        flow,
        "sign_tx",
        "Approve transaction…",
        None,
        None,
    );

    wallet_call(
        "signTransaction",
        &[
            tx_xdr.as_str().into(),
            wallet_opts(user_address, network_passphrase).into(),
        ],
    )
    .await
}

impl WebClient {
    pub(super) async fn sign_and_submit(
        &self,
        prepared: &PreparedSorobanTx,
        user_address: &str,
        network_passphrase: &str,
        flow: &'static str,
        on_status: &Option<Function>,
    ) -> Result<String, JsError> {
        let signed_xdr =
            sign_prepared_tx_xdr(prepared, network_passphrase, user_address, flow, on_status)
                .await?;
        emit_progress(on_status, flow, "submit", "Submitting…", None, None);
        self.submit_signed_tx_xdr(&signed_xdr, flow, on_status)
            .await
    }

    pub(super) async fn submit_signed_tx_xdr(
        &self,
        signed_tx_xdr: &str,
        flow: &'static str,
        on_status: &Option<Function>,
    ) -> Result<String, JsError> {
        let signed = parse_transaction_envelope_xdr(signed_tx_xdr)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let mut on_poll = |current: u32, total: u32| {
            emit_progress(
                on_status,
                flow,
                "confirm",
                "Confirming…",
                Some(current),
                Some(total),
            );
        };
        submit_and_confirm(&signed, self.fetcher.rpc(), Some(&mut on_poll))
            .await
            .map_err(|e| JsError::new(&e.to_string()))
    }
}
