//! Freighter wallet bridge and [`Signer`] for [`PrivatePool`].

use js_sys::{Array, Function, Object, Promise, Reflect};
use stellar_private_payments_sdk::{
    PoolError, PreparedTransaction, Signer,
    chain::{
        Limits, PreparedSorobanTx, ReadXdr, Signature, TransactionEnvelope, WriteXdr,
        auth_sign_steps, unsigned_tx_for_signing,
    },
    types::SignedTransaction,
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

fn copy_js_error_fields(from: &JsValue, to: &JsValue) {
    for key in ["code", "cause"] {
        if let Ok(value) = Reflect::get(from, &JsValue::from_str(key))
            && !value.is_undefined()
            && !value.is_null()
        {
            let _ = Reflect::set(to, &JsValue::from_str(key), &value);
        }
    }
}

fn wallet_js_error(method: &str, stage: &str, rejection: JsValue) -> JsError {
    let message = rejection
        .dyn_ref::<js_sys::Error>()
        .and_then(|err| err.message().as_string())
        .unwrap_or_else(|| format!("{rejection:?}"));
    let err = JsError::new(&format!("wallet.{method} {stage}: {message}"));
    copy_js_error_fields(&rejection, &JsValue::from(err.clone()));
    err
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
        .map_err(|e| wallet_js_error(method, "failed", e))?;
    let promise: Promise = promise_val
        .dyn_into()
        .map_err(|_| JsError::new(&format!("wallet.{method} must return a Promise")))?;
    let result = JsFuture::from(promise)
        .await
        .map_err(|e| wallet_js_error(method, "rejected", e))?;
    result
        .as_string()
        .ok_or_else(|| JsError::new(&format!("wallet.{method} must return a string")))
}

/// Signs a prepared Soroban transaction via Freighter.
pub(crate) async fn sign_prepared_transaction(
    prepared: &PreparedSorobanTx,
    network_passphrase: &str,
    user_address: &str,
) -> Result<TransactionEnvelope, JsError> {
    let steps = auth_sign_steps(prepared, network_passphrase, user_address)
        .map_err(|e| JsError::new(&e.to_string()))?;

    let mut auth_signatures = Vec::with_capacity(steps.len());
    for step in &steps {
        let preimage_b64 = step
            .wallet_preimage_b64()
            .map_err(|e| JsError::new(&e.to_string()))?;
        let sig_b64 = wallet_call(
            "signAuthEntry",
            &[
                preimage_b64.as_str().into(),
                wallet_opts(user_address, network_passphrase).into(),
            ],
        )
        .await?;
        auth_signatures.push((
            step.entry_index,
            Signature::from_base64(&sig_b64).map_err(|e| JsError::new(&e.to_string()))?,
        ));
    }

    let tx_b64 = unsigned_tx_for_signing(prepared, user_address, &auth_signatures)
        .map_err(|e| JsError::new(&e.to_string()))?;

    let signed_b64 = wallet_call(
        "signTransaction",
        &[
            tx_b64.as_str().into(),
            wallet_opts(user_address, network_passphrase).into(),
        ],
    )
    .await?;
    TransactionEnvelope::from_xdr_base64(&signed_b64, Limits::none())
        .map_err(|e| JsError::new(&format!("invalid transaction envelope xdr: {e}")))
}

/// Signs simulated pool transactions via the JS wallet bridge (Freighter).
pub struct WalletSigner {
    network_passphrase: String,
    user_address: String,
}

impl WalletSigner {
    pub fn new(network_passphrase: impl Into<String>, user_address: impl Into<String>) -> Self {
        Self {
            network_passphrase: network_passphrase.into(),
            user_address: user_address.into(),
        }
    }
}

#[async_trait::async_trait(?Send)]
impl Signer for WalletSigner {
    async fn sign(&self, prepared: &PreparedTransaction) -> Result<SignedTransaction, PoolError> {
        let envelope = sign_prepared_transaction(
            &prepared.soroban_tx,
            &self.network_passphrase,
            &self.user_address,
        )
        .await
        .map_err(|e| PoolError::Other(format!("{e:?}")))?;

        let signed_xdr = envelope
            .to_xdr_base64(Limits::none())
            .map_err(|e| PoolError::Other(format!("encode signed transaction xdr: {e}")))?;

        Ok(SignedTransaction { signed_xdr })
    }
}

/// Request an arbitrary message signature via the JS wallet bridge.
pub(crate) async fn sign_wallet_message(
    message: &str,
    network_passphrase: &str,
    user_address: &str,
) -> Result<String, JsError> {
    wallet_call(
        "signMessage",
        &[
            message.into(),
            wallet_opts(user_address, network_passphrase).into(),
        ],
    )
    .await
}

/// Parse a hex signature string (with or without `0x`) into bytes.
pub(crate) fn hex_signature_to_bytes(hex: &str) -> Result<Vec<u8>, JsError> {
    let clean = hex.trim().strip_prefix("0x").unwrap_or(hex.trim());
    if !clean.len().is_multiple_of(2) {
        return Err(JsError::new("signature hex must have even length"));
    }
    clean
        .as_bytes()
        .chunks(2)
        .map(|chunk| {
            let pair = std::str::from_utf8(chunk)
                .map_err(|e| JsError::new(&format!("invalid signature hex: {e}")))?;
            u8::from_str_radix(pair, 16)
                .map_err(|e| JsError::new(&format!("invalid signature hex: {e}")))
        })
        .collect()
}
