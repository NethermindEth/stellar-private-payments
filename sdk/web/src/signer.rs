//! Browser wallet [`Signer`] — calls a JS object passed at [`PrivatePool`]
//! construction.

use js_sys::{Array, Function, Object, Promise, Reflect};
use stellar_private_payments_sdk::{
    Error, PreparedTransaction, Signer,
    chain::{
        Limits, PreparedSorobanTx, ReadXdr, Signature, TransactionEnvelope, WriteXdr,
        auth_sign_steps, unsigned_tx_for_signing,
    },
    types::SignedTransaction,
};
use wasm_bindgen::{JsCast, JsError, JsValue};
use wasm_bindgen_futures::JsFuture;

const SIGN_METHODS: &[&str] = &["signMessage", "signTransaction", "signAuthEntry"];

/// Wallet adapter invoked from WASM (`FreighterSigner` or any object with the
/// three sign methods).
#[derive(Clone)]
pub struct WalletSigner {
    signer: JsValue,
    network_passphrase: String,
    user_address: String,
}

impl WalletSigner {
    pub fn new(
        signer: JsValue,
        network_passphrase: String,
        user_address: String,
    ) -> Result<Self, JsError> {
        if signer.is_null() || signer.is_undefined() {
            return Err(JsError::new("signer is required"));
        }
        for method in SIGN_METHODS {
            if !Reflect::has(&signer, &JsValue::from_str(method)).unwrap_or(false) {
                return Err(JsError::new(&format!(
                    "signer must implement {method}(...)"
                )));
            }
        }
        Ok(Self {
            signer,
            network_passphrase,
            user_address,
        })
    }

    pub(crate) async fn sign_wallet_message(&self, message: &str) -> Result<String, JsError> {
        self.call("signMessage", &[message.into()]).await
    }

    pub(crate) async fn sign_prepared_transaction(
        &self,
        prepared: &PreparedSorobanTx,
    ) -> Result<TransactionEnvelope, JsError> {
        let steps = auth_sign_steps(prepared, &self.network_passphrase, &self.user_address)
            .map_err(|e| JsError::new(&e.to_string()))?;

        let mut auth_signatures = Vec::with_capacity(steps.len());
        for step in &steps {
            let preimage_b64 = step
                .wallet_preimage_b64()
                .map_err(|e| JsError::new(&e.to_string()))?;
            let sig_b64 = self
                .call("signAuthEntry", &[preimage_b64.as_str().into()])
                .await?;
            auth_signatures.push((
                step.entry_index,
                Signature::from_base64(&sig_b64).map_err(|e| JsError::new(&e.to_string()))?,
            ));
        }

        let tx_b64 = unsigned_tx_for_signing(prepared, &self.user_address, &auth_signatures)
            .map_err(|e| JsError::new(&e.to_string()))?;

        let signed_b64 = self
            .call("signTransaction", &[tx_b64.as_str().into()])
            .await?;
        TransactionEnvelope::from_xdr_base64(&signed_b64, Limits::none())
            .map_err(|e| JsError::new(&format!("invalid transaction envelope xdr: {e}")))
    }

    fn wallet_opts(&self) -> Object {
        let opts = Object::new();
        let _ = Reflect::set(&opts, &"address".into(), &self.user_address.clone().into());
        let _ = Reflect::set(
            &opts,
            &"networkPassphrase".into(),
            &self.network_passphrase.clone().into(),
        );
        opts
    }

    async fn call(&self, method: &str, extra_args: &[JsValue]) -> Result<String, JsError> {
        let func: Function = Reflect::get(&self.signer, &JsValue::from_str(method))
            .map_err(|e| JsError::new(&format!("signer.{method}: {e:?}")))?
            .dyn_into()
            .map_err(|_| JsError::new(&format!("signer.{method} must be a function")))?;

        let js_args = Array::new();
        for arg in extra_args {
            js_args.push(arg);
        }
        js_args.push(&self.wallet_opts().into());

        let promise_val = func
            .apply(&self.signer, &js_args)
            .map_err(|e| wallet_js_error(method, "failed", e))?;
        let promise: Promise = promise_val
            .dyn_into()
            .map_err(|_| JsError::new(&format!("signer.{method} must return a Promise")))?;
        let result = JsFuture::from(promise)
            .await
            .map_err(|e| wallet_js_error(method, "rejected", e))?;

        normalize_sign_result(method, result)
    }
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
    let err = JsError::new(&format!("signer.{method} {stage}: {message}"));
    copy_js_error_fields(&rejection, &JsValue::from(err.clone()));
    err
}

fn normalize_sign_result(method: &str, result: JsValue) -> Result<String, JsError> {
    if let Some(s) = result.as_string() {
        return Ok(s);
    }

    let field = match method {
        "signMessage" => "signedMessage",
        "signTransaction" => "signedTxXdr",
        "signAuthEntry" => "signedAuthEntry",
        _ => {
            return Err(JsError::new(&format!(
                "signer.{method} returned unexpected value"
            )));
        }
    };

    let value = Reflect::get(&result, &JsValue::from_str(field))
        .map_err(|e| JsError::new(&format!("signer.{method}: missing {field}: {e:?}")))?;
    value
        .as_string()
        .ok_or_else(|| JsError::new(&format!("signer.{method}: {field} must be a string")))
}

#[async_trait::async_trait(?Send)]
impl Signer for WalletSigner {
    async fn sign(&self, prepared: &PreparedTransaction) -> Result<SignedTransaction, Error> {
        let envelope = self
            .sign_prepared_transaction(&prepared.soroban_tx)
            .await
            .map_err(|e| Error::Other(format!("{e:?}")))?;

        let signed_xdr = envelope
            .to_xdr_base64(Limits::none())
            .map_err(|e| Error::Other(format!("encode signed transaction xdr: {e}")))?;

        Ok(SignedTransaction { signed_xdr })
    }
}

/// Parse a Freighter `signMessage` signature (base64) into raw bytes.
///
/// Freighter returns base64-encoded signature bytes. Hex is accepted as a
/// fallback for custom signers.
pub(crate) fn wallet_message_signature_to_bytes(signature: &str) -> Result<Vec<u8>, JsError> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    let trimmed = signature.trim();
    if let Ok(bytes) = STANDARD.decode(trimmed) {
        return Ok(bytes);
    }

    hex_signature_to_bytes(trimmed)
}
/// Parse a hex signature string (with or without `0x`) into bytes.
fn hex_signature_to_bytes(hex: &str) -> Result<Vec<u8>, JsError> {
    let clean = hex.strip_prefix("0x").unwrap_or(hex);
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    #[test]
    fn wallet_message_signature_accepts_freighter_base64() {
        let bytes = vec![1u8, 2, 3, 4];
        let b64 = STANDARD.encode(&bytes);
        assert_eq!(
            wallet_message_signature_to_bytes(&b64).expect("base64"),
            bytes
        );
    }
}
