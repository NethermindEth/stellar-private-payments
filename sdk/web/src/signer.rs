//! Browser wallet [`Signer`] — calls a JS object passed at [`PrivatePool`]
//! construction.

use js_sys::{Array, Function, Object, Promise, Reflect};
use stellar_private_payments::{
    Error, PreparedTransaction, Signer,
    chain::{
        Limits, PreparedSorobanTx, ReadXdr, Signature, TransactionEnvelope, WriteXdr,
        auth_sign_steps, unsigned_tx_for_signing,
    },
    types::{SignedTransaction, SignerAddress},
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
    /// The account this signer asks the wallet to sign with: the requested
    /// `address`, the auth entries selected for signing, and the public key
    /// embedded in the address credential.
    signer_address: SignerAddress,
}

impl WalletSigner {
    pub fn new(
        signer: JsValue,
        network_passphrase: String,
        signer_address: SignerAddress,
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
            signer_address,
        })
    }

    /// The account this signer asks the wallet to sign with.
    pub(crate) fn signer_address(&self) -> &SignerAddress {
        &self.signer_address
    }

    pub(crate) async fn sign_wallet_message(&self, message: &str) -> Result<String, JsError> {
        self.call("signMessage", &[message.into()]).await
    }

    pub(crate) async fn sign_prepared_transaction(
        &self,
        prepared: &PreparedSorobanTx,
    ) -> Result<TransactionEnvelope, JsError> {
        let steps = auth_sign_steps(
            prepared,
            &self.network_passphrase,
            self.signer_address.as_str(),
        )
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

        let tx_b64 =
            unsigned_tx_for_signing(prepared, self.signer_address.as_str(), &auth_signatures)
                .map_err(|e| JsError::new(&e.to_string()))?;

        let signed_b64 = self
            .call("signTransaction", &[tx_b64.as_str().into()])
            .await?;
        TransactionEnvelope::from_xdr_base64(&signed_b64, Limits::none())
            .map_err(|e| JsError::new(&format!("invalid transaction envelope xdr: {e}")))
    }

    fn wallet_opts(&self) -> Object {
        let opts = Object::new();
        let _ = Reflect::set(
            &opts,
            &"address".into(),
            &JsValue::from_str(self.signer_address.as_str()),
        );
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
            .map_err(|e| wallet_js_error(method, "failed", e))?;

        let (value, signer_address) = normalize_sign_result(method, result)?;
        // `signer_address` is absent only for the bare-string result
        // convention (a custom signer with nothing to check); every SEP-0043
        // wallet (Freighter included) always sets it, and a mismatch there
        // means the wallet signed with an account other than the one
        // `wallet_opts()` asked for above — the signature is not
        // attributable to the requested identity and must not be accepted
        // silently.
        if let Some(actual) = signer_address
            && actual != self.signer_address.as_str()
        {
            return Err(signer_address_mismatch_error(
                method,
                self.signer_address.as_str(),
                &actual,
            ));
        }
        Ok(value)
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

/// Wrap a JS signer rejection, preserving `code`/`cause` from the original.
///
/// `stage` is interpolated into the message, which crosses the wasm/JS boundary
/// and is consumed by the app's cancellation classifier — which falls back to
/// substring matching when a wallet does not set code -4. Keep `stage` (and any
/// other wording composed here) free of "rejected"/"denied"/"cancelled", or
/// every signer failure will be reported to the user as a user cancellation.
fn wallet_js_error(method: &str, stage: &str, rejection: JsValue) -> JsError {
    let message = rejection
        .dyn_ref::<js_sys::Error>()
        .and_then(|err| err.message().as_string())
        .unwrap_or_else(|| format!("{rejection:?}"));
    let err = JsError::new(&format!("signer.{method} {stage}: {message}"));
    copy_js_error_fields(&rejection, &JsValue::from(err.clone()));
    err
}

/// SEP-0043 user-rejection error code. `pub(crate)` so client/mod.rs's
/// `pool_err` can set the same code when it rebuilds a JsError from
/// `Error::UserRejected`, keeping the wasm boundary's rejection code in one
/// place rather than two independently-defined constants that could drift.
pub(crate) const SEP43_USER_REJECTED_CODE: f64 = -4.0;

/// Marker field [`signer_address_mismatch_error`] sets on the JsError it
/// builds, so [`wallet_sign_error`] can recognize the condition without
/// relying on message wording (the same reason `code: -4` marks a rejection).
const SIGNER_ADDRESS_MISMATCH_MARKER: &str = "signerAddressMismatch";

/// Build the error a wallet's signature is rejected with when it reports
/// signing for a different account than [`WalletSigner::wallet_opts`] asked
/// for. Marked so [`wallet_sign_error`] maps it to
/// [`Error::SignerAddressMismatch`] rather than the generic fallback, and
/// deliberately does not set `code: -4` — this is not a user rejection and
/// must not be classified as one by the app's cancellation handling (see
/// [`wallet_js_error`]).
fn signer_address_mismatch_error(method: &str, requested: &str, actual: &str) -> JsError {
    let err = JsError::new(&format!(
        "signer.{method}: wallet signed with {actual}, but {requested} was requested"
    ));
    let value = JsValue::from(err.clone());
    let _ = Reflect::set(
        &value,
        &JsValue::from_str(SIGNER_ADDRESS_MISMATCH_MARKER),
        &JsValue::TRUE,
    );
    let _ = Reflect::set(
        &value,
        &JsValue::from_str("requestedAddress"),
        &JsValue::from_str(requested),
    );
    let _ = Reflect::set(
        &value,
        &JsValue::from_str("actualAddress"),
        &JsValue::from_str(actual),
    );
    err
}

/// Convert a JS signer error into an SDK [`Error`]. A SEP-0043 user rejection
/// (`code: -4`, copied onto the error by [`wallet_js_error`]) becomes
/// [`Error::UserRejected`] so it survives the wasm/JS boundary without relying
/// on message wording; a signer-address mismatch (marked by
/// [`signer_address_mismatch_error`]) becomes [`Error::SignerAddressMismatch`]
/// for the same reason; everything else keeps the previous debug formatting.
fn wallet_sign_error(error: JsError) -> Error {
    let value = JsValue::from(error.clone());
    let is_mismatch = Reflect::get(&value, &JsValue::from_str(SIGNER_ADDRESS_MISMATCH_MARKER))
        .map(|marker| marker.is_truthy())
        .unwrap_or(false);
    if is_mismatch {
        let requested = Reflect::get(&value, &JsValue::from_str("requestedAddress"))
            .ok()
            .and_then(|v| v.as_string())
            .unwrap_or_default();
        let actual = Reflect::get(&value, &JsValue::from_str("actualAddress"))
            .ok()
            .and_then(|v| v.as_string())
            .unwrap_or_default();
        return Error::SignerAddressMismatch { requested, actual };
    }
    let code = Reflect::get(&value, &JsValue::from_str("code"))
        .ok()
        .and_then(|code| code.as_f64());
    if code == Some(SEP43_USER_REJECTED_CODE) {
        let message = Reflect::get(&value, &JsValue::from_str("message"))
            .ok()
            .and_then(|message| message.as_string())
            .unwrap_or_else(|| "request rejected".to_string());
        Error::UserRejected(message)
    } else {
        Error::Other(format!("{error:?}"))
    }
}

/// Extract the signed value and, when present, the `signerAddress` the
/// wallet reports it signed with. Absent only for the legacy bare-string
/// result convention (no object to read a `signerAddress` field off of).
fn normalize_sign_result(
    method: &str,
    result: JsValue,
) -> Result<(String, Option<String>), JsError> {
    if let Some(s) = result.as_string() {
        return Ok((s, None));
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
    let value = value
        .as_string()
        .ok_or_else(|| JsError::new(&format!("signer.{method}: {field} must be a string")))?;

    let signer_address = Reflect::get(&result, &JsValue::from_str("signerAddress"))
        .ok()
        .and_then(|v| v.as_string());

    Ok((value, signer_address))
}

#[async_trait::async_trait(?Send)]
impl Signer for WalletSigner {
    async fn sign_transaction(
        &self,
        prepared: &PreparedTransaction,
    ) -> Result<SignedTransaction, Error> {
        self.sign_soroban_transaction(&prepared.soroban_tx).await
    }

    async fn sign_soroban_transaction(
        &self,
        prepared: &PreparedSorobanTx,
    ) -> Result<SignedTransaction, Error> {
        let envelope = self
            .sign_prepared_transaction(prepared)
            .await
            .map_err(wallet_sign_error)?;

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

/// Acceptance tests for [`WalletSigner::new`]. Node mode is sufficient because
/// acceptance is pure `Reflect` plumbing and no method is called.
#[cfg(all(test, target_arch = "wasm32"))]
mod spike_tests {
    // Tests favour `unwrap()` for brevity; the workspace-wide `unwrap_used` deny
    // is meant for production paths, not assertions.
    #![allow(clippy::unwrap_used)]

    use super::*;
    use wasm_bindgen_test::*;

    const PASSPHRASE: &str = "Test SDF Network ; September 2015";
    const ADDRESS: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

    /// A JS function returning a promise that never settles.
    fn pending_method() -> JsValue {
        Function::new_no_args("return new Promise(function () {});").into()
    }

    /// Build a signer object exposing exactly `methods`.
    fn signer_with(methods: &[&str]) -> JsValue {
        let signer = Object::new();
        for method in methods {
            Reflect::set(&signer, &JsValue::from_str(method), &pending_method()).unwrap();
        }
        signer.into()
    }

    fn new_signer(signer: JsValue) -> Result<WalletSigner, JsError> {
        WalletSigner::new(signer, PASSPHRASE.to_string(), SignerAddress::new(ADDRESS))
    }

    fn error_message(error: JsError) -> String {
        Reflect::get(&JsValue::from(error), &JsValue::from_str("message"))
            .unwrap()
            .as_string()
            .unwrap()
    }

    #[wasm_bindgen_test]
    fn spike_signer_acceptance_rejects_null() {
        for empty in [JsValue::NULL, JsValue::UNDEFINED] {
            let error = new_signer(empty)
                .err()
                .expect("null/undefined signer must be rejected");
            assert_eq!(error_message(error), "signer is required");
        }
    }

    #[wasm_bindgen_test]
    fn spike_signer_acceptance_rejects_partial() {
        for omitted in SIGN_METHODS {
            let present: Vec<&str> = SIGN_METHODS
                .iter()
                .copied()
                .filter(|method| method != omitted)
                .collect();
            let error = new_signer(signer_with(&present))
                .err()
                .unwrap_or_else(|| panic!("signer missing {omitted} must be rejected"));
            assert_eq!(
                error_message(error),
                format!("signer must implement {omitted}(...)")
            );
        }
    }

    #[wasm_bindgen_test]
    fn spike_signer_acceptance_accepts_full() {
        assert!(new_signer(signer_with(SIGN_METHODS)).is_ok());
    }

    /// Build a JS rejection carrying `code`.
    fn rejection_with_code(message: &str, code: f64) -> JsValue {
        let rejection = js_sys::Error::new(message);
        Reflect::set(
            &rejection,
            &JsValue::from_str("code"),
            &JsValue::from_f64(code),
        )
        .unwrap();
        rejection.into()
    }

    fn code_of(error: &JsError) -> Option<f64> {
        Reflect::get(&JsValue::from(error.clone()), &JsValue::from_str("code"))
            .ok()
            .and_then(|code| code.as_f64())
    }

    #[wasm_bindgen_test]
    fn spike_error_mapping_copies_code() {
        let wrapped = wallet_js_error(
            "signTransaction",
            "failed",
            rejection_with_code("stub halt", SEP43_USER_REJECTED_CODE),
        );

        assert_eq!(code_of(&wrapped), Some(SEP43_USER_REJECTED_CODE));
        assert_eq!(
            Reflect::get(&JsValue::from(wrapped), &JsValue::from_str("message"))
                .unwrap()
                .as_string()
                .unwrap(),
            "signer.signTransaction failed: stub halt"
        );
    }

    #[wasm_bindgen_test]
    fn spike_error_mapping_user_rejected() {
        let sentinel = wallet_js_error(
            "signTransaction",
            "failed",
            rejection_with_code("stub halt", SEP43_USER_REJECTED_CODE),
        );
        assert!(
            matches!(wallet_sign_error(sentinel), Error::UserRejected(_)),
            "code -4 must map to Error::UserRejected"
        );

        let codeless = wallet_js_error(
            "signTransaction",
            "failed",
            js_sys::Error::new("network blew up").into(),
        );
        assert_eq!(code_of(&codeless), None);
        assert!(
            matches!(wallet_sign_error(codeless), Error::Other(_)),
            "a code-less signer error must map to Error::Other"
        );

        let other_code = wallet_js_error(
            "signTransaction",
            "failed",
            rejection_with_code("some other wallet error", -1.0),
        );
        assert!(
            matches!(wallet_sign_error(other_code), Error::Other(_)),
            "only code -4 may map to Error::UserRejected"
        );
    }

    /// Fixed 64-byte signature blob the stub signer returns from `signMessage`.
    /// Key derivation SHA-256s the bytes with a domain tag; any 64-byte value
    /// works, but the length is enforced.
    const STUB_SIGNATURE_B64: &str =
        "paWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpQ==";
    /// The same 64 bytes as hex, kept to show it is not usable.
    const STUB_SIGNATURE_HEX: &str = concat!(
        "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5",
        "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"
    );

    #[wasm_bindgen_test]
    fn spike_key_derivation_blob_decodes() {
        let bytes = wallet_message_signature_to_bytes(STUB_SIGNATURE_B64).unwrap();
        assert_eq!(
            bytes.len(),
            64,
            "derivation rejects anything but exactly 64 bytes"
        );
        assert_eq!(bytes, vec![0xA5u8; 64]);

        // 128 hex chars decode as base64 before the hex fallback is tried, so a
        // 64-byte hex string yields 96 bytes and fails the length check.
        let via_hex = wallet_message_signature_to_bytes(STUB_SIGNATURE_HEX).unwrap();
        assert_eq!(
            via_hex.len(),
            96,
            "128 hex chars decode as base64, not as hex"
        );
    }

    /// A different valid-looking address than [`ADDRESS`], standing in for
    /// the account a wallet might actually be active on when the app asked
    /// it to sign as [`ADDRESS`].
    const OTHER_ADDRESS: &str = "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBWHF";

    /// Build a signer whose `signMessage` resolves immediately with the given
    /// `signerAddress`, mirroring exactly what a real SEP-0043 wallet's
    /// `signTransaction`/`signAuthEntry`/`signMessage` response shape looks
    /// like (a `{ signedMessage, signerAddress }` object — see
    /// `@stellar/freighter-api`'s type declarations, which mark
    /// `signerAddress` as always present). This is the realistic injection
    /// boundary for the mismatch: `WalletSigner::call()` reads `signerAddress`
    /// off exactly this kind of resolved value, so a stub returning a
    /// different one here exercises the same code path a wallet reporting a
    /// wrong active account would.
    fn signer_reporting(signer_address: &str) -> JsValue {
        let signer = Object::new();
        let body = format!(
            "return Promise.resolve({{ signedMessage: {:?}, signerAddress: {signer_address:?} }});",
            STUB_SIGNATURE_B64
        );
        Reflect::set(
            &signer,
            &JsValue::from_str("signMessage"),
            &Function::new_no_args(&body),
        )
        .unwrap();
        for method in SIGN_METHODS.iter().filter(|m| **m != "signMessage") {
            Reflect::set(&signer, &JsValue::from_str(method), &pending_method()).unwrap();
        }
        signer.into()
    }

    #[wasm_bindgen_test]
    async fn spike_matching_signer_address_is_accepted() {
        let wallet_signer = new_signer(signer_reporting(ADDRESS)).unwrap();
        let sig = wallet_signer
            .sign_wallet_message("hello")
            .await
            .expect("a signerAddress matching the request must be accepted");
        assert_eq!(sig, STUB_SIGNATURE_B64);
    }

    #[wasm_bindgen_test]
    async fn spike_mismatching_signer_address_is_rejected() {
        let wallet_signer = new_signer(signer_reporting(OTHER_ADDRESS)).unwrap();
        let error = wallet_signer
            .sign_wallet_message("hello")
            .await
            .expect_err("a signerAddress other than the requested one must be rejected");

        let value = JsValue::from(error.clone());
        assert!(
            Reflect::get(&value, &JsValue::from_str(SIGNER_ADDRESS_MISMATCH_MARKER))
                .unwrap()
                .is_truthy(),
            "the rejection must be marked as a signer-address mismatch, not a generic failure"
        );
        assert!(
            Reflect::get(&value, &JsValue::from_str("code"))
                .unwrap()
                .as_f64()
                != Some(SEP43_USER_REJECTED_CODE),
            "a signer-address mismatch must not be classified as a user rejection"
        );

        match wallet_sign_error(error) {
            Error::SignerAddressMismatch { requested, actual } => {
                assert_eq!(requested, ADDRESS);
                assert_eq!(actual, OTHER_ADDRESS);
            }
            other => panic!("expected Error::SignerAddressMismatch, got {other:?}"),
        }
    }
}
