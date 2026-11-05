//! Wasm wrappers around admin call envelopes: what a call does, who signed
//! it, and its submission.

use stellar_private_payments::{
    Error,
    operator::{
        CallStatus as NativeCallStatus, Envelopes as NativeEnvelopes,
        OperatorCall as NativeOperatorCall, SignerWeight as NativeSignerWeight,
        SigningStatus as NativeSigningStatus, UnsignedOperatorCall as NativeUnsignedOperatorCall,
    },
};
use wasm_bindgen::prelude::*;

use crate::client::pool_err;

/// Maps an operator error to a JS `Error`. A call that reads entries about to
/// archive carries the `stellar contract extend` commands that fix it as
/// `extendCommands`.
pub(crate) fn operator_err(error: Error) -> JsValue {
    if let Error::EntriesArchiveSoon { extend_commands } = &error {
        let js_error = js_sys::Error::new(&error.to_string());
        let commands: js_sys::Array = extend_commands
            .iter()
            .map(|command| JsValue::from_str(command))
            .collect();
        let _ = js_sys::Reflect::set(&js_error, &JsValue::from_str("extendCommands"), &commands);
        return js_error.into();
    }
    pool_err(error).into()
}

/// What an admin call envelope does, as its signers read it.
#[wasm_bindgen]
pub struct OperatorCall {
    inner: NativeOperatorCall,
}

#[wasm_bindgen]
impl OperatorCall {
    #[wasm_bindgen(getter)]
    pub fn source(&self) -> String {
        self.inner.source.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn sequence(&self) -> String {
        self.inner.sequence.to_string()
    }

    /// Most the source pays, in stroops.
    #[wasm_bindgen(getter)]
    pub fn fee(&self) -> u32 {
        self.inner.fee
    }

    /// Unix seconds after which the network refuses the envelope.
    #[wasm_bindgen(getter, js_name = validUntil)]
    #[allow(clippy::cast_precision_loss)]
    pub fn valid_until(&self) -> f64 {
        self.inner.valid_until as f64
    }

    #[wasm_bindgen(getter, js_name = contractId)]
    pub fn contract_id(&self) -> String {
        self.inner.contract_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn method(&self) -> String {
        self.inner.method.clone()
    }

    /// Arguments as text: addresses as strkeys, 256-bit integers as `0x` hex.
    #[wasm_bindgen(getter)]
    pub fn args(&self) -> Vec<String> {
        self.inner.args_text()
    }
}

/// An admin call, simulated and ready for its source's signers.
#[wasm_bindgen]
pub struct UnsignedOperatorCall {
    inner: NativeUnsignedOperatorCall,
}

#[wasm_bindgen]
impl UnsignedOperatorCall {
    /// Base64 `TransactionEnvelope` without signatures.
    #[wasm_bindgen(getter, js_name = envelopeXdr)]
    pub fn envelope_xdr(&self) -> String {
        self.inner.envelope_xdr.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn call(&self) -> OperatorCall {
        OperatorCall {
            inner: self.inner.call.clone(),
        }
    }
}

impl From<NativeUnsignedOperatorCall> for UnsignedOperatorCall {
    fn from(inner: NativeUnsignedOperatorCall) -> Self {
        Self { inner }
    }
}

/// One key that may sign for an admin account.
#[wasm_bindgen]
pub struct SignerWeight {
    inner: NativeSignerWeight,
}

#[wasm_bindgen]
impl SignerWeight {
    #[wasm_bindgen(getter)]
    pub fn key(&self) -> String {
        self.inner.key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn weight(&self) -> u32 {
        self.inner.weight
    }

    #[wasm_bindgen(getter)]
    pub fn signed(&self) -> bool {
        self.inner.signed
    }
}

/// How far an envelope is from the weight its source requires.
#[wasm_bindgen]
pub struct SigningStatus {
    inner: NativeSigningStatus,
}

#[wasm_bindgen]
impl SigningStatus {
    /// The source's medium threshold, at least 1.
    #[wasm_bindgen(getter)]
    pub fn threshold(&self) -> u32 {
        self.inner.threshold
    }

    #[wasm_bindgen(getter, js_name = signedWeight)]
    pub fn signed_weight(&self) -> u32 {
        self.inner.signed_weight
    }

    #[wasm_bindgen(getter)]
    pub fn ready(&self) -> bool {
        self.inner.is_ready()
    }

    #[wasm_bindgen(getter)]
    pub fn signers(&self) -> Vec<SignerWeight> {
        self.inner
            .signers
            .iter()
            .cloned()
            .map(|inner| SignerWeight { inner })
            .collect()
    }
}

/// Where a submitted admin call stands.
#[wasm_bindgen]
pub struct CallStatus {
    inner: NativeCallStatus,
}

#[wasm_bindgen]
impl CallStatus {
    /// `success`, `failed` or `pending`.
    #[wasm_bindgen(getter)]
    pub fn status(&self) -> String {
        match self.inner {
            NativeCallStatus::Success => "success",
            NativeCallStatus::Failed { .. } => "failed",
            NativeCallStatus::Pending => "pending",
        }
        .to_string()
    }

    /// Base64 `TransactionResult` of a failed call, when the RPC returned
    /// one.
    #[wasm_bindgen(getter, js_name = resultXdr)]
    pub fn result_xdr(&self) -> Option<String> {
        match &self.inner {
            NativeCallStatus::Failed { result_xdr, .. } => result_xdr.clone(),
            _ => None,
        }
    }

    /// Contract or host error that stopped a failed call, such as
    /// `Error(Contract, #6)`, when the RPC returned its diagnostic events.
    #[wasm_bindgen(getter, js_name = hostError)]
    pub fn host_error(&self) -> Option<String> {
        match &self.inner {
            NativeCallStatus::Failed { host_error, .. } => host_error.clone(),
            _ => None,
        }
    }
}

/// Reads, submits and confirms admin call envelopes for any role.
#[wasm_bindgen]
pub struct Envelopes {
    inner: NativeEnvelopes,
}

#[wasm_bindgen]
impl Envelopes {
    #[wasm_bindgen(js_name = open)]
    pub fn open(rpc_url: String, network_passphrase: String) -> Result<Envelopes, JsError> {
        crate::wasm_start();
        Ok(Self {
            inner: NativeEnvelopes::open(&rpc_url, &network_passphrase).map_err(pool_err)?,
        })
    }

    /// Reads an envelope, refusing anything its signers could not read in
    /// full.
    pub fn describe(&self, envelope_xdr: String) -> Result<OperatorCall, JsError> {
        Ok(OperatorCall {
            inner: self.inner.describe(&envelope_xdr).map_err(pool_err)?,
        })
    }

    /// The source's signers and which of them signed the envelope.
    #[wasm_bindgen(js_name = signingStatus)]
    pub async fn signing_status(&self, envelope_xdr: String) -> Result<SigningStatus, JsError> {
        Ok(SigningStatus {
            inner: self
                .inner
                .signing_status(&envelope_xdr)
                .await
                .map_err(pool_err)?,
        })
    }

    /// Sends a signed envelope; returns its transaction hash.
    pub async fn submit(&self, signed_envelope_xdr: String) -> Result<String, JsError> {
        self.inner
            .submit(&signed_envelope_xdr)
            .await
            .map_err(pool_err)
    }

    /// Polls a submitted call once.
    pub async fn confirm(&self, hash: String) -> Result<CallStatus, JsError> {
        Ok(CallStatus {
            inner: self.inner.confirm(&hash).await.map_err(pool_err)?,
        })
    }
}
