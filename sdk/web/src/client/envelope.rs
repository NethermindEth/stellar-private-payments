//! Wasm wrappers around admin call envelopes: what a call does.

use stellar_private_payments::{
    Error,
    operator::{
        OperatorCall as NativeOperatorCall, UnsignedOperatorCall as NativeUnsignedOperatorCall,
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
