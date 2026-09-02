use std::str::FromStr;

use serde::Serialize;
use stellar_private_payments::{
    disclosure::DisclosureRequest as NativeDisclosureRequest,
    types::{
        DisclosureCircuitMetadata as NativeDisclosureCircuitMetadata,
        DisclosureContext as NativeDisclosureContext,
        DisclosurePublicInputs as NativeDisclosurePublicInputs,
        DisclosureReceipt as NativeDisclosureReceipt,
        DisclosureVerificationReport as NativeDisclosureVerificationReport, Field,
    },
};
use wasm_bindgen::prelude::*;

use super::convert::field_hex;

#[wasm_bindgen]
pub struct DisclosureCircuitMetadata {
    inner: NativeDisclosureCircuitMetadata,
}

#[wasm_bindgen]
impl DisclosureCircuitMetadata {
    #[wasm_bindgen(getter)]
    pub fn name(&self) -> String {
        self.inner.name.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn levels(&self) -> u32 {
        self.inner.levels
    }

    #[wasm_bindgen(getter, js_name = nNotes)]
    pub fn n_notes(&self) -> u32 {
        self.inner.n_notes
    }

    #[wasm_bindgen(getter, js_name = vkHash)]
    pub fn vk_hash(&self) -> String {
        self.inner.vk_hash.clone()
    }
}

impl From<NativeDisclosureCircuitMetadata> for DisclosureCircuitMetadata {
    fn from(inner: NativeDisclosureCircuitMetadata) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen]
pub struct DisclosureContext {
    inner: NativeDisclosureContext,
}

#[wasm_bindgen]
impl DisclosureContext {
    #[wasm_bindgen(getter)]
    pub fn network(&self) -> String {
        self.inner.network.clone()
    }

    #[wasm_bindgen(getter, js_name = poolAddress)]
    pub fn pool_address(&self) -> String {
        self.inner.pool_address.clone()
    }

    #[wasm_bindgen(getter, js_name = authorityLabel)]
    pub fn authority_label(&self) -> String {
        self.inner.authority_label.clone()
    }

    #[wasm_bindgen(getter, js_name = authorityIdentityPayloadHex)]
    pub fn authority_identity_payload_hex(&self) -> String {
        self.inner.authority_identity_payload_hex.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn purpose(&self) -> String {
        self.inner.purpose.clone()
    }

    #[wasm_bindgen(getter, js_name = contextNonce)]
    pub fn context_nonce(&self) -> String {
        field_hex(&self.inner.context_nonce)
    }
}

impl From<NativeDisclosureContext> for DisclosureContext {
    fn from(inner: NativeDisclosureContext) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen]
pub struct DisclosurePublicInputs {
    inner: NativeDisclosurePublicInputs,
}

#[wasm_bindgen]
impl DisclosurePublicInputs {
    #[wasm_bindgen(getter)]
    pub fn roots(&self) -> Vec<String> {
        self.inner.roots.iter().map(field_hex).collect()
    }

    #[wasm_bindgen(getter, js_name = noteCommitments)]
    pub fn note_commitments(&self) -> Vec<String> {
        self.inner.note_commitments.iter().map(field_hex).collect()
    }

    #[wasm_bindgen(getter, js_name = extContextHash)]
    pub fn ext_context_hash(&self) -> String {
        field_hex(&self.inner.ext_context_hash)
    }

    #[wasm_bindgen(getter)]
    pub fn nullifiers(&self) -> Vec<String> {
        self.inner.nullifiers.iter().map(field_hex).collect()
    }

    #[wasm_bindgen(getter)]
    pub fn amounts(&self) -> Vec<String> {
        self.inner
            .amounts
            .iter()
            .map(|amount| amount.0.to_string())
            .collect()
    }
}

impl From<NativeDisclosurePublicInputs> for DisclosurePublicInputs {
    fn from(inner: NativeDisclosurePublicInputs) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen]
pub struct DisclosureReceipt {
    inner: NativeDisclosureReceipt,
}

#[wasm_bindgen]
impl DisclosureReceipt {
    #[wasm_bindgen(getter)]
    pub fn version(&self) -> u32 {
        self.inner.version
    }

    #[wasm_bindgen(getter)]
    pub fn circuit(&self) -> DisclosureCircuitMetadata {
        DisclosureCircuitMetadata::from(self.inner.circuit.clone())
    }

    #[wasm_bindgen(getter)]
    pub fn context(&self) -> DisclosureContext {
        DisclosureContext::from(self.inner.context.clone())
    }

    #[wasm_bindgen(getter, js_name = publicInputs)]
    pub fn public_inputs(&self) -> DisclosurePublicInputs {
        DisclosurePublicInputs::from(self.inner.public_inputs.clone())
    }

    #[wasm_bindgen(getter, js_name = proofCompressedHex)]
    pub fn proof_compressed_hex(&self) -> String {
        self.inner.proof_compressed_hex.clone()
    }

    #[wasm_bindgen(getter, js_name = issuedAt)]
    pub fn issued_at(&self) -> String {
        self.inner.issued_at.clone()
    }

    /// Plain JSON object for `JSON.stringify` / receipt export and
    /// verification.
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<JsValue, JsError> {
        self.inner
            .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
            .map_err(|e| JsError::new(&format!("failed to serialize disclosure receipt: {e}")))
    }

    /// Reconstruct a receipt from `toJSON` output, for verification after
    /// storage or transport.
    #[wasm_bindgen(js_name = fromJSON)]
    pub fn from_json(value: JsValue) -> Result<DisclosureReceipt, JsError> {
        let inner: NativeDisclosureReceipt = serde_wasm_bindgen::from_value(value)
            .map_err(|e| JsError::new(&format!("invalid disclosure receipt: {e}")))?;
        Ok(Self { inner })
    }
}

impl From<NativeDisclosureReceipt> for DisclosureReceipt {
    fn from(inner: NativeDisclosureReceipt) -> Self {
        Self { inner }
    }
}

impl DisclosureReceipt {
    pub(crate) fn native(&self) -> &NativeDisclosureReceipt {
        &self.inner
    }
}

#[wasm_bindgen]
pub struct DisclosureVerificationReport {
    inner: NativeDisclosureVerificationReport,
}

#[wasm_bindgen]
impl DisclosureVerificationReport {
    #[wasm_bindgen(getter, js_name = proofVerified)]
    pub fn proof_verified(&self) -> bool {
        self.inner.proof_verified
    }

    #[wasm_bindgen(getter, js_name = contextVerified)]
    pub fn context_verified(&self) -> bool {
        self.inner.context_verified
    }

    #[wasm_bindgen(getter, js_name = knownRootStatus)]
    pub fn known_root_status(&self) -> bool {
        self.inner.known_root_status
    }

    #[wasm_bindgen(getter, js_name = nullifiersUnspent)]
    pub fn nullifiers_unspent(&self) -> bool {
        self.inner.nullifiers_unspent
    }

    #[wasm_bindgen(getter, js_name = spentNullifierIndices)]
    pub fn spent_nullifier_indices(&self) -> js_sys::Array {
        self.inner
            .spent_nullifier_indices
            .iter()
            .map(|index| JsValue::from(*index))
            .collect()
    }
}

impl From<NativeDisclosureVerificationReport> for DisclosureVerificationReport {
    fn from(inner: NativeDisclosureVerificationReport) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen]
pub struct DisclosureRequest {
    inner: NativeDisclosureRequest,
}

#[wasm_bindgen]
impl DisclosureRequest {
    #[wasm_bindgen(constructor)]
    pub fn new(
        selected_commitments: Vec<String>,
        authority_label: String,
        authority_identity_payload_hex: String,
        purpose: String,
        context_nonce: String,
    ) -> Result<DisclosureRequest, JsError> {
        let selected_commitments = selected_commitments
            .iter()
            .map(|value| Field::from_str(value.trim()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| JsError::new(&e.to_string()))?;
        let context_nonce =
            Field::from_str(context_nonce.trim()).map_err(|e| JsError::new(&e.to_string()))?;
        Ok(Self {
            inner: NativeDisclosureRequest {
                selected_commitments,
                authority_label,
                authority_identity_payload_hex,
                purpose,
                context_nonce,
            },
        })
    }

    #[wasm_bindgen(js_name = fromValue)]
    pub fn from_value(value: JsValue) -> Result<DisclosureRequest, JsError> {
        let inner: NativeDisclosureRequest = serde_wasm_bindgen::from_value(value)
            .map_err(|e| JsError::new(&format!("invalid disclosure request: {e}")))?;
        Ok(Self { inner })
    }

    pub(crate) fn native(&self) -> NativeDisclosureRequest {
        self.inner.clone()
    }
}
