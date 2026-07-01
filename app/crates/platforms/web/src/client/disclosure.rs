//! WASM selective-disclosure methods on [`Pool`].

use super::{emit_progress, parse_field_bigint_numeric, parse_field_hex_str, pool::Pool, pool_err};
use js_sys::{BigInt, Function};
use stellar_private_payments_sdk::DisclosureRequest;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
impl Pool {
    #[wasm_bindgen(js_name = disclose)]
    #[allow(clippy::too_many_arguments)]
    pub async fn disclose_wasm(
        &self,
        selected_commitment_hex: String,
        authority_label: String,
        authority_identity_payload_hex: String,
        purpose: String,
        context_nonce: BigInt,
        on_status: Option<Function>,
    ) -> Result<JsValue, JsError> {
        let receipt = self
            .disclose_inner(
                selected_commitment_hex,
                authority_label,
                authority_identity_payload_hex,
                purpose,
                context_nonce,
                on_status,
            )
            .await?;
        match receipt {
            None => Ok(JsValue::NULL),
            Some(r) => Ok(serde_wasm_bindgen::to_value(&r)?),
        }
    }

    #[wasm_bindgen(js_name = verifyDisclosure)]
    pub async fn verify_disclosure_wasm(
        &self,
        receipt_json: String,
        expected_vk_hash: String,
    ) -> Result<JsValue, JsError> {
        let receipt = serde_json::from_str(&receipt_json)
            .map_err(|e| JsError::new(&format!("invalid receipt JSON: {e}")))?;
        let report = self
            .inner()
            .verify_disclosure(&receipt, &expected_vk_hash)
            .await
            .map_err(pool_err)?;
        Ok(serde_wasm_bindgen::to_value(&report)?)
    }
}

impl Pool {
    async fn disclose_inner(
        &self,
        selected_commitment_hex: String,
        authority_label: String,
        authority_identity_payload_hex: String,
        purpose: String,
        context_nonce: BigInt,
        on_status: Option<Function>,
    ) -> Result<Option<stellar_private_payments_sdk::types::DisclosureReceipt>, JsError> {
        let on_status = &on_status;
        emit_progress(
            on_status,
            "disclosure",
            "sync_check",
            "Checking sync & ASP membership…",
            None,
            None,
        );
        emit_progress(
            on_status,
            "disclosure",
            "fetch_chain_state",
            "Fetching on-chain state…",
            None,
            None,
        );

        let req = DisclosureRequest {
            selected_commitment: parse_field_hex_str(&selected_commitment_hex)?,
            authority_label,
            authority_identity_payload_hex,
            purpose,
            context_nonce: parse_field_bigint_numeric(&context_nonce)?,
        };

        emit_progress(
            on_status,
            "disclosure",
            "load_state",
            "Building witness inputs…",
            None,
            None,
        );
        emit_progress(on_status, "disclosure", "prove", "Proving…", None, None);

        self.inner().disclose(req).await.map_err(pool_err)
    }
}
