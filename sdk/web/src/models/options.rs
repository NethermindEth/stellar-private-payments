use std::str::FromStr;

use stellar_private_payments::{
    planner::Transact,
    types::{EncryptionPublicKey, ExtAmount, Field, NoteAmount, NotePublicKey},
    zk::flows::N_OUTPUTS,
};
use wasm_bindgen::prelude::*;

use super::config::contract_config_from_js;

pub(crate) struct TransactConfig {
    ext_recipient: String,
    ext_amount: i128,
    input_note_ids: Vec<String>,
    output_amounts: Vec<u128>,
    out_recipient_note_keys_hex: Vec<Option<String>>,
    out_recipient_enc_keys_hex: Vec<Option<String>>,
}

impl TransactConfig {
    fn from_value(value: JsValue) -> Result<TransactConfig, JsError> {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Raw {
            ext_recipient: String,
            ext_amount: i128,
            input_note_ids: Vec<String>,
            output_amounts: Vec<u128>,
            out_recipient_note_keys_hex: Vec<Option<String>>,
            out_recipient_enc_keys_hex: Vec<Option<String>>,
        }
        let raw: Raw = serde_wasm_bindgen::from_value(value)
            .map_err(|e| JsError::new(&format!("invalid transact config: {e}")))?;
        Ok(Self {
            ext_recipient: raw.ext_recipient,
            ext_amount: raw.ext_amount,
            input_note_ids: raw.input_note_ids,
            output_amounts: raw.output_amounts,
            out_recipient_note_keys_hex: raw.out_recipient_note_keys_hex,
            out_recipient_enc_keys_hex: raw.out_recipient_enc_keys_hex,
        })
    }

    fn into_transact(self) -> Result<Transact, JsError> {
        if self.input_note_ids.len() > 2 {
            return Err(JsError::new("inputNoteIds must have length 0..=2"));
        }
        if self.output_amounts.len() != N_OUTPUTS {
            return Err(JsError::new(&format!(
                "outputAmounts must have length {N_OUTPUTS}"
            )));
        }
        if self.out_recipient_note_keys_hex.len() != N_OUTPUTS {
            return Err(JsError::new(&format!(
                "outRecipientNoteKeysHex must have length {N_OUTPUTS}"
            )));
        }
        if self.out_recipient_enc_keys_hex.len() != N_OUTPUTS {
            return Err(JsError::new(&format!(
                "outRecipientEncKeysHex must have length {N_OUTPUTS}"
            )));
        }

        let ext_amount = ExtAmount::from(self.ext_amount);
        let input_commitments = self
            .input_note_ids
            .iter()
            .map(|s| Field::from_str(s.trim()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| JsError::new(&e.to_string()))?;

        let mut output_amounts = [NoteAmount::ZERO; N_OUTPUTS];
        for (out, stroops) in output_amounts.iter_mut().zip(self.output_amounts) {
            *out = NoteAmount::from(stroops);
        }

        let mut out_recipient_note_pubkeys: [Option<NotePublicKey>; N_OUTPUTS] = [None, None];
        let mut out_recipient_encryption_pubkeys: [Option<EncryptionPublicKey>; N_OUTPUTS] =
            [None, None];
        for i in 0..N_OUTPUTS {
            if let Some(hex) = &self.out_recipient_note_keys_hex[i] {
                out_recipient_note_pubkeys[i] =
                    Some(NotePublicKey::parse(hex).map_err(|e| JsError::new(&e.to_string()))?);
            }
            if let Some(hex) = &self.out_recipient_enc_keys_hex[i] {
                out_recipient_encryption_pubkeys[i] = Some(
                    EncryptionPublicKey::parse(hex).map_err(|e| JsError::new(&e.to_string()))?,
                );
            }
        }

        Ok(Transact::new(
            input_commitments,
            output_amounts,
            ext_amount,
            self.ext_recipient,
            out_recipient_note_pubkeys,
            out_recipient_encryption_pubkeys,
        ))
    }
}

pub(crate) fn transact_from_js(value: JsValue) -> Result<Transact, JsError> {
    TransactConfig::from_value(value)?.into_transact()
}

#[wasm_bindgen]
pub struct PoolOptions {
    pool_contract: String,
}

#[wasm_bindgen]
impl PoolOptions {
    #[wasm_bindgen(constructor)]
    pub fn new(pool_contract: String) -> Self {
        Self { pool_contract }
    }

    #[wasm_bindgen(js_name = fromValue)]
    pub fn from_value(value: JsValue) -> Result<PoolOptions, JsError> {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Raw {
            pool_contract: String,
        }
        let raw: Raw = serde_wasm_bindgen::from_value(value)
            .map_err(|e| JsError::new(&format!("invalid pool options: {e}")))?;
        Ok(Self {
            pool_contract: raw.pool_contract,
        })
    }

    #[wasm_bindgen(getter, js_name = poolContract)]
    pub fn pool_contract(&self) -> String {
        self.pool_contract.clone()
    }
}

#[wasm_bindgen]
pub struct RegisterPublicKeysOptions {
    note_public_key_hex: Option<String>,
    encryption_public_key_hex: Option<String>,
}

#[wasm_bindgen]
impl RegisterPublicKeysOptions {
    #[wasm_bindgen(constructor)]
    pub fn new(
        note_public_key_hex: Option<String>,
        encryption_public_key_hex: Option<String>,
    ) -> Self {
        Self {
            note_public_key_hex,
            encryption_public_key_hex,
        }
    }

    #[wasm_bindgen(js_name = fromValue)]
    pub fn from_value(value: JsValue) -> Result<RegisterPublicKeysOptions, JsError> {
        if value.is_null() || value.is_undefined() {
            return Ok(Self {
                note_public_key_hex: None,
                encryption_public_key_hex: None,
            });
        }
        #[derive(serde::Deserialize, Default)]
        #[serde(rename_all = "camelCase")]
        struct Raw {
            note_public_key_hex: Option<String>,
            encryption_public_key_hex: Option<String>,
        }
        let raw: Raw = serde_wasm_bindgen::from_value(value)
            .map_err(|e| JsError::new(&format!("invalid registerPublicKeys options: {e}")))?;
        Ok(Self {
            note_public_key_hex: raw.note_public_key_hex,
            encryption_public_key_hex: raw.encryption_public_key_hex,
        })
    }

    pub(crate) fn note_public_key_hex(&self) -> Option<String> {
        self.note_public_key_hex.clone()
    }

    pub(crate) fn encryption_public_key_hex(&self) -> Option<String> {
        self.encryption_public_key_hex.clone()
    }
}

#[wasm_bindgen]
pub struct AccountOptions {
    network_passphrase: String,
    user_address: Option<String>,
    signer_address: Option<String>,
}

#[wasm_bindgen]
impl AccountOptions {
    #[wasm_bindgen(js_name = fromValue)]
    pub fn from_value(value: JsValue) -> Result<AccountOptions, JsError> {
        if value.is_null() || value.is_undefined() {
            return Err(JsError::new(
                "account options with networkPassphrase are required",
            ));
        }
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Raw {
            network_passphrase: String,
            user_address: Option<String>,
            signer_address: Option<String>,
        }
        let raw: Raw = serde_wasm_bindgen::from_value(value)
            .map_err(|e| JsError::new(&format!("invalid account options: {e}")))?;
        Ok(Self {
            network_passphrase: raw.network_passphrase,
            user_address: raw.user_address,
            signer_address: raw.signer_address,
        })
    }

    pub(crate) fn network_passphrase(&self) -> &str {
        &self.network_passphrase
    }

    pub(crate) fn user_address(&self) -> Option<&str> {
        self.user_address.as_deref()
    }

    pub(crate) fn signer_address(&self) -> Option<&str> {
        self.signer_address.as_deref()
    }
}

#[wasm_bindgen]
pub struct VerifyDisclosureOptions {
    prover_worker_url: Option<String>,
    contract_config: super::config::ContractConfig,
    circuits_base_url: String,
}

#[wasm_bindgen]
impl VerifyDisclosureOptions {
    #[wasm_bindgen(js_name = fromValue)]
    pub fn from_value(value: JsValue) -> Result<VerifyDisclosureOptions, JsError> {
        if value.is_null() || value.is_undefined() {
            return Err(JsError::new(
                "verifySelectiveDisclosure options with contractConfig and circuitsBaseUrl are required",
            ));
        }
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Raw {
            prover_worker_url: Option<String>,
            circuits_base_url: String,
        }
        let contract_config = js_sys::Reflect::get(&value, &JsValue::from_str("contractConfig"))
            .map_err(|_| {
                JsError::new("verifySelectiveDisclosure options: contractConfig is required")
            })?;
        let raw: Raw = serde_wasm_bindgen::from_value(value).map_err(|e| {
            JsError::new(&format!("invalid verifySelectiveDisclosure options: {e}"))
        })?;
        Ok(Self {
            prover_worker_url: raw.prover_worker_url,
            contract_config: contract_config_from_js(contract_config)?,
            circuits_base_url: raw.circuits_base_url,
        })
    }

    pub(crate) fn prover_worker_url(&self) -> Option<&str> {
        self.prover_worker_url.as_deref()
    }

    pub(crate) fn contract_config(&self) -> &super::config::ContractConfig {
        &self.contract_config
    }

    pub(crate) fn circuits_base_url(&self) -> &str {
        &self.circuits_base_url
    }
}
