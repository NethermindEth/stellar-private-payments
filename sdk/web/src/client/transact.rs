//! Parse a [`Transact`] step from JS for the low-level `transact` op.

use serde::Deserialize;
use std::str::FromStr;
use stellar_private_payments_sdk::{
    Transact,
    tx::flows::N_OUTPUTS,
    types::{EncryptionPublicKey, ExtAmount, Field, NoteAmount, NotePublicKey},
};
use wasm_bindgen::{JsError, JsValue};

use crate::amounts::parse_token_amount;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransactConfig {
    ext_recipient: String,
    /// Signed external amount in stroops (decimal string).
    ext_amount: String,
    /// Pool commitment hex strings (0–2 entries).
    input_note_ids: Vec<String>,
    /// Output note amounts in stroops (exactly 2).
    output_amounts: Vec<String>,
    /// Recipient note public keys per output (`null` when unused).
    out_recipient_note_keys_hex: Vec<Option<String>>,
    out_recipient_enc_keys_hex: Vec<Option<String>>,
}

pub(crate) fn parse_transact_step(config: JsValue) -> Result<Transact, JsError> {
    let cfg: TransactConfig = serde_wasm_bindgen::from_value(config)?;

    if cfg.input_note_ids.len() > 2 {
        return Err(JsError::new("input_note_ids must have length 0..=2"));
    }
    if cfg.output_amounts.len() != N_OUTPUTS {
        return Err(JsError::new(&format!(
            "output_amounts must have length {N_OUTPUTS}"
        )));
    }
    if cfg.out_recipient_note_keys_hex.len() != N_OUTPUTS {
        return Err(JsError::new(&format!(
            "out_recipient_note_keys_hex must have length {N_OUTPUTS}"
        )));
    }
    if cfg.out_recipient_enc_keys_hex.len() != N_OUTPUTS {
        return Err(JsError::new(&format!(
            "out_recipient_enc_keys_hex must have length {N_OUTPUTS}"
        )));
    }

    let ext_amount =
        ExtAmount::from_str(cfg.ext_amount.trim()).map_err(|e| JsError::new(&e.to_string()))?;

    let input_commitments = cfg
        .input_note_ids
        .iter()
        .map(|s| Field::from_str(s.trim()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| JsError::new(&e.to_string()))?;

    let mut output_amounts = [NoteAmount::ZERO; N_OUTPUTS];
    for (out, s) in output_amounts.iter_mut().zip(cfg.output_amounts) {
        let stroops = parse_token_amount(&s)?;
        *out = NoteAmount::from(stroops);
    }

    let mut out_recipient_note_pubkeys: [Option<NotePublicKey>; N_OUTPUTS] = [None, None];
    let mut out_recipient_encryption_pubkeys: [Option<EncryptionPublicKey>; N_OUTPUTS] =
        [None, None];
    for i in 0..N_OUTPUTS {
        if let Some(hex) = &cfg.out_recipient_note_keys_hex[i] {
            out_recipient_note_pubkeys[i] =
                Some(NotePublicKey::parse(hex).map_err(|e| JsError::new(&e.to_string()))?);
        }
        if let Some(hex) = &cfg.out_recipient_enc_keys_hex[i] {
            out_recipient_encryption_pubkeys[i] =
                Some(EncryptionPublicKey::parse(hex).map_err(|e| JsError::new(&e.to_string()))?);
        }
    }

    Ok(Transact::new(
        input_commitments,
        output_amounts,
        ext_amount,
        cfg.ext_recipient,
        out_recipient_note_pubkeys,
        out_recipient_encryption_pubkeys,
    ))
}
