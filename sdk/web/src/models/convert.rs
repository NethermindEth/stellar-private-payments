//! Shared native → JS field conversions for wasm-bindgen models.

use stellar_private_payments::types::{
    EncryptionPublicKey, Field, GvkMode, NoteAmount, NotePublicKey, POLICY_FLAGS_IN_SUFFIX_ORDER,
    PolicyFlags, encode_0x_hex,
};

pub(crate) fn gvk_mode_name(mode: GvkMode) -> &'static str {
    match mode {
        GvkMode::Off => "off",
        GvkMode::ViewOnly => "viewOnly",
        GvkMode::Traceable => "traceable",
    }
}

pub(crate) fn policy_flag_names(flags: PolicyFlags) -> Vec<String> {
    POLICY_FLAGS_IN_SUFFIX_ORDER
        .iter()
        .filter(|flag| flags.contains(**flag))
        .map(|flag| flag.name().to_string())
        .collect()
}

pub(crate) fn field_hex(value: &Field) -> String {
    value.to_string()
}

pub(crate) fn note_amount_string(value: &NoteAmount) -> String {
    value.to_string()
}

pub(crate) fn note_public_key_hex(value: &NotePublicKey) -> String {
    encode_0x_hex(&value.0)
}

pub(crate) fn encryption_public_key_hex(value: &EncryptionPublicKey) -> String {
    encode_0x_hex(&value.0)
}
