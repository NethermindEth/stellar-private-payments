use stellar_private_payments::types::{
    EncryptionPublicKey, NotePublicKey, UserNoteSummary as NativeUserNoteSummary,
};
use wasm_bindgen::prelude::*;

use super::{
    convert::{encryption_public_key_hex, field_hex, note_amount_string, note_public_key_hex},
    global_view_key_ciphertext::GlobalViewKeyCiphertext,
};

/// Compact note view returned by [`crate::Account::user_notes`] and
/// [`crate::PrivatePool::notes`].
#[wasm_bindgen]
pub struct UserNoteSummary {
    inner: NativeUserNoteSummary,
}

#[wasm_bindgen]
impl UserNoteSummary {
    /// Pool commitment (`0x` field hex).
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> String {
        field_hex(&self.inner.id)
    }

    #[wasm_bindgen(getter, js_name = poolContractId)]
    pub fn pool_contract_id(&self) -> String {
        self.inner.pool_contract_id.clone()
    }

    /// Stroops as a decimal string.
    #[wasm_bindgen(getter)]
    pub fn amount(&self) -> String {
        note_amount_string(&self.inner.amount)
    }

    #[wasm_bindgen(getter, js_name = leafIndex)]
    pub fn leaf_index(&self) -> u32 {
        self.inner.leaf_index
    }

    #[wasm_bindgen(getter, js_name = createdAtLedger)]
    pub fn created_at_ledger(&self) -> u32 {
        self.inner.created_at_ledger
    }

    #[wasm_bindgen(getter)]
    pub fn spent(&self) -> bool {
        self.inner.spent
    }

    #[wasm_bindgen(getter, js_name = gvkCiphertext)]
    pub fn gvk_ciphertext(&self) -> Option<GlobalViewKeyCiphertext> {
        self.inner
            .gvk_ciphertext
            .as_ref()
            .map(GlobalViewKeyCiphertext::from)
    }
}

impl From<NativeUserNoteSummary> for UserNoteSummary {
    fn from(inner: NativeUserNoteSummary) -> Self {
        Self { inner }
    }
}

pub(crate) fn user_note_summaries(values: Vec<NativeUserNoteSummary>) -> Vec<UserNoteSummary> {
    values.into_iter().map(UserNoteSummary::from).collect()
}

/// Locally derived note and encryption public keys for an account.
#[wasm_bindgen]
pub struct UserPublicKeys {
    note_public_key: String,
    encryption_public_key: String,
}

#[wasm_bindgen]
impl UserPublicKeys {
    #[wasm_bindgen(getter, js_name = notePublicKey)]
    pub fn note_public_key(&self) -> String {
        self.note_public_key.clone()
    }

    #[wasm_bindgen(getter, js_name = encryptionPublicKey)]
    pub fn encryption_public_key(&self) -> String {
        self.encryption_public_key.clone()
    }
}

impl From<(NotePublicKey, EncryptionPublicKey)> for UserPublicKeys {
    fn from((note, enc): (NotePublicKey, EncryptionPublicKey)) -> Self {
        Self {
            note_public_key: note_public_key_hex(&note),
            encryption_public_key: encryption_public_key_hex(&enc),
        }
    }
}
