use stellar_private_payments::types::GlobalViewKeyCiphertext as NativeGlobalViewKeyCiphertext;
use wasm_bindgen::prelude::*;

use super::{baby_jubjub_point::BabyJubJubPoint, convert::field_hex};

/// GVK ciphertext attached to a note commitment event.
#[wasm_bindgen]
pub struct GlobalViewKeyCiphertext {
    inner: NativeGlobalViewKeyCiphertext,
}

#[wasm_bindgen]
impl GlobalViewKeyCiphertext {
    #[wasm_bindgen(getter)]
    pub fn r(&self) -> BabyJubJubPoint {
        BabyJubJubPoint::from(&self.inner.r)
    }

    #[wasm_bindgen(getter)]
    pub fn c1(&self) -> String {
        field_hex(&self.inner.c1)
    }

    #[wasm_bindgen(getter)]
    pub fn c2(&self) -> String {
        field_hex(&self.inner.c2)
    }

    #[wasm_bindgen(getter)]
    pub fn c3(&self) -> String {
        field_hex(&self.inner.c3)
    }
}

impl From<NativeGlobalViewKeyCiphertext> for GlobalViewKeyCiphertext {
    fn from(inner: NativeGlobalViewKeyCiphertext) -> Self {
        Self { inner }
    }
}

impl From<&NativeGlobalViewKeyCiphertext> for GlobalViewKeyCiphertext {
    fn from(inner: &NativeGlobalViewKeyCiphertext) -> Self {
        Self {
            inner: inner.clone(),
        }
    }
}
