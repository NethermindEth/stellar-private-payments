use stellar_private_payments::types::BabyJubJubPoint as NativeBabyJubJubPoint;
use wasm_bindgen::prelude::*;

use super::convert::field_hex;

/// Baby JubJub curve point (BN254 field coordinates).
#[wasm_bindgen]
pub struct BabyJubJubPoint {
    inner: NativeBabyJubJubPoint,
}

#[wasm_bindgen]
impl BabyJubJubPoint {
    #[wasm_bindgen(getter)]
    pub fn x(&self) -> String {
        field_hex(&self.inner.x)
    }

    #[wasm_bindgen(getter)]
    pub fn y(&self) -> String {
        field_hex(&self.inner.y)
    }
}

impl From<NativeBabyJubJubPoint> for BabyJubJubPoint {
    fn from(inner: NativeBabyJubJubPoint) -> Self {
        Self { inner }
    }
}

impl From<&NativeBabyJubJubPoint> for BabyJubJubPoint {
    fn from(inner: &NativeBabyJubJubPoint) -> Self {
        Self {
            inner: inner.clone(),
        }
    }
}
