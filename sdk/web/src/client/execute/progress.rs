//! In-flight transaction progress via DOM `CustomEvent`.

use js_sys::{Array, Function, Object, Reflect};
use serde::Serialize;
use wasm_bindgen::{JsCast, JsValue};
use web_sys::Window;

pub const TX_PROGRESS_EVENT: &str = "stellar-private-payments:tx-progress";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TxProgressDetail<'a> {
    flow: &'a str,
    stage: &'a str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    current: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    total: Option<u32>,
}

pub(crate) fn emit(
    flow: &'static str,
    stage: &'static str,
    message: impl Into<String>,
    current: Option<u32>,
    total: Option<u32>,
) {
    let Some(window) = web_sys::window() else {
        return;
    };
    dispatch(&window, flow, stage, message.into(), current, total);
}

fn dispatch(
    window: &Window,
    flow: &str,
    stage: &str,
    message: String,
    current: Option<u32>,
    total: Option<u32>,
) {
    let detail = TxProgressDetail {
        flow,
        stage,
        message,
        current,
        total,
    };
    let Ok(detail_val) = serde_wasm_bindgen::to_value(&detail) else {
        return;
    };
    dispatch_detail(window, detail_val);
}

fn dispatch_detail(window: &Window, detail: JsValue) {
    let init = Object::new();
    let _ = Reflect::set(&init, &JsValue::from_str("detail"), &detail);

    let Ok(ctor_val) = Reflect::get(window, &JsValue::from_str("CustomEvent")) else {
        return;
    };
    let Ok(ctor) = ctor_val.dyn_into::<Function>() else {
        return;
    };
    let args = Array::new();
    args.push(&JsValue::from_str(TX_PROGRESS_EVENT));
    args.push(&init);

    let Ok(event_val) = Reflect::construct(&ctor, &args) else {
        return;
    };
    let Ok(event) = event_val.dyn_into::<web_sys::Event>() else {
        return;
    };
    let _ = window.dispatch_event(&event);
}
