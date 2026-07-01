//! Fetch compiled circuit artifacts from the app static server.

use js_sys::{ArrayBuffer, Reflect, Uint8Array};
use wasm_bindgen::{JsCast, JsError, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode};

pub(crate) async fn fetch_circuit_file(path: &str) -> Result<Vec<u8>, JsError> {
    const PUBLIC_URL: Option<&str> = option_env!("PUBLIC_URL");
    let global = js_sys::global();

    let location = Reflect::get(&global, &JsValue::from_str("location"))
        .map_err(|_| JsError::new("accessing self.location failed"))?;

    let origin = Reflect::get(&location, &JsValue::from_str("origin"))
        .map_err(|_| JsError::new("accessing self.location.origin failed"))?
        .as_string()
        .ok_or_else(|| JsError::new("origin is not a string"))?;

    let public_url = PUBLIC_URL.unwrap_or("/");

    let url_string = if public_url.starts_with("http://") || public_url.starts_with("https://") {
        format!("{public_url}{path}")
    } else if public_url == "/" {
        format!("{origin}/{path}")
    } else {
        return Err(JsError::new("PUBLIC_URL must be an absolute URL or '/'"));
    };

    log::debug!("[circuits] fetching {url_string}");

    let opts = RequestInit::new();
    opts.set_method("GET");
    opts.set_mode(RequestMode::Cors);

    let request = Request::new_with_str_and_init(&url_string, &opts)
        .map_err(|e| JsError::new(&format!("request failed for {url_string}: {e:?}")))?;

    let resp_value = if let Some(window) = web_sys::window() {
        JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(|e| JsError::new(&format!("network error: {e:?}")))?
    } else {
        let worker: web_sys::WorkerGlobalScope = global
            .dyn_into()
            .map_err(|_| JsError::new("no window or worker global scope"))?;
        JsFuture::from(worker.fetch_with_request(&request))
            .await
            .map_err(|e| JsError::new(&format!("network error: {e:?}")))?
    };

    let resp: web_sys::Response = resp_value
        .dyn_into()
        .map_err(|_| JsError::new("failed to cast response"))?;

    if !resp.ok() {
        return Err(JsError::new(&format!(
            "HTTP {} for {}",
            resp.status(),
            url_string
        )));
    }

    let array_buffer_promise = resp
        .array_buffer()
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    let array_buffer_value = JsFuture::from(array_buffer_promise)
        .await
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    let array_buffer: ArrayBuffer = array_buffer_value
        .dyn_into()
        .map_err(|_| JsError::new("failed to cast array buffer"))?;
    let uint8_array = Uint8Array::new(&array_buffer);
    Ok(uint8_array.to_vec())
}
