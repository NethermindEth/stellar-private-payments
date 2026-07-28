//! Fetch compiled circuit artifacts bundled with the npm package or from the
//! host app.

use js_sys::{ArrayBuffer, Reflect, Uint8Array};
use sha2::{Digest as _, Sha256};
use std::fmt::Write as _;
use wasm_bindgen::{JsCast, JsError, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Cache, CacheStorage, Request, RequestInit, RequestMode, Response};

const CIRCUITS_BASE_GLOBAL: &str = "__STELLAR_PRIVATE_PAYMENTS_CIRCUITS_BASE__";
const CACHE_NAME: &str = "stellar-circuits-v1";

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..]);
    out
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().wrapping_mul(2));
    for b in bytes {
        write!(&mut out, "{:02x}", b).expect("writing to String should not fail");
    }
    out
}

pub(crate) fn ensure_sha256_matches(
    name: &str,
    bytes: &[u8],
    expected_len: usize,
    expected_sha256: [u8; 32],
) -> Result<(), JsError> {
    if bytes.len() != expected_len {
        return Err(JsError::new(&format!(
            "{name} length mismatch: expected={}, got={}",
            expected_len,
            bytes.len(),
        )));
    }
    let actual = sha256(bytes);
    if actual != expected_sha256 {
        return Err(JsError::new(&format!(
            "{name} SHA256 mismatch: expected={}, got={}",
            to_hex(&expected_sha256),
            to_hex(&actual),
        )));
    }
    Ok(())
}

fn circuit_fetch_url(filename: &str) -> Result<String, JsError> {
    let global = js_sys::global();

    if let Ok(value) = Reflect::get(&global, &JsValue::from_str(CIRCUITS_BASE_GLOBAL))
        && let Some(base) = value.as_string()
        && !base.is_empty()
    {
        return Ok(format!("{base}{filename}"));
    }

    const PUBLIC_URL: Option<&str> = option_env!("PUBLIC_URL");

    let location = Reflect::get(&global, &JsValue::from_str("location"))
        .map_err(|_| JsError::new("accessing self.location failed"))?;

    let origin = Reflect::get(&location, &JsValue::from_str("origin"))
        .map_err(|_| JsError::new("accessing self.location.origin failed"))?
        .as_string()
        .ok_or_else(|| JsError::new("origin is not a string"))?;

    let public_url = PUBLIC_URL.unwrap_or("/");
    let path = format!("circuits/{filename}");

    if public_url.starts_with("http://") || public_url.starts_with("https://") {
        Ok(format!("{public_url}{path}"))
    } else if public_url == "/" {
        Ok(format!("{origin}/{path}"))
    } else {
        Err(JsError::new("PUBLIC_URL must be an absolute URL or '/'"))
    }
}

fn get_cache_storage() -> Result<Option<CacheStorage>, JsError> {
    let global = js_sys::global();
    if let Ok(caches) = Reflect::get(&global, &JsValue::from_str("caches")) {
        if caches.is_undefined() {
            return Ok(None);
        }
        let storage: CacheStorage = caches
            .dyn_into()
            .map_err(|_| JsError::new("failed to cast caches to CacheStorage"))?;
        Ok(Some(storage))
    } else {
        Ok(None)
    }
}

async fn open_cache() -> Result<Option<Cache>, JsError> {
    if let Some(storage) = get_cache_storage()? {
        let cache_val = JsFuture::from(storage.open(CACHE_NAME))
            .await
            .map_err(|e| JsError::new(&format!("failed to open cache: {e:?}")))?;
        let cache: Cache = cache_val
            .dyn_into()
            .map_err(|_| JsError::new("failed to cast Cache"))?;
        Ok(Some(cache))
    } else {
        Ok(None)
    }
}

async fn response_to_bytes(resp: Response) -> Result<Vec<u8>, JsError> {
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

pub(crate) async fn fetch_circuit_file(filename: &str) -> Result<Vec<u8>, JsError> {
    let url_string = circuit_fetch_url(filename)?;
    tracing::debug!("[circuits] fetching {url_string}");

    let cache_opt = open_cache().await.unwrap_or_else(|e| {
        tracing::warn!("[circuits] failed to open cache: {:?}", e);
        None
    });

    if let Some(cache) = &cache_opt {
        let match_val = JsFuture::from(cache.match_with_str(&url_string))
            .await
            .map_err(|e| JsError::new(&format!("cache.match error: {e:?}")))?;

        if !match_val.is_undefined() {
            tracing::debug!("[circuits] cache hit for {url_string}");
            let resp: Response = match_val
                .dyn_into()
                .map_err(|_| JsError::new("cache hit cast failed"))?;
            return response_to_bytes(resp).await;
        }
    }

    tracing::debug!("[circuits] network fetch for {url_string}");
    let opts = RequestInit::new();
    opts.set_method("GET");
    opts.set_mode(RequestMode::Cors);

    let request = Request::new_with_str_and_init(&url_string, &opts)
        .map_err(|e| JsError::new(&format!("request failed for {url_string}: {e:?}")))?;

    let global = js_sys::global();
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

    let resp: Response = resp_value
        .dyn_into()
        .map_err(|_| JsError::new("failed to cast response"))?;

    if !resp.ok() {
        return Err(JsError::new(&format!(
            "HTTP {} for {}",
            resp.status(),
            url_string
        )));
    }

    if let Some(cache) = &cache_opt
        && let Ok(resp_clone) = resp.clone()
    {
        let _ = JsFuture::from(cache.put_with_str(&url_string, &resp_clone)).await;
    }

    response_to_bytes(resp).await
}

pub(crate) async fn fetch_circuit_file_verified(
    filename: &str,
    expected_len: usize,
    expected_sha256: [u8; 32],
) -> Result<Vec<u8>, JsError> {
    let bytes = fetch_circuit_file(filename).await?;
    if let Err(err) = ensure_sha256_matches(filename, &bytes, expected_len, expected_sha256) {
        tracing::warn!("[circuits] hash mismatch for {filename}: {err:?}, evicting and refetching");
        let url_string = circuit_fetch_url(filename)?;
        if let Some(cache) = open_cache().await.unwrap_or(None) {
            let _ = JsFuture::from(cache.delete_with_str(&url_string)).await;
        }
        let refetched_bytes = fetch_circuit_file(filename).await?;
        ensure_sha256_matches(filename, &refetched_bytes, expected_len, expected_sha256)?;
        return Ok(refetched_bytes);
    }
    Ok(bytes)
}

/// Split a cached `sha256(payload) || payload` frame, returning the payload
/// only when the stored digest matches a fresh hash of the payload. Returns
/// `None` for a too-short or tampered/truncated frame so the caller re-derives.
fn verify_framed_uncompressed(framed: &[u8]) -> Option<Vec<u8>> {
    if framed.len() < 32 {
        return None;
    }
    let (stored, payload) = framed.split_at(32);
    if sha256(payload).as_slice() == stored {
        Some(payload.to_vec())
    } else {
        None
    }
}

/// Return uncompressed circuit bytes for `filename`, served from the Cache API
/// when present and freshly derived (via `derive`) on a miss.
///
/// This is the warm-cache fast path for proving keys: `derive` runs the
/// expensive fetch + point-decompression only on a miss, and its result is
/// stored so subsequent loads skip it entirely.
///
/// * The cache key binds both `filename` and `compressed_sha256`, so a circuit
///   upgrade (new proving key => new expected hash) yields a fresh key and
///   never serves a stale uncompressed blob from a previous deployment.
/// * Each stored blob is framed as `sha256(payload) || payload`; a read that
///   fails the integrity check is evicted and re-derived (self-heal), matching
///   the compressed path's behaviour.
/// * Entries live in the same `stellar-circuits-v1` cache as the compressed
///   artifacts, distinguished by the `.uncompressed.<hex>` key suffix; the
///   compressed entries are untouched.
/// * Any cache failure (unavailable / open / match / put error) degrades to
///   simply calling `derive` — caching is best-effort and never breaks a load.
///   Only a `derive` error propagates.
///
/// `derive` is async so it can fetch the compressed artifact and build the
/// proving key; it is invoked at most once, only on a miss or corrupt entry.
pub(crate) async fn get_or_derive_uncompressed<F, Fut>(
    filename: &str,
    compressed_sha256: [u8; 32],
    derive: F,
) -> Result<Vec<u8>, JsError>
where
    F: FnOnce() -> Fut,
    Fut: core::future::Future<Output = Result<Vec<u8>, JsError>>,
{
    let key = circuit_fetch_url(&format!(
        "{filename}.uncompressed.{}",
        to_hex(&compressed_sha256)
    ))?;

    let cache_opt = open_cache().await.unwrap_or_else(|e| {
        tracing::warn!("[circuits] failed to open cache for uncompressed {filename}: {e:?}");
        None
    });

    // Try to serve from cache. Any error here is treated as a miss.
    if let Some(cache) = &cache_opt {
        match JsFuture::from(cache.match_with_str(&key)).await {
            Ok(match_val) if !match_val.is_undefined() => match match_val.dyn_into::<Response>() {
                Ok(resp) => match response_to_bytes(resp).await {
                    Ok(framed) => {
                        if let Some(payload) = verify_framed_uncompressed(&framed) {
                            tracing::debug!("[circuits] uncompressed cache hit for {filename}");
                            return Ok(payload);
                        }
                        tracing::warn!(
                            "[circuits] uncompressed cache entry for {filename} failed integrity check, evicting"
                        );
                        let _ = JsFuture::from(cache.delete_with_str(&key)).await;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "[circuits] failed to read uncompressed cache bytes for {filename}: {e:?}"
                        );
                        let _ = JsFuture::from(cache.delete_with_str(&key)).await;
                    }
                },
                Err(_) => {
                    tracing::warn!(
                        "[circuits] uncompressed cache match cast failed for {filename}"
                    );
                }
            },
            Ok(_) => { /* undefined => cache miss */ }
            Err(e) => {
                tracing::warn!("[circuits] uncompressed cache match error for {filename}: {e:?}");
            }
        }
    }

    // Miss or corrupt entry: derive fresh bytes (the expensive path).
    tracing::debug!("[circuits] deriving uncompressed bytes for {filename}");
    let payload = derive().await?;

    // Best-effort store; a storage failure must never break the load.
    if let Some(cache) = &cache_opt {
        let mut framed = Vec::with_capacity(32usize.saturating_add(payload.len()));
        framed.extend_from_slice(&sha256(&payload));
        framed.extend_from_slice(&payload);
        match Response::new_with_opt_u8_array(Some(&mut framed[..])) {
            Ok(resp) => {
                if let Err(e) = JsFuture::from(cache.put_with_str(&key, &resp)).await {
                    tracing::warn!("[circuits] failed to store uncompressed {filename}: {e:?}");
                }
            }
            Err(e) => {
                tracing::warn!(
                    "[circuits] failed to build response for uncompressed {filename}: {e:?}"
                );
            }
        }
    }

    Ok(payload)
}

#[cfg(test)]
mod tests {
    // Tests favour `unwrap()` for brevity; the workspace-wide `unwrap_used` deny
    // is meant for production paths, not assertions.
    #![allow(clippy::unwrap_used)]

    use super::*;
    use std::{cell::Cell, rc::Rc};
    use wasm_bindgen::closure::Closure;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    const TEST_FILE: &str = "test.bin";
    const EXPECTED_LEN: usize = 4;
    const GOOD_BYTES: [u8; 4] = [1, 2, 3, 4];
    // sha256([1, 2, 3, 4]) ==
    // 9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a
    const EXPECTED_SHA256: [u8; 32] = [
        0x9f, 0x64, 0xa7, 0x47, 0xe1, 0xb9, 0x7f, 0x13, 0x1f, 0xab, 0xb6, 0xb4, 0x47, 0x29, 0x6c,
        0x9b, 0x6f, 0x02, 0x01, 0xe7, 0x9f, 0xb3, 0xc5, 0x35, 0x6e, 0x6c, 0x77, 0xe8, 0x9b, 0x6a,
        0x80, 0x6a,
    ];

    /// Point circuit_fetch_url at a fixed, deterministic base (used only as the
    /// cache key here — no server listens on it) and clear the cache so each
    /// test starts from a clean slate.
    async fn setup_test_env() {
        let global = js_sys::global();
        Reflect::set(
            &global,
            &JsValue::from_str(CIRCUITS_BASE_GLOBAL),
            &JsValue::from_str("http://127.0.0.1:8080/"),
        )
        .unwrap();

        if let Some(storage) = get_cache_storage().unwrap() {
            let _ = JsFuture::from(storage.delete(CACHE_NAME)).await;
        }
    }

    /// Replace `window.fetch` with a hermetic shim that never touches the
    /// network: it returns a fresh 200 Response carrying `GOOD_BYTES` and
    /// increments a counter on every call. The returned counter lets tests
    /// assert exactly how many network round-trips happened, so "cache hit
    /// == no refetch" and "self-heal refetches once" become real assertions
    /// rather than hopes.
    fn install_fetch_shim() -> Rc<Cell<u32>> {
        let counter = Rc::new(Cell::new(0u32));
        let counter_for_closure = counter.clone();

        let closure = Closure::wrap(Box::new(move |_req: JsValue| -> js_sys::Promise {
            counter_for_closure.set(counter_for_closure.get().wrapping_add(1));
            let mut body = GOOD_BYTES;
            let resp = web_sys::Response::new_with_opt_u8_array(Some(&mut body)).unwrap();
            let resp_val: JsValue = resp.into();
            js_sys::Promise::resolve(&resp_val)
        }) as Box<dyn FnMut(JsValue) -> js_sys::Promise>);

        let window = web_sys::window().expect("wasm-bindgen-test runs in a window context");
        Reflect::set(
            &window,
            &JsValue::from_str("fetch"),
            closure.as_ref().unchecked_ref(),
        )
        .unwrap();
        // Keep the shim alive for the remainder of the test.
        closure.forget();

        counter
    }

    #[wasm_bindgen_test]
    async fn test_cache_miss_populates_and_hit_does_not_refetch() {
        setup_test_env().await;
        let fetch_count = install_fetch_shim();

        // First fetch: cache miss -> exactly one network round-trip, populates cache.
        let bytes1 = fetch_circuit_file_verified(TEST_FILE, EXPECTED_LEN, EXPECTED_SHA256)
            .await
            .unwrap();
        assert_eq!(bytes1, GOOD_BYTES.to_vec());
        assert_eq!(
            fetch_count.get(),
            1,
            "cache miss should hit network exactly once"
        );

        // The cache entry must now exist under the artifact's resolved URL.
        let cache = open_cache().await.unwrap().unwrap();
        let url = circuit_fetch_url(TEST_FILE).unwrap();
        let match_val = JsFuture::from(cache.match_with_str(&url)).await.unwrap();
        assert!(
            !match_val.is_undefined(),
            "cache should be populated after a miss"
        );

        // Second fetch: cache hit -> the counter must NOT advance.
        let bytes2 = fetch_circuit_file_verified(TEST_FILE, EXPECTED_LEN, EXPECTED_SHA256)
            .await
            .unwrap();
        assert_eq!(bytes2, GOOD_BYTES.to_vec());
        assert_eq!(
            fetch_count.get(),
            1,
            "cache hit must NOT trigger another network fetch"
        );
    }

    #[wasm_bindgen_test]
    fn test_hash_rejects_wrong_len_and_wrong_digest() {
        // Wrong length is rejected.
        assert!(
            ensure_sha256_matches("x", &[1, 2, 3], EXPECTED_LEN, EXPECTED_SHA256).is_err(),
            "wrong length must be rejected"
        );
        // Correct length but wrong digest is rejected.
        assert!(
            ensure_sha256_matches("x", &[9, 9, 9, 9], EXPECTED_LEN, EXPECTED_SHA256).is_err(),
            "wrong digest must be rejected"
        );
        // Correct bytes pass.
        assert!(
            ensure_sha256_matches("x", &GOOD_BYTES, EXPECTED_LEN, EXPECTED_SHA256).is_ok(),
            "matching length and digest must pass"
        );
    }

    #[wasm_bindgen_test]
    async fn test_poisoned_cache_self_heals() {
        setup_test_env().await;
        let fetch_count = install_fetch_shim();

        // Poison the cache with bad bytes under the artifact's resolved URL.
        let cache = open_cache().await.unwrap().unwrap();
        let url = circuit_fetch_url(TEST_FILE).unwrap();
        let bad_resp = web_sys::Response::new_with_opt_str(Some("bad data")).unwrap();
        JsFuture::from(cache.put_with_str(&url, &bad_resp))
            .await
            .unwrap();

        // Verified fetch reads the poisoned entry, fails the hash check, evicts it,
        // and refetches from the (shimmed) network exactly once.
        let bytes = fetch_circuit_file_verified(TEST_FILE, EXPECTED_LEN, EXPECTED_SHA256)
            .await
            .unwrap();
        assert_eq!(
            bytes,
            GOOD_BYTES.to_vec(),
            "self-heal must return good bytes"
        );
        assert_eq!(
            fetch_count.get(),
            1,
            "self-heal should refetch from network exactly once"
        );

        // The healed entry is now cached: a subsequent read is a hit (no new fetch).
        let bytes2 = fetch_circuit_file_verified(TEST_FILE, EXPECTED_LEN, EXPECTED_SHA256)
            .await
            .unwrap();
        assert_eq!(bytes2, GOOD_BYTES.to_vec());
        assert_eq!(
            fetch_count.get(),
            1,
            "healed cache entry should serve subsequent reads without refetch"
        );
    }

    const UNCOMPRESSED_FILE: &str = "uncompressed_test.bin";
    const UNCOMPRESSED_SHA: [u8; 32] = EXPECTED_SHA256;
    const DERIVED_BYTES: [u8; 5] = [10, 20, 30, 40, 50];

    type DeriveFuture = core::future::Ready<Result<Vec<u8>, JsError>>;
    type DeriveClosure = Box<dyn FnOnce() -> DeriveFuture>;

    /// Build a `derive` closure for `get_or_derive_uncompressed` that never
    /// touches the network: it returns `DERIVED_BYTES` and increments a
    /// counter each time it is invoked, so tests can assert exactly how many
    /// times the (expensive) derive path ran.
    fn install_derive_counter() -> (Rc<Cell<u32>>, DeriveClosure) {
        let counter = Rc::new(Cell::new(0u32));
        let counter_for_closure = counter.clone();
        let derive: DeriveClosure = Box::new(move || {
            counter_for_closure.set(counter_for_closure.get().wrapping_add(1));
            core::future::ready(Ok(DERIVED_BYTES.to_vec()))
        });
        (counter, derive)
    }

    #[wasm_bindgen_test]
    async fn test_uncompressed_cache_miss_populates_and_hit_does_not_rederive() {
        setup_test_env().await;

        // First call: cache miss -> derive runs exactly once, populates cache.
        let (derive_count, derive) = install_derive_counter();
        let bytes1 = get_or_derive_uncompressed(UNCOMPRESSED_FILE, UNCOMPRESSED_SHA, derive)
            .await
            .unwrap();
        assert_eq!(bytes1, DERIVED_BYTES.to_vec());
        assert_eq!(
            derive_count.get(),
            1,
            "cache miss should invoke derive exactly once"
        );

        // The cache entry must now exist under the uncompressed key.
        let cache = open_cache().await.unwrap().unwrap();
        let key = circuit_fetch_url(&format!(
            "{UNCOMPRESSED_FILE}.uncompressed.{}",
            to_hex(&UNCOMPRESSED_SHA)
        ))
        .unwrap();
        let match_val = JsFuture::from(cache.match_with_str(&key)).await.unwrap();
        assert!(
            !match_val.is_undefined(),
            "uncompressed cache should be populated after a miss"
        );

        // Second call: cache hit -> derive must NOT run again.
        let (derive_count2, derive2) = install_derive_counter();
        let bytes2 = get_or_derive_uncompressed(UNCOMPRESSED_FILE, UNCOMPRESSED_SHA, derive2)
            .await
            .unwrap();
        assert_eq!(bytes2, DERIVED_BYTES.to_vec());
        assert_eq!(
            derive_count2.get(),
            0,
            "cache hit must NOT invoke derive again"
        );
    }

    #[wasm_bindgen_test]
    async fn test_uncompressed_cache_corrupt_entry_self_heals() {
        setup_test_env().await;

        // Poison the cache with a frame that fails the integrity check (wrong
        // sha256 header for the payload it carries).
        let cache = open_cache().await.unwrap().unwrap();
        let key = circuit_fetch_url(&format!(
            "{UNCOMPRESSED_FILE}.uncompressed.{}",
            to_hex(&UNCOMPRESSED_SHA)
        ))
        .unwrap();
        let mut poisoned = vec![0u8; 32]; // all-zero header does not match any payload
        poisoned.extend_from_slice(&[1, 2, 3]);
        let poisoned_resp =
            web_sys::Response::new_with_opt_u8_array(Some(&mut poisoned[..])).unwrap();
        JsFuture::from(cache.put_with_str(&key, &poisoned_resp))
            .await
            .unwrap();

        // Reading through the corrupt entry: integrity check fails, entry is
        // evicted, and derive runs exactly once to heal it.
        let (derive_count, derive) = install_derive_counter();
        let bytes = get_or_derive_uncompressed(UNCOMPRESSED_FILE, UNCOMPRESSED_SHA, derive)
            .await
            .unwrap();
        assert_eq!(
            bytes,
            DERIVED_BYTES.to_vec(),
            "self-heal must return freshly derived bytes"
        );
        assert_eq!(
            derive_count.get(),
            1,
            "corrupt entry should invoke derive exactly once to self-heal"
        );

        // The healed entry is now cached: a subsequent read is a hit (no re-derive).
        let (derive_count2, derive2) = install_derive_counter();
        let bytes2 = get_or_derive_uncompressed(UNCOMPRESSED_FILE, UNCOMPRESSED_SHA, derive2)
            .await
            .unwrap();
        assert_eq!(bytes2, DERIVED_BYTES.to_vec());
        assert_eq!(
            derive_count2.get(),
            0,
            "healed cache entry should serve subsequent reads without another derive"
        );
    }
}
