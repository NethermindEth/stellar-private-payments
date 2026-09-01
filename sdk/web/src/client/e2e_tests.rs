//! End-to-end browser tests for the web client.
//!
//! These tests run under `wasm-bindgen-test` in a headless browser and drive
//! `Client`/`PrivatePool` with a stub wallet signer. Setup deposits are
//! genuinely signed and submitted so later tests have spendable notes; the flow
//! tests assert the SEP-0043 `code: -4` sentinel at the signing boundary.
//!
//! Worker JS and circuit artifacts are served from `sdk/web/dist` on a separate
//! local origin. Because `wasm-bindgen-test-runner` serves the test page from a
//! fresh temp directory, a plain cross-origin module worker would not start;
//! the tests build a same-origin `blob:` URL for the worker loader instead.
//!
//! Run via `sdk/web/scripts/e2e-browser-test.sh` with `-- --include-ignored`.

// Tests favour `unwrap()` for brevity; the workspace-wide `unwrap_used` deny is
// meant for production paths, not assertions.
#![allow(clippy::unwrap_used)]

use std::{cell::RefCell, rc::Rc};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use js_sys::{Function, Object, Reflect};
use stellar_private_payments::chain::{
    Limits, LocalSigner as ChainLocalSigner, ReadXdr, TransactionEnvelope, WriteXdr,
};
use wasm_bindgen::{JsValue, closure::Closure};
use wasm_bindgen_test::*;

use super::Client;
use crate::storage::Storage;

const TEST_DEPLOYMENT_JSON: &str = include_str!("../../../../deployments/testnet/deployments.json");

fn test_contract_config() -> JsValue {
    let config: stellar_private_payments::types::ContractConfig =
        serde_json::from_str(TEST_DEPLOYMENT_JSON).expect("parse test deployment json");
    serde_wasm_bindgen::to_value(&config).expect("contract config js value")
}

fn test_circuits_base_url() -> String {
    format!("{STATIC_ORIGIN}/circuits/")
}

wasm_bindgen_test_configure!(run_in_browser);

/// Origin of the CORS-enabled static server rooted at `sdk/web/dist`.
///
/// Compiled in from `E2E_STATIC_ORIGIN`; defaults to the documented origin.
const STATIC_ORIGIN: &str = match option_env!("E2E_STATIC_ORIGIN") {
    Some(origin) => origin,
    None => "http://127.0.0.1:8099",
};

/// Testnet RPC endpoint.
const RPC_URL: &str = match option_env!("E2E_RPC_URL") {
    Some(url) => url,
    None => "https://soroban-testnet.stellar.org",
};

/// Optional archive RPC used when the public RPC no longer retains deployment
/// history. This is test-only configuration; production callers choose their
/// bootnode explicitly.
const BOOTNODE_URL: Option<&str> = option_env!("E2E_BOOTNODE_URL");

/// Native XLM pool. `policyFlags: ["blocklist"]`, so no ASP membership leaf is
/// required.
const POOL_CONTRACT: &str = match option_env!("E2E_POOL_CONTRACT") {
    Some(id) => id,
    None => "CCPNFGD7A6LJ7H4FGFLTBSU6XGCPFR5DN76N5WNXOTDPOKASJIU4EMFV",
};

const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

/// Amount seeded per setup deposit, in stroops (0.1 XLM).
const SEED_DEPOSIT_STROOPS: u128 = 1_000_000;

/// Address of test account A.
const ACCOUNT_A_ADDRESS: Option<&str> = option_env!("E2E_ACCOUNT_A_ADDRESS");

/// Address of test account B, the transfer recipient.
const ACCOUNT_B_ADDRESS: Option<&str> = option_env!("E2E_ACCOUNT_B_ADDRESS");

/// Amount moved by the transfer/withdraw flow tests, in stroops.
const FLOW_AMOUNT_STROOPS: u128 = 500_000;

/// Secret for test account A, used only to sign setup transactions.
///
/// These are disposable testnet accounts; never point this at an account that
/// matters.
const ACCOUNT_A_SECRET: Option<&str> = option_env!("E2E_ACCOUNT_A_SECRET");

/// Fixed 64-byte signature blob the stub signer returns from `signMessage`.
///
/// Key derivation SHA-256s these bytes with a domain tag and never verifies
/// them as a real Ed25519 signature, but the length must be exactly 64. Base64,
/// not hex: `wallet_message_signature_to_bytes` tries base64 first, and 128 hex
/// chars are themselves valid base64, decoding to 96 bytes.
const STUB_SIGNATURE_B64: &str =
    "paWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpQ==";

/// Build a same-origin `blob:` URL for a worker loader served at
/// `{STATIC_ORIGIN}/workers/{file}`.
async fn blob_worker_url(file: &str) -> String {
    // Use XMLHttpRequest, not fetch, because this crate's circuits tests
    // replace `window.fetch` with a shim and never restore it.
    let js = format!(
        r#"(async function () {{
             const base = '{STATIC_ORIGIN}/workers';
             const url = base + '/{file}';
             let src = await new Promise(function (resolve, reject) {{
               const xhr = new XMLHttpRequest();
               xhr.open('GET', url, true);
               xhr.onload = function () {{
                 if (xhr.status >= 200 && xhr.status < 300) resolve(xhr.responseText);
                 else reject(new Error('GET ' + url + ': ' + xhr.status));
               }};
               xhr.onerror = function () {{ reject(new Error('network error for ' + url)); }};
               xhr.send();
             }});
             src = src.replace(/from '\.\/([^']+)'/g, "from '" + base + "/$1'");
             src = src.replace(
               /new URL\('\.\.\/circuits\/', import\.meta\.url\)\.href/g,
               "'{STATIC_ORIGIN}/circuits/'"
             );
             const blob = new Blob([src], {{ type: 'application/javascript' }});
             return URL.createObjectURL(blob);
           }})()"#
    );
    let promise = js_sys::Promise::from(js_sys::eval(&js).unwrap());
    wasm_bindgen_futures::JsFuture::from(promise)
        .await
        .unwrap()
        .as_string()
        .unwrap()
}

// The one `Storage` for this page. See `open_test_storage`.
thread_local! {
    static SHARED_STORAGE: RefCell<Option<Storage>> = const { RefCell::new(None) };
}

/// Open `Storage` against a blob-wrapped storage worker.
///
/// `Storage::open` must be called once per page session because OPFS holds the
/// SQLite file with an exclusive sync access handle. Open lazily and hand out
/// `fork()` handles to the same worker.
async fn open_test_storage() -> Storage {
    if let Some(handle) = SHARED_STORAGE.with(|cell| cell.borrow().as_ref().map(Storage::fork)) {
        return handle;
    }

    let worker_url = blob_worker_url("storage-worker.js").await;
    let options = Object::new();
    Reflect::set(
        &options,
        &JsValue::from_str("workerUrl"),
        &JsValue::from_str(&worker_url),
    )
    .unwrap();
    let storage = Storage::open(options.into())
        .await
        .expect("storage worker must start and answer its ping");

    // Borrow only after the await, never across it.
    let handle = storage.fork();
    SHARED_STORAGE.with(|cell| *cell.borrow_mut() = Some(storage));
    handle
}

/// Build a `Client` with a blob-wrapped prover worker.
async fn build_test_client(storage: &Storage) -> Client {
    let prover_url = blob_worker_url("prover-worker.js").await;
    Client::new(
        RPC_URL.to_string(),
        storage,
        prover_url,
        test_contract_config(),
        test_circuits_base_url(),
        BOOTNODE_URL.map(str::to_owned),
    )
    .await
    .expect("client construction must succeed")
}

/// Stub wallet signer that halts flows at the signing boundary.
///
/// `signMessage` succeeds so key derivation can complete. `signTransaction` and
/// `signAuthEntry` both reject with SEP-0043 `code: -4`, which maps to
/// `Error::UserRejected` and surfaces to JS as `{status:"failed", code:-4}`.
fn stub_signer() -> JsValue {
    signer_with_mode(SignerMode::Sentinel)
}

/// Which way a test signer answers signing requests.
#[derive(Clone, Copy)]
enum SignerMode {
    /// Reject with the SEP-0043 `code: -4` sentinel.
    Sentinel,
    /// Produce real Ed25519 signatures for setup transactions.
    Signing,
}

/// `signMessage` return, shared by both modes.
fn sign_message_fn() -> Function {
    Function::new_with_args(
        "message, opts",
        &format!("return Promise.resolve('{STUB_SIGNATURE_B64}');"),
    )
}

/// Build a test signer object with all three methods `WalletSigner` requires.
fn signer_with_mode(mode: SignerMode) -> JsValue {
    let signer = Object::new();
    Reflect::set(
        &signer,
        &JsValue::from_str("signMessage"),
        &sign_message_fn(),
    )
    .unwrap();

    match mode {
        SignerMode::Sentinel => {
            let reject_with_sentinel = || {
                Function::new_with_args(
                    "payload, opts",
                    "var e = new Error('e2e stub signer: halted at the signing boundary');\
                     e.code = -4;\
                     return Promise.reject(e);",
                )
            };
            Reflect::set(
                &signer,
                &JsValue::from_str("signTransaction"),
                &reject_with_sentinel(),
            )
            .unwrap();
            Reflect::set(
                &signer,
                &JsValue::from_str("signAuthEntry"),
                &reject_with_sentinel(),
            )
            .unwrap();
        }
        SignerMode::Signing => install_real_signing(&signer),
    }

    signer.into()
}

/// Install real `signTransaction` / `signAuthEntry` methods via `LocalSigner`.
fn install_real_signing(signer: &Object) {
    let secret = ACCOUNT_A_SECRET.expect(
        "E2E_ACCOUNT_A_SECRET not compiled in: run via \
         `set -a; . deployments/testnet/.e2e-accounts.env; set +a`",
    );
    let local = Rc::new(
        ChainLocalSigner::from_secret(secret).expect("E2E_ACCOUNT_A_SECRET must be a valid S… key"),
    );

    // signTransaction(txXdrBase64, opts) -> Promise<signedTxXdrBase64>
    let tx_signer = local.clone();
    let sign_tx = Closure::wrap(Box::new(move |tx_b64: JsValue, _opts: JsValue| {
        let b64 = tx_b64.as_string().expect("signTransaction takes a string");
        let envelope = TransactionEnvelope::from_xdr_base64(&b64, Limits::none())
            .expect("unsigned envelope must be valid xdr");
        let signed = tx_signer
            .sign_transaction(envelope, TESTNET_PASSPHRASE)
            .expect("signing the envelope must succeed");
        let out = signed
            .to_xdr_base64(Limits::none())
            .expect("signed envelope must encode");
        js_sys::Promise::resolve(&JsValue::from_str(&out))
    })
        as Box<dyn FnMut(JsValue, JsValue) -> js_sys::Promise>);

    // signAuthEntry(preimageBase64, opts) -> Promise<signatureBase64>
    let entry_signer = local.clone();
    let sign_entry = Closure::wrap(Box::new(move |preimage_b64: JsValue, _opts: JsValue| {
        let b64 = preimage_b64
            .as_string()
            .expect("signAuthEntry takes a string");
        let bytes = STANDARD
            .decode(b64.trim())
            .expect("auth preimage must be base64");
        let signature = entry_signer.sign(&bytes);
        js_sys::Promise::resolve(&JsValue::from_str(&STANDARD.encode(signature.as_bytes())))
    })
        as Box<dyn FnMut(JsValue, JsValue) -> js_sys::Promise>);

    // `into_js_value` intentionally leaks: the signer must stay callable for
    // the rest of the test.
    Reflect::set(
        signer,
        &JsValue::from_str("signTransaction"),
        &sign_tx.into_js_value(),
    )
    .unwrap();
    Reflect::set(
        signer,
        &JsValue::from_str("signAuthEntry"),
        &sign_entry.into_js_value(),
    )
    .unwrap();
}

/// Both workers must start and answer, and `Client` must construct.
#[wasm_bindgen_test]
#[ignore = "needs testnet accounts and CORS server; run via e2e-browser-test.sh with -- --include-ignored"]
async fn e2e_smoke_client_construction() {
    let storage = open_test_storage().await;

    let mut client = build_test_client(&storage).await;

    client
        .contract_config()
        .expect("deployment config must parse");
    assert!(!stub_signer().is_undefined());

    client.stop_background_sync();
}

/// Open an `Account` session for test account A using the sentinel signer.
async fn open_account_a(client: &Client) -> super::Account {
    open_account_a_with(client, SignerMode::Sentinel).await
}

/// Open an `Account` session for test account A with an explicit signer mode.
async fn open_account_a_with(client: &Client, mode: SignerMode) -> super::Account {
    let address = ACCOUNT_A_ADDRESS.expect(
        "E2E_ACCOUNT_A_ADDRESS not compiled in: run via \
         `set -a; . deployments/testnet/.e2e-accounts.env; set +a`",
    );

    let options = Object::new();
    Reflect::set(
        &options,
        &JsValue::from_str("networkPassphrase"),
        &JsValue::from_str(TESTNET_PASSPHRASE),
    )
    .unwrap();
    Reflect::set(
        &options,
        &JsValue::from_str("userAddress"),
        &JsValue::from_str(address),
    )
    .unwrap();

    client
        .account(options.into(), signer_with_mode(mode))
        .await
        .expect("account session must open")
}

/// Read the `status` field of an `execute_plan` response.
fn response_status(response: &JsValue) -> String {
    Reflect::get(response, &JsValue::from_str("status"))
        .unwrap()
        .as_string()
        .unwrap_or_default()
}

/// Number of confirmed transaction hashes in an `execute_plan` response.
fn response_hash_count(response: &JsValue) -> u32 {
    Reflect::get(response, &JsValue::from_str("hashes"))
        .ok()
        .and_then(|hashes| js_sys::Array::try_from(hashes).ok().map(|a| a.length()))
        .unwrap_or(0)
}

/// SEP-0043 error code from an `execute_plan` response, when present.
///
/// `-4` is the sentinel for a user rejection.
fn response_code(response: &JsValue) -> Option<f64> {
    Reflect::get(response, &JsValue::from_str("code"))
        .ok()
        .and_then(|code| code.as_f64())
}

/// DOM event carrying transaction progress.
const TX_PROGRESS_EVENT: &str = "stellar-private-payments:tx-progress";

/// Start recording `stage` values from progress events.
fn start_progress_capture() {
    js_sys::eval(&format!(
        r#"(function () {{
             globalThis.__e2eStages = [];
             globalThis.__e2eProgressListener = function (ev) {{
               if (ev && ev.detail && ev.detail.stage) {{
                 globalThis.__e2eStages.push(ev.detail.stage);
               }}
             }};
             window.addEventListener('{TX_PROGRESS_EVENT}', globalThis.__e2eProgressListener);
           }})()"#
    ))
    .expect("installing the progress listener must succeed");
}

/// Stop recording and return the stages seen, in order.
fn captured_stages() -> Vec<String> {
    let joined = js_sys::eval(&format!(
        r#"(function () {{
             window.removeEventListener('{TX_PROGRESS_EVENT}', globalThis.__e2eProgressListener);
             return (globalThis.__e2eStages || []).join(',');
           }})()"#
    ))
    .expect("reading captured stages must succeed")
    .as_string()
    .unwrap_or_default();

    if joined.is_empty() {
        return Vec::new();
    }
    joined.split(',').map(str::to_string).collect()
}

/// Run a deposit to completion so later tests start from real on-chain notes.
///
/// Uses `SignerMode::Signing` because this is setup, not a flow under test.
async fn seed_deposit(client: &Client, amount: u128) {
    let account = open_account_a_with(client, SignerMode::Signing).await;
    let pool = open_pool(&account).await;

    let response = pool
        .deposit(amount)
        .await
        .expect("seed deposit must not error at the JS boundary");
    let status = response_status(&response);

    assert_eq!(
        status,
        "ok",
        "seed deposit must confirm on chain, got status={status} message={:?}",
        Reflect::get(&response, &JsValue::from_str("message"))
            .ok()
            .and_then(|m| m.as_string())
    );
    console_log!(
        "seeded deposit of {amount} stroops in {} transaction(s)",
        response_hash_count(&response)
    );
}

/// A real signed+submitted deposit must leave spendable notes behind.
#[wasm_bindgen_test]
#[ignore = "needs testnet accounts and CORS server; run via e2e-browser-test.sh with -- --include-ignored"]
async fn e2e_seed_deposit_creates_spendable_notes() {
    let storage = open_test_storage().await;
    let mut client = build_test_client(&storage).await;

    client.sync().await.expect("initial sync must succeed");

    let account = open_account_a_with(&client, SignerMode::Signing).await;
    let pool = open_pool(&account).await;
    let balance_before = pool.balance().await.expect("balance read before");

    seed_deposit(&client, SEED_DEPOSIT_STROOPS).await;

    client
        .sync()
        .await
        .expect("sync after deposit must succeed");

    let balance_after = pool.balance().await.expect("balance read after");
    console_log!("pool balance {balance_before} -> {balance_after} stroops");

    assert_eq!(
        balance_after,
        balance_before.saturating_add(SEED_DEPOSIT_STROOPS),
        "balance must grow by the deposited amount"
    );

    client.stop_background_sync();
}

/// Assert a response is the signing-boundary sentinel.
///
/// Checks status=failed, code=-4, no submitted hashes, and that the `sign`
/// stage was reached.
fn assert_halted_at_signing(flow: &str, response: &JsValue, stages: &[String]) {
    let status = response_status(response);
    let message = Reflect::get(response, &JsValue::from_str("message"))
        .ok()
        .and_then(|m| m.as_string())
        .unwrap_or_default();

    assert_eq!(
        status, "failed",
        "{flow}: expected status=failed, got {status} (message: {message}; stages: {stages:?})"
    );
    assert_eq!(
        response_code(response),
        Some(-4.0),
        "{flow}: expected the SEP-0043 code -4 sentinel (message: {message}; stages: {stages:?})"
    );
    assert_eq!(
        response_hash_count(response),
        0,
        "{flow}: nothing may be submitted when halting at the signing boundary"
    );
    assert!(
        stages.iter().any(|stage| stage == "sign"),
        "{flow}: must have reached the 'sign' stage (stages: {stages:?})"
    );
}

/// Deposit must reach prove → simulate and then halt at signing.
#[wasm_bindgen_test]
#[ignore = "needs testnet accounts and CORS server; run via e2e-browser-test.sh with -- --include-ignored"]
async fn e2e_deposit_halts_at_signing() {
    let storage = open_test_storage().await;
    let mut client = build_test_client(&storage).await;
    client.sync().await.expect("sync must succeed");

    let account = open_account_a(&client).await;
    let pool = open_pool(&account).await;

    let balance_before = pool.balance().await.expect("balance read before");

    start_progress_capture();
    let response = pool
        .deposit(SEED_DEPOSIT_STROOPS)
        .await
        .expect("deposit must resolve at the JS boundary, not throw");
    let stages = captured_stages();
    console_log!("deposit stages: {stages:?}");

    assert_halted_at_signing("deposit", &response, &stages);

    // A halted flow must not have moved any funds.
    let balance_after = pool.balance().await.expect("balance read after");
    assert_eq!(
        balance_after, balance_before,
        "a flow halted at signing must not change the pool balance"
    );

    client.stop_background_sync();
}

/// Transfer must spend seeded notes through prove → simulate, then halt at
/// signing.
#[wasm_bindgen_test]
#[ignore = "needs testnet accounts and CORS server; run via e2e-browser-test.sh with -- --include-ignored"]
async fn e2e_transfer_halts_at_signing() {
    let recipient = ACCOUNT_B_ADDRESS.expect(
        "E2E_ACCOUNT_B_ADDRESS not compiled in: run via \
         `set -a; . deployments/testnet/.e2e-accounts.env; set +a`",
    );

    let storage = open_test_storage().await;
    let mut client = build_test_client(&storage).await;
    client.sync().await.expect("initial sync must succeed");

    // Give account A something to spend.
    seed_deposit(&client, SEED_DEPOSIT_STROOPS).await;
    client
        .sync()
        .await
        .expect("sync after seeding must succeed");

    let account = open_account_a(&client).await;
    let pool = open_pool(&account).await;
    let balance_before = pool.balance().await.expect("balance read before");
    assert!(
        balance_before >= FLOW_AMOUNT_STROOPS,
        "seeding must leave at least {FLOW_AMOUNT_STROOPS} stroops spendable, have {balance_before}"
    );

    start_progress_capture();
    let response = pool
        .transfer(recipient, FLOW_AMOUNT_STROOPS)
        .await
        .expect("transfer must resolve at the JS boundary, not throw");
    let stages = captured_stages();
    console_log!("transfer stages: {stages:?}");

    assert_halted_at_signing("transfer", &response, &stages);

    let balance_after = pool.balance().await.expect("balance read after");
    assert_eq!(
        balance_after, balance_before,
        "a transfer halted at signing must not move funds"
    );

    client.stop_background_sync();
}

/// Withdraw must spend seeded notes through prove → simulate, then halt at
/// signing.
#[wasm_bindgen_test]
#[ignore = "needs testnet accounts and CORS server; run via e2e-browser-test.sh with -- --include-ignored"]
async fn e2e_withdraw_halts_at_signing() {
    let storage = open_test_storage().await;
    let mut client = build_test_client(&storage).await;
    client.sync().await.expect("initial sync must succeed");

    seed_deposit(&client, SEED_DEPOSIT_STROOPS).await;
    client
        .sync()
        .await
        .expect("sync after seeding must succeed");

    let account = open_account_a(&client).await;
    let pool = open_pool(&account).await;
    let balance_before = pool.balance().await.expect("balance read before");
    assert!(
        balance_before >= FLOW_AMOUNT_STROOPS,
        "seeding must leave at least {FLOW_AMOUNT_STROOPS} stroops spendable, have {balance_before}"
    );

    start_progress_capture();
    let response = pool
        .withdraw(FLOW_AMOUNT_STROOPS, None)
        .await
        .expect("withdraw must resolve at the JS boundary, not throw");
    let stages = captured_stages();
    console_log!("withdraw stages: {stages:?}");

    assert_halted_at_signing("withdraw", &response, &stages);

    let balance_after = pool.balance().await.expect("balance read after");
    assert_eq!(
        balance_after, balance_before,
        "a withdraw halted at signing must not move funds"
    );

    client.stop_background_sync();
}

/// Open the target pool session for an account.
async fn open_pool(account: &super::Account) -> super::PrivatePool {
    let options = Object::new();
    Reflect::set(
        &options,
        &JsValue::from_str("poolContract"),
        &JsValue::from_str(POOL_CONTRACT),
    )
    .unwrap();
    account
        .pool(options.into())
        .await
        .expect("pool session must open")
}

/// A full session against testnet: key derivation from the stub blob, sync, and
/// a pool state read.
#[wasm_bindgen_test]
#[ignore = "needs testnet accounts and CORS server; run via e2e-browser-test.sh with -- --include-ignored"]
async fn e2e_session_account_setup_and_sync() {
    let storage = open_test_storage().await;
    let mut client = build_test_client(&storage).await;

    let account = open_account_a(&client).await;
    assert_eq!(
        account.user_address(),
        ACCOUNT_A_ADDRESS.unwrap(),
        "session must bind to the configured test account"
    );

    // Catch local storage up to the chain tip so state reads are meaningful.
    client.sync().await.expect("sync to chain tip must succeed");

    let pool = open_pool(&account).await;
    let balance = pool
        .balance()
        .await
        .expect("pool balance read must succeed");
    let notes = pool.notes().await.expect("pool notes read must succeed");
    console_log!(
        "account {} pool balance: {balance} stroops, notes present: {}",
        account.user_address(),
        !notes.is_undefined()
    );

    client.stop_background_sync();
}
