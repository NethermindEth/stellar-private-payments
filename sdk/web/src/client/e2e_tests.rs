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
use ed25519_dalek::SigningKey;
use js_sys::{Function, Object, Reflect};
use rand::rngs::OsRng;
use stellar_private_payments::{
    chain::{Limits, LocalSigner as ChainLocalSigner, ReadXdr, TransactionEnvelope, WriteXdr},
    zk::encryption::sep53_payload,
};
use stellar_strkey::ed25519 as strkey_ed25519;
use wasm_bindgen::{JsValue, closure::Closure};
use wasm_bindgen_test::*;

use super::Client;
use crate::{models::PoolExecuteResult, storage::Storage};

// Only local `stellar/quickstart` is supported
// (deployments/scripts/localnet.sh, started by e2e-browser-test.sh) — accounts
// are ephemeral, so testnet bought no extra coverage, only friendbot limits and
// an extra CLI dependency.
const TEST_DEPLOYMENT_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../deployments/local/deployments.json"
));

fn test_contract_config_native() -> stellar_private_payments::types::ContractConfig {
    serde_json::from_str(TEST_DEPLOYMENT_JSON).expect("parse test deployment json")
}

fn test_contract_config() -> JsValue {
    serde_wasm_bindgen::to_value(&test_contract_config_native()).expect("contract config js value")
}

/// The deployment's native XLM pool (`policyFlags: ["blocklist"]`, no ASP
/// membership needed), resolved from `TEST_DEPLOYMENT_JSON` itself.
fn test_pool_contract() -> String {
    test_contract_config_native()
        .pools
        .into_iter()
        .find(|pool| {
            pool.enabled
                && matches!(
                    pool.asset,
                    stellar_private_payments::types::AssetDescriptor::Native
                )
        })
        .expect("no enabled native pool in deployments/local/deployments.json")
        .pool_contract_id
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

/// RPC endpoint of the local `stellar/quickstart` network.
const RPC_URL: &str = "http://localhost:8000/rpc";

/// Friendbot endpoint of the local `stellar/quickstart` network, used to fund
/// ephemeral test accounts.
const FRIENDBOT_URL: &str = "http://localhost:8000/friendbot";

/// Passphrase of the local `stellar/quickstart` standalone network.
const NETWORK_PASSPHRASE: &str = "Standalone Network ; February 2017";

/// Amount seeded per setup deposit, in stroops (0.1 XLM).
const SEED_DEPOSIT_STROOPS: u128 = 1_000_000;

/// An ephemeral Stellar keypair, generated fresh for one test and never
/// persisted — no CLI, no shared env file, no long-lived on-chain identity.
#[derive(Clone)]
struct TestAccount {
    label: &'static str,
    address: String,
    secret: String,
}

fn generate_account(label: &'static str) -> TestAccount {
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut OsRng, &mut seed);
    let signing_key = SigningKey::from_bytes(&seed);

    let address = strkey_ed25519::PublicKey(signing_key.verifying_key().to_bytes())
        .to_string()
        .to_string();
    let secret = strkey_ed25519::PrivateKey(seed)
        .as_unredacted()
        .to_string()
        .to_string();

    TestAccount {
        label,
        address,
        secret,
    }
}

/// Fund `address` via the network's friendbot. XMLHttpRequest, not fetch,
/// since this crate's circuits tests replace `window.fetch` with a shim and
/// never restore it. `eval` only interpolates compile-time/self-generated
/// values, never untrusted input.
async fn fund_account(address: &str) {
    let js = format!(
        r#"new Promise(function (resolve, reject) {{
             const xhr = new XMLHttpRequest();
             xhr.open('GET', '{FRIENDBOT_URL}?addr={address}', true);
             xhr.onload = function () {{
               if (xhr.status >= 200 && xhr.status < 300) resolve(xhr.responseText);
               else reject(new Error('friendbot ' + xhr.status + ': ' + xhr.responseText));
             }};
             xhr.onerror = function () {{ reject(new Error('friendbot: network error')); }};
             xhr.send();
           }})"#
    );
    let promise = js_sys::Promise::from(js_sys::eval(&js).unwrap());
    wasm_bindgen_futures::JsFuture::from(promise)
        .await
        .unwrap_or_else(|e| panic!("friendbot funding failed for {address}: {e:?}"));
}

/// Poll Horizon until `address` is visible on-chain. Friendbot's response
/// only confirms submission — RPC's own ledger ingestion can lag behind it
/// right after a fresh network starts, so a deposit simulated immediately
/// after funding can hit an account RPC doesn't know about yet.
async fn wait_for_account_visible(address: &str) {
    let js = format!(
        r#"(async function () {{
             for (let attempt = 0; attempt < 30; attempt++) {{
               const ok = await new Promise(function (resolve) {{
                 const xhr = new XMLHttpRequest();
                 xhr.open('GET', 'http://localhost:8000/accounts/{address}', true);
                 xhr.onload = function () {{ resolve(xhr.status === 200); }};
                 xhr.onerror = function () {{ resolve(false); }};
                 xhr.send();
               }});
               if (ok) return;
               await new Promise((resolve) => setTimeout(resolve, 500));
             }}
             throw new Error('account {address} never became visible on Horizon');
           }})()"#
    );
    let promise = js_sys::Promise::from(js_sys::eval(&js).unwrap());
    wasm_bindgen_futures::JsFuture::from(promise)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
}

/// Generate, fund, and return a fresh ephemeral test account.
async fn create_funded_account(label: &'static str) -> TestAccount {
    let account = generate_account(label);
    fund_account(&account.address).await;
    wait_for_account_visible(&account.address).await;
    account
}

/// Register `account`'s public keys so it can be resolved as a transfer
/// recipient — a passive on-chain lookup, the same call the app itself
/// makes. Only needed for accounts used as a transfer target.
async fn register_account(client: &Client, account: &TestAccount) {
    let session = open_account_with(client, account, SignerMode::Signing(account.clone())).await;
    session
        .register_public_keys()
        .await
        .expect("register_public_keys must succeed");
}

/// Amount moved by the transfer/withdraw flow tests, in stroops.
const FLOW_AMOUNT_STROOPS: u128 = 500_000;

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
        None,
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
    signer_with_mode(&generate_account("smoke"), SignerMode::Sentinel)
}

/// Which way a test signer answers signing requests.
#[derive(Clone)]
enum SignerMode {
    /// Reject with the SEP-0043 `code: -4` sentinel.
    Sentinel,
    /// Produce real Ed25519 signatures for setup transactions, as the given
    /// account.
    Signing(TestAccount),
}

/// `signMessage`, shared by both modes: a real SEP-53 signature by `account`.
///
/// Key derivation checks the signature against the account's own key, so a
/// stand-in blob would be refused.
fn sign_message_fn(account: &TestAccount) -> JsValue {
    let signer = test_account_signer(account);
    Closure::wrap(Box::new(move |message: JsValue, _opts: JsValue| {
        let message = message.as_string().expect("signMessage takes a string");
        let signature = signer.sign(&sep53_payload(&message));
        js_sys::Promise::resolve(&JsValue::from_str(&STANDARD.encode(signature.as_bytes())))
    })
        as Box<dyn FnMut(JsValue, JsValue) -> js_sys::Promise>)
    .into_js_value()
}

/// The test account's in-process signer, from its generated secret.
fn test_account_signer(account: &TestAccount) -> ChainLocalSigner {
    ChainLocalSigner::from_secret(&account.secret).unwrap_or_else(|_| {
        panic!(
            "generated secret for account '{}' must be valid",
            account.label
        )
    })
}

/// Build a test signer object with all three methods `WalletSigner` requires.
fn signer_with_mode(account: &TestAccount, mode: SignerMode) -> JsValue {
    let signer = Object::new();
    Reflect::set(
        &signer,
        &JsValue::from_str("signMessage"),
        &sign_message_fn(account),
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
        SignerMode::Signing(ref signing_account) => install_real_signing(&signer, signing_account),
    }

    signer.into()
}

/// Install real `signTransaction` / `signAuthEntry` methods via `LocalSigner`.
fn install_real_signing(signer: &Object, account: &TestAccount) {
    let local = Rc::new(test_account_signer(account));

    // signTransaction(txXdrBase64, opts) -> Promise<signedTxXdrBase64>
    let tx_signer = local.clone();
    let sign_tx = Closure::wrap(Box::new(move |tx_b64: JsValue, _opts: JsValue| {
        let b64 = tx_b64.as_string().expect("signTransaction takes a string");
        let envelope = TransactionEnvelope::from_xdr_base64(&b64, Limits::none())
            .expect("unsigned envelope must be valid xdr");
        let signed = tx_signer
            .sign_transaction(envelope, NETWORK_PASSPHRASE)
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
#[ignore = "needs localnet and CORS server; run via e2e-browser-test.sh with -- --include-ignored"]
async fn e2e_smoke_client_construction() {
    let storage = open_test_storage().await;

    let mut client = build_test_client(&storage).await;

    client.contract_config();
    assert!(!stub_signer().is_undefined());

    client.stop_background_sync();
}

/// Open an `Account` session using the sentinel signer.
async fn open_account(client: &Client, account: &TestAccount) -> super::Account {
    open_account_with(client, account, SignerMode::Sentinel).await
}

/// Open an `Account` session for a test account with an explicit signer mode,
/// deriving and persisting its privacy keys.
async fn open_account_with(
    client: &Client,
    account: &TestAccount,
    mode: SignerMode,
) -> super::Account {
    let session = client
        .account(account_options(account), signer_with_mode(account, mode))
        .await
        .expect("account session must open");
    session
        .derive_privacy_keys()
        .await
        .expect("privacy keys must derive (stub signer answers signMessage)");
    session
}

/// `Client::account` options naming `account` as the note owner.
fn account_options(account: &TestAccount) -> JsValue {
    let options = Object::new();
    Reflect::set(
        &options,
        &JsValue::from_str("networkPassphrase"),
        &JsValue::from_str(NETWORK_PASSPHRASE),
    )
    .unwrap();
    Reflect::set(
        &options,
        &JsValue::from_str("userAddress"),
        &JsValue::from_str(&account.address),
    )
    .unwrap();
    options.into()
}

/// A wallet that signs the key-derivation message with another account must
/// not derive or leave keys behind under the owner. Opening the session
/// itself always succeeds now — derivation is a separate, explicit call.
#[wasm_bindgen_test]
#[ignore = "needs localnet and CORS server; run via e2e-browser-test.sh with -- --include-ignored"]
async fn e2e_foreign_derivation_signature_is_refused() {
    let storage = open_test_storage().await;
    let mut client = build_test_client(&storage).await;

    let (owner, impostor) = futures::join!(
        create_funded_account("foreign-derivation-owner"),
        create_funded_account("foreign-derivation-impostor"),
    );

    // Twice: had the first refusal stored keys, the second call would find
    // them, skip derivation, and succeed.
    for attempt in ["first", "second"] {
        let signer = signer_with_mode(&owner, SignerMode::Sentinel);
        Reflect::set(
            &signer,
            &JsValue::from_str("signMessage"),
            &sign_message_fn(&impostor),
        )
        .unwrap();

        let session = client
            .account(account_options(&owner), signer)
            .await
            .expect("opening the session does not itself derive keys");

        let error = match session.derive_privacy_keys().await {
            Ok(_) => panic!("{attempt} derivation accepted the impostor's signature for the owner"),
            Err(error) => JsValue::from(error),
        };
        let message = Reflect::get(&error, &JsValue::from_str("message"))
            .unwrap()
            .as_string()
            .unwrap_or_default();
        assert!(
            message.contains("not made by the note owner"),
            "{attempt} derivation refused for another reason: {message}"
        );
    }

    client.stop_background_sync();
}

/// Read the `status` field of a pool execute response.
fn response_status(response: &PoolExecuteResult) -> String {
    response.status()
}

/// Number of confirmed transaction hashes in a pool execute response.
fn response_hash_count(response: &PoolExecuteResult) -> u32 {
    response.hashes().len() as u32
}

/// SEP-0043 error code from a pool execute response, when present.
///
/// `-4` is the sentinel for a user rejection.
fn response_code(response: &PoolExecuteResult) -> Option<i32> {
    response.code()
}

/// DOM event carrying transaction progress.
const TX_PROGRESS_EVENT: &str = "stellar-private-payments:tx-progress";

/// Start recording `stage` values from progress events under a test-local key.
fn start_progress_capture(capture_id: &str) {
    js_sys::eval(&format!(
        r#"(function () {{
             globalThis.__e2eStages = globalThis.__e2eStages || {{}};
             globalThis.__e2eProgressListeners = globalThis.__e2eProgressListeners || {{}};
             globalThis.__e2eStages['{capture_id}'] = [];
             globalThis.__e2eProgressListeners['{capture_id}'] = function (ev) {{
               if (ev && ev.detail && ev.detail.flow === '{capture_id}' && ev.detail.stage) {{
                 globalThis.__e2eStages['{capture_id}'].push(ev.detail.stage);
               }}
             }};
             window.addEventListener('{TX_PROGRESS_EVENT}', globalThis.__e2eProgressListeners['{capture_id}']);
           }})()"#
    ))
    .expect("installing the progress listener must succeed");
}

/// Stop recording and return the stages seen, in order.
fn captured_stages(capture_id: &str) -> Vec<String> {
    let joined = js_sys::eval(&format!(
        r#"(function () {{
             const listener = (globalThis.__e2eProgressListeners || {{}})['{capture_id}'];
             if (listener) window.removeEventListener('{TX_PROGRESS_EVENT}', listener);
             return ((globalThis.__e2eStages || {{}})['{capture_id}'] || []).join(',');
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
async fn seed_deposit(client: &Client, test_account: &TestAccount, amount: u128) {
    let account = open_account_with(
        client,
        test_account,
        SignerMode::Signing(test_account.clone()),
    )
    .await;
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
        response.message()
    );
    console_log!(
        "seeded deposit of {amount} stroops in {} transaction(s)",
        response_hash_count(&response)
    );
}

/// A real signed+submitted deposit must leave spendable notes behind.
#[wasm_bindgen_test]
#[ignore = "needs localnet and CORS server; run via e2e-browser-test.sh with -- --include-ignored"]
async fn e2e_seed_deposit_creates_spendable_notes() {
    let storage = open_test_storage().await;
    let mut client = build_test_client(&storage).await;

    client.sync().await.expect("initial sync must succeed");

    let test_account = create_funded_account("seed-deposit").await;
    let account = open_account_with(
        &client,
        &test_account,
        SignerMode::Signing(test_account.clone()),
    )
    .await;
    let pool = open_pool(&account).await;
    let balance_before = pool.balance().await.expect("balance read before");

    seed_deposit(&client, &test_account, SEED_DEPOSIT_STROOPS).await;

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
fn assert_halted_at_signing(flow: &str, response: &PoolExecuteResult, stages: &[String]) {
    let status = response_status(response);
    let message = response.message().unwrap_or_default();

    assert_eq!(
        status, "failed",
        "{flow}: expected status=failed, got {status} (message: {message}; stages: {stages:?})"
    );
    assert_eq!(
        response_code(response),
        Some(-4),
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
#[ignore = "needs localnet and CORS server; run via e2e-browser-test.sh with -- --include-ignored"]
async fn e2e_deposit_halts_at_signing() {
    let storage = open_test_storage().await;
    let mut client = build_test_client(&storage).await;
    client.sync().await.expect("sync must succeed");

    let test_account = create_funded_account("deposit-halt").await;
    let account = open_account(&client, &test_account).await;
    let pool = open_pool(&account).await;

    let balance_before = pool.balance().await.expect("balance read before");

    start_progress_capture("deposit");
    let response = pool
        .deposit(SEED_DEPOSIT_STROOPS)
        .await
        .expect("deposit must resolve at the JS boundary, not throw");
    let stages = captured_stages("deposit");
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
#[ignore = "needs localnet and CORS server; run via e2e-browser-test.sh with -- --include-ignored"]
async fn e2e_transfer_halts_at_signing() {
    let storage = open_test_storage().await;
    let mut client = build_test_client(&storage).await;
    client.sync().await.expect("initial sync must succeed");

    // The recipient (created + registered) and the source (created + seeded)
    // are independent until the transfer call below, so build them
    // concurrently.
    let (recipient_account, source_account) = futures::join!(
        async {
            let recipient_account = create_funded_account("transfer-recipient").await;
            register_account(&client, &recipient_account).await;
            recipient_account
        },
        async {
            let source_account = create_funded_account("transfer-source").await;
            seed_deposit(&client, &source_account, SEED_DEPOSIT_STROOPS).await;
            source_account
        },
    );
    client
        .sync()
        .await
        .expect("sync after seeding must succeed");

    let account = open_account(&client, &source_account).await;
    let pool = open_pool(&account).await;
    let balance_before = pool.balance().await.expect("balance read before");
    assert!(
        balance_before >= FLOW_AMOUNT_STROOPS,
        "seeding must leave at least {FLOW_AMOUNT_STROOPS} stroops spendable, have {balance_before}"
    );

    start_progress_capture("transfer");
    let response = pool
        .transfer(&recipient_account.address, FLOW_AMOUNT_STROOPS)
        .await
        .expect("transfer must resolve at the JS boundary, not throw");
    let stages = captured_stages("transfer");
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
#[ignore = "needs localnet and CORS server; run via e2e-browser-test.sh with -- --include-ignored"]
async fn e2e_withdraw_halts_at_signing() {
    let storage = open_test_storage().await;
    let mut client = build_test_client(&storage).await;
    client.sync().await.expect("initial sync must succeed");

    let test_account = create_funded_account("withdraw-halt").await;
    seed_deposit(&client, &test_account, SEED_DEPOSIT_STROOPS).await;
    client
        .sync()
        .await
        .expect("sync after seeding must succeed");

    let account = open_account(&client, &test_account).await;
    let pool = open_pool(&account).await;
    let balance_before = pool.balance().await.expect("balance read before");
    assert!(
        balance_before >= FLOW_AMOUNT_STROOPS,
        "seeding must leave at least {FLOW_AMOUNT_STROOPS} stroops spendable, have {balance_before}"
    );

    start_progress_capture("withdraw");
    let response = pool
        .withdraw(FLOW_AMOUNT_STROOPS, None)
        .await
        .expect("withdraw must resolve at the JS boundary, not throw");
    let stages = captured_stages("withdraw");
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
        &JsValue::from_str(&test_pool_contract()),
    )
    .unwrap();
    account
        .pool(options.into())
        .await
        .expect("pool session must open")
}

/// A full session against localnet: key derivation from the owner's SEP-53
/// signature, sync, and a pool state read.
#[wasm_bindgen_test]
#[ignore = "needs localnet and CORS server; run via e2e-browser-test.sh with -- --include-ignored"]
async fn e2e_session_account_setup_and_sync() {
    let storage = open_test_storage().await;
    let mut client = build_test_client(&storage).await;

    let test_account = create_funded_account("session-setup").await;
    let account = open_account(&client, &test_account).await;
    assert_eq!(
        account.user_address(),
        test_account.address,
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
        !notes.is_empty()
    );

    client.stop_background_sync();
}
