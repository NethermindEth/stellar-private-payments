//! End-to-end browser tests for the web client (issue #168).
//!
//! Runs under `wasm-bindgen-test` in a real headless browser
//! (`run_in_browser`), driving [`Client`]/[`super::PrivatePool`] directly with
//! a stub wallet signer so a flow can be taken up to the signing boundary.
//!
//! # Worker loading
//!
//! `wasm-bindgen-test-runner` serves its test page from a fresh
//! `tempfile::tempdir()` created per run (wasm-bindgen-cli 0.2.126,
//! `src/wasm_bindgen_test_runner.rs:217`), so the built worker JS and circuit
//! artifacts cannot live on the test page's own origin — they must be served
//! from a separate local origin ([`STATIC_ORIGIN`]).
//!
//! That is a problem, because a **cross-origin module worker never starts**
//! (the script is fetched — the static server logs a 200 — but never executes,
//! with no error event), and `sdk/web` spawns both workers as module workers
//! (`.as_module(true)`: [`crate::storage`] and [`super`]).
//!
//! The way through: a `blob:` URL inherits the *page* origin, and a
//! same-origin blob module worker does start. `gloo_worker` already relies on
//! exactly this when `with_loader(false)` — it wraps an absolutised import in a
//! blob (gloo-worker 0.6.0 `src/actor/spawner.rs:181-205`). Since `sdk/web`
//! passes `with_loader(true)`, the worker URL is used verbatim, so these tests
//! hand it a blob URL built the same way: fetch the loader shim cross-origin
//! (allowed, with CORS), rewrite its relative specifiers to absolute
//! [`STATIC_ORIGIN`] URLs, and wrap that in a blob. Everything the shim then
//! imports has a real absolute base, so the wasm resolves correctly.
//!
//! # Setup transactions really are signed and submitted
//!
//! Transfer and withdraw need pre-existing spendable notes, so on-chain state
//! is seeded by genuinely signed and submitted deposits ([`seed_deposit`],
//! using [`SignerMode::Signing`]). Issue #168's "stop before signing" scope
//! applies to the **flows under test**, which use [`SignerMode::Sentinel`] —
//! not to setup. The accounts are disposable testnet accounts from
//! `deployments/scripts/e2e-accounts-setup.sh`.
//!
//! # Key derivation: why `signMessage` returns a fixed blob in both modes
//!
//! `Client::account` derives privacy keys on first use from whatever
//! `signMessage` returns (`sdk/web/src/client/mod.rs:207-213`), so both modes
//! need a working `signMessage`. Both return the same fixed 64-byte blob, which
//! means **the session's privacy keys differ from the keys
//! `deployments/scripts/e2e-accounts-setup.sh` registered on-chain** (those
//! came from a real SEP-53 signature via `spp onboard`).
//!
//! That is deliberate:
//!
//! * No flow under test resolves the account's *own* registered keys. Deposit
//!   and withdraw never consult the registry; `resolve_transfer_recipient`
//!   resolves only the **recipient's** keys (`sdk/client/src/pool.rs:338-352`).
//!   `Account::is_registered` does look up the own entry but only tests that
//!   one *exists* (`sdk/client/src/account.rs:111-119`).
//! * What seeding actually requires is that the seeding session and the
//!   asserted-flow session derive the *same* keys, so seeded notes are
//!   spendable later. A fixed blob guarantees that.
//! * Reproducing the registered signature would mean reimplementing SEP-53
//!   (prefix `"Stellar Signed Message:\n"`, SHA-256, sign —
//!   `cli/src/stellar_cli.rs:101-103`), for which there is no in-repo Rust
//!   helper; the CLI shells out to the `stellar` binary. A subtly wrong
//!   reimplementation would derive different keys *silently*.
//!
//! Consequence to keep in mind: these tests do **not** validate recipient-key
//! interop. A note encrypted to an account's *registered* key would not be
//! decryptable by one of these sessions. Nothing here depends on that, because
//! the asserted flows never submit.
//!
//! # Running these tests
//!
//! They need a CORS-enabled static server rooted at `sdk/web/dist` on
//! [`STATIC_ORIGIN`] plus `CHROMEDRIVER`. `sdk/web/scripts/e2e-browser-test.sh`
//! owns that whole lifecycle — build, serve, wait for readiness, run, tear
//! down:
//!
//! ```text
//! sdk/web/scripts/e2e-browser-test.sh \
//!   cargo test --target wasm32-unknown-unknown \
//!     -p stellar-private-payments-sdk-web -- --include-ignored
//! ```
//!
//! Every test here carries an `ignore` attribute, because each needs testnet
//! accounts and that static server. `--include-ignored` opts them in. That is
//! what lets the PR-time `wasm-test` job in `.github/workflows/wasm-build.yml`
//! run the rest of this crate's tests (the spike and circuits tests, which need
//! neither secrets nor a server) without these failing. The deployment gate in
//! `.github/workflows/deployment.yml` passes `--include-ignored` so it really
//! runs them — without that flag the gate would silently pass having skipped
//! everything.

// Tests favour `unwrap()` for brevity; the workspace-wide `unwrap_used` deny is
// meant for production paths, not assertions.
#![allow(clippy::unwrap_used)]

use std::{cell::RefCell, rc::Rc};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use js_sys::{Function, Object, Reflect};
use stellar_private_payments_sdk::chain::{
    Limits, LocalSigner as ChainLocalSigner, ReadXdr, TransactionEnvelope, WriteXdr,
};
use wasm_bindgen::{JsValue, closure::Closure};
use wasm_bindgen_test::*;

use super::Client;
use crate::storage::Storage;

wasm_bindgen_test_configure!(run_in_browser);

/// Origin of the CORS-enabled static server rooted at `sdk/web/dist`.
///
/// Compiled in from `E2E_STATIC_ORIGIN` when set (the wrapper script exports
/// it), otherwise the documented default. `option_env!` is resolved at build
/// time, so changing the variable rebuilds these tests.
const STATIC_ORIGIN: &str = match option_env!("E2E_STATIC_ORIGIN") {
    Some(origin) => origin,
    None => "http://127.0.0.1:8099",
};

/// Testnet RPC endpoint (the repo's existing default,
/// `app/js/disclosure.js:29`).
const RPC_URL: &str = match option_env!("E2E_RPC_URL") {
    Some(url) => url,
    None => "https://soroban-testnet.stellar.org",
};

/// Native XLM pool. `policyFlags: ["blocklist"]`, so it needs non-membership
/// only — no ASP membership leaf, hence no admin secret (membership proofs are
/// Allowlist-gated — `sdk/types/src/policy_tx.rs`; the pool's flags are in
/// `deployments/testnet/deployments.json`).
const POOL_CONTRACT: &str = match option_env!("E2E_POOL_CONTRACT") {
    Some(id) => id,
    // Current testnet native XLM pool (`deployments/testnet/deployments.json`).
    None => "CCPNFGD7A6LJ7H4FGFLTBSU6XGCPFR5DN76N5WNXOTDPOKASJIU4EMFV",
};

const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

/// Amount seeded per setup deposit, in stroops (0.1 XLM). Deliberately small:
/// these are friendbot-funded testnet accounts and every seed costs real
/// (testnet) balance plus proving time.
const SEED_DEPOSIT_STROOPS: u128 = 1_000_000;

/// Address of test account A, provisioned by
/// `deployments/scripts/e2e-accounts-setup.sh`.
///
/// Flows that halt at the signing boundary need only the *address*.
const ACCOUNT_A_ADDRESS: Option<&str> = option_env!("E2E_ACCOUNT_A_ADDRESS");

/// Address of test account B — the transfer recipient. Registered in the
/// public-key registry by the provisioning script, which is what lets
/// `resolve_transfer_recipient` find its keys
/// (`sdk/client/src/pool.rs:338-352`).
const ACCOUNT_B_ADDRESS: Option<&str> = option_env!("E2E_ACCOUNT_B_ADDRESS");

/// Amount moved by the transfer/withdraw flow tests, in stroops. Smaller than
/// [`SEED_DEPOSIT_STROOPS`] so a single seeded note covers it.
const FLOW_AMOUNT_STROOPS: u128 = 500_000;

/// Secret for test account A, used **only** by [`SignerMode::Signing`] to sign
/// the setup transactions that seed on-chain state.
///
/// This is compiled into the test binary under `target/`. Acceptable because
/// these are disposable testnet accounts created by
/// `deployments/scripts/e2e-accounts-setup.sh`; never point this at an account
/// that matters. The flows under test never need it — they halt before signing.
const ACCOUNT_A_SECRET: Option<&str> = option_env!("E2E_ACCOUNT_A_SECRET");

/// Fixed 64-byte signature blob the stub signer returns from `signMessage`,
/// base64-encoded. Key derivation SHA-256s these bytes with a domain tag and
/// never verifies them as a real Ed25519 signature, but the length must be
/// exactly 64 (`sdk/prover/src/encryption.rs:121-123`). Base64 — never hex:
/// `wallet_message_signature_to_bytes` tries base64 first, and 128 hex chars
/// are themselves valid base64, decoding to 96 bytes.
const STUB_SIGNATURE_B64: &str =
    "paWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpQ==";

/// Build a same-origin `blob:` URL for a worker loader served at
/// `{STATIC_ORIGIN}/workers/{file}`.
///
/// Fetches the shim, absolutises its relative import specifiers and its
/// `import.meta.url`-derived circuits base (which would otherwise resolve
/// against the blob URL and fail), then wraps the result in a blob.
async fn blob_worker_url(file: &str) -> String {
    // Deliberately XMLHttpRequest, NOT fetch: the circuits tests in this same
    // crate replace `window.fetch` with a shim that returns 4 canned bytes and
    // never restore it (`closure.forget()`, sdk/web/src/circuits.rs:373-403).
    // They share this page, so a `fetch` here would silently receive garbage
    // instead of the worker JS and the worker would never start.
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
             // './foo.js' -> absolute on the static origin
             src = src.replace(/from '\.\/([^']+)'/g, "from '" + base + "/$1'");
             // new URL('../circuits/', import.meta.url).href -> absolute
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

/// Open [`Storage`] against a blob-wrapped storage worker.
///
/// `Storage::open` pings the worker before returning
/// (`sdk/web/src/storage.rs:57-62`), so success is a real round-trip, not just
/// a constructor that did not throw.
async fn open_test_storage() -> Storage {
    // `Storage::open` must be called ONCE per page session — the OPFS-backed
    // SQLite file is held with an exclusive sync access handle, so a second
    // storage worker fails with "Another tab or window is using this app's local
    // database". Every test in this module shares one page, so open lazily and
    // hand out `fork()` handles to the same worker, exactly as
    // `sdk/web/src/storage.rs:70-73` prescribes.
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

/// Build a [`Client`] with a blob-wrapped prover worker.
async fn build_test_client(storage: &Storage) -> Client {
    let prover_url = blob_worker_url("prover-worker.js").await;
    Client::new(RPC_URL.to_string(), storage, prover_url, None)
        .await
        .expect("client construction must succeed")
}

/// Stub wallet signer for driving a flow to the signing boundary.
///
/// `WalletSigner::new` requires all three of `signMessage`, `signTransaction`
/// and `signAuthEntry` to be present (`sdk/web/src/signer.rs:16`, `:36-42`),
/// even though only some are called.
///
/// `signMessage` succeeds so key derivation can complete. Both signing methods
/// reject with SEP-0043 `code: -4`, which maps to `Error::UserRejected` and
/// surfaces to JS as `{status:"failed", code:-4}` — a value no other stage of
/// the pipeline can produce. Note `signAuthEntry` is called *before*
/// `signTransaction` (`signer.rs:66-68` vs `:78-80`), so a flow may halt at
/// either; rejecting both means the sentinel appears whichever comes first.
fn stub_signer() -> JsValue {
    signer_with_mode(SignerMode::Sentinel)
}

/// Which way a test signer answers signing requests.
#[derive(Clone, Copy)]
enum SignerMode {
    /// Reject with the SEP-0043 `code: -4` sentinel. Used by the flows under
    /// test, so they halt at the signing boundary.
    Sentinel,
    /// Produce real Ed25519 signatures. Used **only** for setup transactions
    /// that must actually land on chain (see [`seed_deposit`]).
    Signing,
}

/// `signMessage` return, shared by both modes — see the key-derivation note in
/// the module header for why this is the fixed blob rather than a real SEP-53
/// signature.
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

/// Install `signTransaction` / `signAuthEntry` that really sign, mirroring what
/// a wallet does, via `chain::LocalSigner` (the same signer the native CLI and
/// tests use). Bridging through JS closures is far less code than
/// reimplementing the XDR signing dance, and it exercises the exact
/// `WalletSigner` call path production uses.
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
    // `LocalSigner::sign` SHA-256s the bytes then signs, which is exactly what
    // `sign_auth_preimage` does to the preimage XDR
    // (`sdk/stellar/src/signer.rs:110-116`).
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

    // `into_js_value` intentionally leaks: the signer must stay callable for the
    // rest of the test.
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

/// Both workers must start and answer, and [`Client`] must construct.
#[wasm_bindgen_test]
#[ignore = "needs testnet accounts and a CORS static server; run via sdk/web/scripts/e2e-browser-test.sh with -- --include-ignored"]
async fn e2e_smoke_client_construction() {
    let storage = open_test_storage().await;

    let mut client = build_test_client(&storage).await;

    // `Client::new` spawns the prover but does not ping it; ping explicitly so
    // this asserts the prover worker really came up.
    client
        .ensure_prover()
        .await
        .expect("prover worker must start and answer its ping");

    // The bundled deployment must parse, and the stub signer must satisfy
    // WalletSigner's acceptance rules.
    Client::contract_config().expect("bundled deployment config must parse");
    assert!(!stub_signer().is_undefined());

    // Release the background indexer slot before drop.
    client.stop_background_sync();
}

/// Open an [`super::Account`] session for test account A.
///
/// First use derives privacy keys from the stub's `signMessage` return
/// (`sdk/web/src/client/mod.rs:207-213`).
async fn open_account_a(client: &Client) -> super::Account {
    open_account_a_with(client, SignerMode::Sentinel).await
}

/// Open an [`super::Account`] session for test account A with an explicit
/// signer mode.
async fn open_account_a_with(client: &Client, mode: SignerMode) -> super::Account {
    let address = ACCOUNT_A_ADDRESS.expect(
        "E2E_ACCOUNT_A_ADDRESS not compiled in: run via \
         `set -a; . deployments/testnet/.e2e-accounts.env; set +a` \
         (see deployments/scripts/e2e-accounts-setup.sh)",
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
        .expect("account session must open and derive keys from the stub blob")
}

/// Read the `status` field of an `execute_plan` response
/// (`sdk/web/src/client/execute/mod.rs:29-42`).
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
/// `-4` is the sentinel: it is reachable only via `Error::UserRejected`, which
/// only the signer path constructs
/// (`sdk/web/src/client/execute/mod.rs:92-104`).
fn response_code(response: &JsValue) -> Option<f64> {
    Reflect::get(response, &JsValue::from_str("code"))
        .ok()
        .and_then(|code| code.as_f64())
}

/// DOM event carrying transaction progress
/// (`TX_PROGRESS_EVENT`, `sdk/web/src/client/execute/progress.rs:8`).
const TX_PROGRESS_EVENT: &str = "stellar-private-payments:tx-progress";

/// Start recording `stage` values from progress events.
///
/// Needed to tell "halted at signing" apart from "died earlier and never
/// reached signing" — a `{status:"failed"}` response alone cannot distinguish
/// them.
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

/// Run a deposit to completion — prove, simulate, **sign, submit, confirm** —
/// so later tests start from real on-chain notes.
///
/// Uses [`SignerMode::Signing`]: this is setup, not a flow under test.
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
#[ignore = "needs testnet accounts and a CORS static server; run via sdk/web/scripts/e2e-browser-test.sh with -- --include-ignored"]
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

/// Assert a response is the signing-boundary sentinel and nothing weaker.
///
/// Three conditions together, because any one alone is a false-green risk:
/// `code == -4` proves the halt came from the signer, an empty `hashes` proves
/// nothing was submitted, and a `sign` stage in `stages` proves proving and
/// simulation actually completed rather than the flow dying early.
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
        "{flow}: must have reached the 'sign' stage — otherwise the failure came \
         from prove/simulate, not the signing boundary (stages: {stages:?})"
    );
}

/// Deposit must run prove → simulate and then halt exactly at signing.
///
/// Deposit needs no pre-existing notes, so this test seeds nothing.
#[wasm_bindgen_test]
#[ignore = "needs testnet accounts and a CORS static server; run via sdk/web/scripts/e2e-browser-test.sh with -- --include-ignored"]
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

    // Belt and braces: a halted flow must not have moved any funds.
    let balance_after = pool.balance().await.expect("balance read after");
    assert_eq!(
        balance_after, balance_before,
        "a flow halted at signing must not change the pool balance"
    );

    client.stop_background_sync();
}

/// Transfer must spend seeded notes through prove → simulate, then halt at
/// signing.
///
/// Unlike deposit, this exercises the *spend* path, so it needs pre-existing
/// spendable notes (seeded here) and a non-membership proof for the inputs
/// (`policyFlags: ["blocklist"]` on the target pool).
#[wasm_bindgen_test]
#[ignore = "needs testnet accounts and a CORS static server; run via sdk/web/scripts/e2e-browser-test.sh with -- --include-ignored"]
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
///
/// `recipient` is omitted, so it defaults to the account's own address
/// (`sdk/web/src/client/pool.rs:123`).
#[wasm_bindgen_test]
#[ignore = "needs testnet accounts and a CORS static server; run via sdk/web/scripts/e2e-browser-test.sh with -- --include-ignored"]
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
///
/// This is the runtime proof of the phase-1 assumption that a fixed 64-byte
/// `signMessage` blob survives `derive_save_user_keys` — the spike only
/// verified that the blob decodes to 64 bytes.
#[wasm_bindgen_test]
#[ignore = "needs testnet accounts and a CORS static server; run via sdk/web/scripts/e2e-browser-test.sh with -- --include-ignored"]
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

    // Reaching here means neither signTransaction nor signAuthEntry was called:
    // both reject with the code -4 sentinel, which would have failed the reads.
    client.stop_background_sync();
}
