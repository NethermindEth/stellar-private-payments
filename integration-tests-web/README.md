# Browser e2e tests for the web client

End-to-end smoke tests that drive `Client`/`PrivatePool` in a real headless
browser against a local `stellar/quickstart` network, covering deposit,
transfer and withdraw up to — but excluding — transaction signing and
submission.

The tests live in [`tests/e2e.rs`](tests/e2e.rs). This crate is separate from
`sdk/web` because it needs a live local network and its deployed contract
addresses (`deployments/local/deployments.json`, compiled in).

## Prerequisites

- **A browser and matching driver.** `chromedriver` + `chromium`/`chrome` is the
  tested combination; `geckodriver` + `firefox` also works
  (`GECKODRIVER=… ` instead of `CHROMEDRIVER=…`). GitHub's `ubuntu-latest`
  runners ship both preinstalled.
- **Node.js** — the worker JS and circuit artifacts are served from
  `sdk/web/dist`, built via `npm`.
- **Circuit artifacts**, built once:

```bash
make circuits
```

Circuit artifacts must exist under `target/circuits-artifacts/` (served from
`sdk/web/dist/circuits/` after `npm run build`).

Everything else is handled by the wrapper script described below: it builds
`sdk/web/dist` on demand (`npm ci && npm run build`) when `dist/workers` is
missing, and resolves `chromedriver` from `PATH`. A missing Rust/wasm
toolchain or missing circuit artifacts surface as that build's own error.

## Account provisioning

There isn't any. Each test generates, funds (via friendbot), and — if it needs
a resolvable transfer recipient — registers its own ephemeral keypair at run
time (`TestAccount` in [`tests/e2e.rs`](tests/e2e.rs)). Nothing is persisted,
no CLI involved. The pool tested is resolved from
`deployments/local/deployments.json` (the first enabled native-asset pool).

## Running the tests

Run through the wrapper. Nothing needs sourcing first:

```bash
integration-tests-web/run.sh cargo test --target wasm32-unknown-unknown --manifest-path integration-tests-web/Cargo.toml -- --include-ignored
```

`--include-ignored` is required. These e2e tests are `#[ignore]`d by default
because they need localnet and the static server, unlike `sdk/web`'s own
unit tests run earlier in the same CI job. Omit the flag and all seven are
silently skipped — the run still reports success.

CI runs each ignored e2e test in a fresh browser/OPFS database because sync
cursors are global to the database while note derivation is account-specific.
To reproduce that isolation or debug a single test, append a filter:

```bash
integration-tests-web/run.sh cargo test --target wasm32-unknown-unknown --manifest-path integration-tests-web/Cargo.toml e2e_deposit_halts_at_signing -- --include-ignored --nocapture
```

[`run.sh`](run.sh)
owns the run lifecycle: starts/stops the local `stellar/quickstart` container
(`deployments/scripts/localnet.sh`), deploys fresh contracts to it
(`deployments/scripts/deploy-local.sh`), builds `sdk/web/dist` when
missing, serves it with CORS headers on `E2E_STATIC_ORIGIN` (default
`http://127.0.0.1:8099`), waits for readiness, resolves `CHROMEDRIVER` from
`PATH` when unset, and raises `WASM_BINDGEN_TEST_TIMEOUT` to 600s — the
wasm-bindgen default of 20s cannot cover real proving plus chain confirmation.
A server already listening on that origin is reused and left running.

Do not use `python3 -m http.server` by hand: it sends no CORS headers, and the
test page loads these assets cross-origin. Invoking `cargo test` directly,
without the wrapper, loses the static server and localnet the tests
need — prefer the wrapper.

This crate is excluded from the workspace, so `-p integration-tests-web` from
the repo root won't resolve it — use `--manifest-path` instead.

## How the signing boundary is tested

Each flow runs with a stub wallet signer whose `signTransaction` and
`signAuthEntry` reject with SEP-0043 `code: -4`. That maps to
`Error::UserRejected` and surfaces to JS as `{status: "failed", code: -4}` — a
value **no other stage of the pipeline can produce**, so it distinguishes
"halted at signing as intended" from "something upstream actually broke".

Every flow test asserts four things together:

1. `status == "failed"`,
2. `code == -4` (the halt came from the signer),
3. `hashes` is empty (nothing was submitted),
4. progress events reached the `sign` stage (proving and simulation really
   completed, rather than the flow dying early).

`signMessage` returns a real SEP-53 signature from the selected test account.
`Client::account` verifies it against the note owner's public key before
deriving and storing privacy keys — an arbitrary 64-byte blob fails this check.

`e2e_foreign_derivation_signature_is_refused` requests a session for one
ephemeral account but returns a different account's message signature, and
checks derivation is refused both times (a first-failure bypass would only
show up on the retry).

**Setup transactions are signed and submitted, by design.** Transfer and
withdraw need pre-existing spendable notes, so the suite seeds them with real
submitted deposits; the flows under assertion stop before signing, so setup
isn't covered by that boundary. Each seeded deposit uses a fresh account, so
there's nothing to run dry across runs.
