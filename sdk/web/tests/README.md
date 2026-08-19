# Browser e2e tests for the web client

End-to-end smoke tests that drive `Client`/`PrivatePool` in a real headless
browser against testnet, covering deposit, transfer and withdraw up to — but
excluding — transaction signing and submission.

The tests live in [`../src/client/e2e_tests.rs`](../src/client/e2e_tests.rs) (an
inline `#[cfg(test)]` module, not this directory — they need crate-internal
access).

## Prerequisites

- **A browser and matching driver.** `chromedriver` + `chromium`/`chrome` is the
  tested combination; `geckodriver` + `firefox` also works
  (`GECKODRIVER=… ` instead of `CHROMEDRIVER=…`). GitHub's `ubuntu-latest`
  runners ship both preinstalled.
- **Node.js** — the worker JS and circuit artifacts are served from
  `sdk/web/dist`, built via `npm`.
- **Circuit artifacts**, built once, in **both** profiles:

```bash
cargo build -p circuits
cargo build -p circuits --release
```

Both are needed. `sdk/web/build.rs` reads the debug artifacts
(`target/circuits-artifacts/debug`) to compile the debug test binary, and the
release artifacts feed the `sdk/web` npm dist that the prover fetches at
runtime. Building only `--release` fails the test compile on a fresh checkout —
easy to miss locally, where earlier builds have usually left the debug
artifacts lying around.

Everything else is handled by the wrapper script described below.

## Account provisioning

The tests need two funded testnet accounts registered in the public-key
registry. Provision them once:

```bash
deployments/scripts/e2e-accounts-setup.sh
```

This creates two keypairs, funds them via friendbot (with backoff), derives
privacy keys and registers public keys on-chain, then writes
`deployments/testnet/.e2e-accounts.env` (mode 600, git-ignored — **it contains
secret keys**). Re-running verifies instead of re-provisioning; `--verify`
checks without creating, and `--force` recreates.

No ASP membership registration and no admin secret are required: the target pool
carries `policyFlags: ["blocklist"]`, so membership proofs are not needed (they
are gated on the `Allowlist` flag — `sdk/types/src/policy_tx.rs`; the pool's
flags are in `deployments/testnet/deployments.json`).

## Running the tests

Run through the wrapper. Nothing needs sourcing first:

```bash
sdk/web/scripts/e2e-browser-test.sh cargo test --target wasm32-unknown-unknown -p stellar-private-payments-sdk-web -- --include-ignored
```

`--include-ignored` is required. These e2e tests are `#[ignore]`d by default
precisely because they need testnet accounts and the static server, which lets
the PR-time `wasm-test` job run the rest of this crate's tests (the spike and
circuits tests) without either. Omit the flag and all six are silently skipped —
the run still reports success.

Run the suite **unfiltered** as shown above; the tests are designed to run in
one page. To iterate on a single test while debugging, append a filter:

```bash
sdk/web/scripts/e2e-browser-test.sh cargo test --target wasm32-unknown-unknown -p stellar-private-payments-sdk-web e2e_deposit_halts_at_signing -- --include-ignored --nocapture
```

[`../scripts/e2e-browser-test.sh`](../scripts/e2e-browser-test.sh) owns the run
lifecycle: it exports `deployments/testnet/.e2e-accounts.env` (override with
`E2E_ENV_FILE`; a missing file is not an error), builds `sdk/web/dist` when
missing, serves it with CORS headers on `E2E_STATIC_ORIGIN` (default
`http://127.0.0.1:8099`), waits for readiness, resolves `CHROMEDRIVER` from
`PATH` when unset, and raises `WASM_BINDGEN_TEST_TIMEOUT` to 600s — the
wasm-bindgen default of 20s cannot cover real proving plus testnet confirmation.
A server already listening on that origin is reused and left running.

Variables already exported win over the env file, so you can override any single
value inline (`E2E_POOL_CONTRACT=… sdk/web/scripts/e2e-browser-test.sh …`), and
CI's injected secrets are never clobbered by a stale local file.

Do not use `python3 -m http.server` by hand: it sends no CORS headers, and the
test page loads these assets cross-origin.

### Rebuild caveat

Configuration is read at **compile time** via `option_env!`
(`E2E_ACCOUNT_A_ADDRESS`, `E2E_ACCOUNT_A_SECRET`, `E2E_ACCOUNT_B_ADDRESS`,
`E2E_RPC_URL`, `E2E_POOL_CONTRACT`, `E2E_STATIC_ORIGIN`). `sdk/web/build.rs`
declares `rerun-if-env-changed` for each, so editing the env file rebuilds the
test binary on the next run.

They must be **exported** for the `cargo` invocation, not merely present in the
file — the wrapper does that for you. Invoking `cargo test` directly, without
the wrapper, you have to export them yourself
(`set -a; . deployments/testnet/.e2e-accounts.env; set +a`), and you also lose
the static server the tests need. Prefer the wrapper.

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

`signMessage` still succeeds — `Client::account` derives privacy keys from it on
first use — returning a fixed 64-byte blob. The test signer intentionally does
not reproduce a real SEP-53 signature, because key derivation only needs a
64-byte input and the flows under test never submit.

**Setup transactions are signed and submitted, by design.** Transfer and withdraw
need pre-existing spendable notes, so the suite seeds them with genuinely
submitted deposits using a real Ed25519 signer. The flows under assertion stop
before signing; setup is not covered by that boundary. The accounts are
disposable testnet accounts, and each seeded deposit spends a small amount of
testnet XLM, so repeated local runs slowly drain them — re-run the provisioning
script if an account runs dry.
