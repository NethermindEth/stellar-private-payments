# integration-tests-app

End-to-end tests that drive the app through a real Freighter extension in
Chrome/Chromium, submitting real transactions against a local
`stellar/quickstart` network started fresh for each run
(`deployments/scripts/localnet.sh`) and deployed to
(`deployments/scripts/deploy-local.sh`).

## Requirements

`serve-and-run.sh` and `run-e2e.sh` both check the Freighter profile is
ready (node_modules, the vendored extension, the profile snapshot) before
every run and provision it via `scripts/setup.sh` if not
(`E2E_SKIP_SETUP=1` opts out). That can't do the one-time headed onboarding
itself when no display is available — see
[First time run](#first-time-run) — but it will tell you exactly which
command to run for that. The manual requirements:

- **Node.js** (18+; tested on 26)
- **Chromium** — the scripts launch the system browser directly via
  Playwright (`launchPersistentContext`), not Playwright's own bundled
  browser, so a real Chromium/Chrome install is required. The default path
  is `/usr/bin/chromium`; override it with `E2E_CHROMIUM_PATH` if yours
  lives elsewhere (see macOS below).
- For headed modes (`HEADFUL=1`), a real display (`$DISPLAY` set) — not
  needed for the default headless/CI mode.

### Ubuntu

```bash
sudo apt update
sudo apt install -y nodejs npm
```

For Chromium, use the `canonical-chromium-builds` PPA — the scripts launch the
system browser directly with an unpacked extension, which the Ubuntu snap
package cannot do:

```bash
sudo add-apt-repository ppa:canonical-chromium-builds/stable
sudo apt update
sudo apt install -y chromium-browser
```

**Do not use the `chromium` snap for these tests.** The snap wrapper runs
Chromium in its own mount namespace with a private `/tmp`, so the extension
never loads and every test fails with "Connect Freighter is still shown".
If you hit that error, check `which chromium` / `E2E_CHROMIUM_PATH` for a
`/snap/*` or `/var/snap/*` path and switch to the PPA install above.

If you already have the snap installed and just want the tests to work, remove
it and install from the PPA. If you use another sandboxed browser that cannot
see the host `/tmp` (Flatpak, etc.), set `E2E_PROFILE_TMPDIR` to a directory
that the browser process can see.

Ubuntu's `apt` Node.js package can lag well behind current releases; if you
hit version issues, install via [nvm](https://github.com/nvm-sh/nvm) or
[nodesource](https://github.com/nodesource/distributions) instead.

### Arch Linux

```bash
sudo pacman -S nodejs npm chromium
```

Arch's default install path (`/usr/bin/chromium`) matches the scripts'
default, so no `E2E_CHROMIUM_PATH` override is needed.

### macOS (Homebrew)

Install [Homebrew](https://brew.sh) first if you don't have it, then:

```bash
brew install node llvm
```

Two macOS-specific prerequisites beyond the common ones:

- **`llvm` from Homebrew is required to build the SDK's WASM artifacts.**
  Apple's bundled clang has no `wasm32-unknown-unknown` backend, so
  `cargo build` (and `make serve`) fails with "No available targets are
  compatible with triple wasm32-unknown-unknown". Put Homebrew's clang
  first on `PATH`:

  ```bash
  export PATH="$(brew --prefix llvm)/bin:$PATH"
  ```

- **The e2e suite serves the app itself (`make serve`) and manages the
  server's process group.** `serve-and-run.sh` uses `setsid` when present
  and falls back to a perl `setpgrp` shim on macOS, so `make integration-tests-app-e2e`
  works out of the box — but don't remove the fallback or run the server
  in a way that detaches it from the script's process group, or you'll hit
  "could not determine the server's process group".

For the browser, the tests launch Chromium directly via Playwright
(`launchPersistentContext`) with an unpacked extension. The most reliable
way to get a compatible build is Playwright's own Chrome for Testing:

```bash
cd integration-tests-app && npx playwright install chromium
```

then point `E2E_CHROMIUM_PATH` at the binary inside the downloaded bundle:

```bash
export E2E_CHROMIUM_PATH="$(echo ~/Library/Caches/ms-playwright/chromium-*/chrome-mac-arm64)/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing"
```

(`brew install --cask chromium` also works; either way, set
`E2E_CHROMIUM_PATH` to the real binary — the app-bundle path above, not the
`Chromium` symlink — and add the `export` to your shell profile or prefix
each command with it.)

## First time run

Prerequisites: the Requirements above, plus the `stellar` CLI (27 or newer —
`spp` passes `--auto-sign` to `stellar tx sign`, which older releases don't
know), `trunk`, and Docker (for localnet).

From the repo root:

```bash
make integration-tests-app-setup   # one-time: profile snapshot, headed
make integration-tests-app-e2e     # whole suite
```

`integration-tests-app-setup` installs `node_modules`, fetches the vendored
extension, and builds/verifies the profile snapshot — the one step that needs
a headed browser (or `xvfb-run -a make integration-tests-app-setup` on
CI/headless). It's idempotent, so it's safe to run before every session.
`serve-and-run.sh`/`run-e2e.sh` also call it automatically when missing, so
this step is optional — it just moves the headed cost earlier.

## Subsequent runs

`serve-and-run.sh` starts localnet, deploys fresh contracts, serves the app on
`localhost:8080`, runs the given tests (default: the whole suite) and tears it
all down:

```bash
bash integration-tests-app/scripts/serve-and-run.sh integration-tests-app/tests/02-deposit.mjs
```

Two env vars control a run:

- `APPROVE=auto|human` — `auto` clicks through every Freighter approval
  popup by matching its button text; `human` leaves them alone and waits
  for you to click.
- `HEADFUL=1` — runs Chrome with a visible window instead of headless.

`run-all.sh` and `run-e2e.sh` are the inner steps; they expect localnet and
`APP_URL` already up.

## Operation building blocks and timeout policy

The numbered scenarios compose small operations from `src/` rather than
sleeping for a guessed amount of time. Use the same pattern for a new flow:

```js
import { deposit, withdraw } from '../src/moveFunds.mjs';
import { gotoAdvanced, gotoMoveFlow, gotoMoveFunds } from '../src/navigation.mjs';
import { waitForSyncedLedger } from '../src/indexer.mjs';
import { waitForNotesAfterIndexer } from '../src/notes.mjs';

await gotoMoveFunds(page);
await deposit(helpers, { logTag: 'my-flow', amount: '0.01', rpcUrl });

const beforeWithdrawal = await waitForSyncedLedger(page);
const spentNote = waitForNotesAfterIndexer(page, {
  afterLedger: beforeWithdrawal.ledger,
  notes: { minCount: 1, predicate: (note) => note.state === 'spent' },
});
await gotoMoveFlow(page, 'withdraw');
await withdraw(helpers, { logTag: 'my-flow', amount: '0.01', rpcUrl });
await gotoAdvanced(page);
await spentNote;
```

For transfers, navigate to the `transfer` flow and use `transfer(...)` after
the recipient lookup reaches its observable ready state. For selective
disclosure, navigate with `gotoDisclosure(page)`, select notes through the
disclosure helpers, generate a receipt, then use `verifyDisclosureUntil(...)`
to wait for the required proof, context, root, and note-readiness result.

Timeouts are ownership-specific, not one global test timeout:

- DOM/view and dialog transitions are bounded at 5–15 seconds.
- Wallet runtime readiness is bounded at 60 seconds. Readiness means
  the app's `body[data-wallet-state="ready"]` — the selected pool is usable,
  not merely that an address is rendered.

  `connectApp` returns when the runtime is ready or onboarding is open.
  `driveWizard` completes onboarding and then waits for runtime readiness.
- Freighter approval discovery is short and repeated while an operation is
  active.
- Submitted transaction confirmation has a 60-second chain/RPC bound.
- Indexer, note readiness, and disclosure proof/root work use their own
  operation-level conditions and 120–180 second budgets.

Do not replace these waits with `page.waitForTimeout(...)`. If a bounded wait
fails, retain its last observed state and investigate the owning boundary:
the DOM state, extension approval, chain transaction, indexer ledger, note
readiness, or proof worker.

### Useful commands

```bash
npm --prefix integration-tests-app run test:unit                         # helper tests
bash integration-tests-app/scripts/serve-and-run.sh                       # full local suite
```

## The tests

Each submits real transactions against localnet — run them
deliberately, not in a tight loop.

| File | Proves |
|---|---|
| `tests/01-connect.mjs` | Connect flow: Freighter's grant-access approval, wallet address shown, network is the local custom network. |
| `tests/02-deposit.mjs` | Deposit 0.01 XLM: proving/signing/submitting stages, Freighter signTransaction approval(s), and `SUCCESS` confirmation through Soroban RPC. |
| `tests/03-rejection.mjs` | Rejecting a deposit's signing prompt: the app surfaces it as "Deposit cancelled." (not a crash or generic error) and returns to idle. |
| `tests/04-deposit-withdraw.mjs` | Deposit then withdraw to self back-to-back: two distinct transactions, both confirmed `SUCCESS` on-chain. |
| `tests/05-deposit-transfer.mjs` | Deposit then transfer to a second, freshly created and registered account: recipient resolves through the public-key registry, two distinct transactions, both confirmed `SUCCESS` on-chain. |
| `tests/06-disclose-basic.mjs` | Deposit twice, generate a 1-note selective-disclosure receipt for an unspent note, then verify the receipt through the app's verify flow. |
| `tests/07-disclose-spent.mjs` | Deposit three times, withdraw once, then verify a spent-note receipt and an unspent-note receipt. |
| `tests/08-disclose-lifecycle.mjs` | Verify 1/2/3/4-note and spent-note receipts, withdraw again, then re-verify each receipt against current chain state. |
| `tests/09-disclose-negative.mjs` | Verify malformed-input recovery, proof tampering, and context tampering with their respective verification results. |
| `tests/10-advanced-transfers.mjs` | Deposit 0.01 XLM, then transfer it to a registered second account through the Advanced flow and confirm `SUCCESS` on-chain. |
| `tests/11-failure-modes.mjs` | Verify pre-signing failures for insufficient notes, unregistered recipients, the pool deposit cap, and invalid, missing or unfunded signing accounts, then complete a successful recovery deposit. |
| `tests/12-signing-account.mjs` | Import a second ephemeral account and pick it to sign and pay, deposit 0.01 XLM into the owner's notes and withdraw it back to the owner, checking the confirmations name both accounts, the withdrawal warns that it links them, and on-chain the deposit is sent by the owner and the withdrawal by the signer. |
| `tests/13-onboarding.mjs` | Drives the app's real onboarding wizard end to end for a freshly imported, unseeded account (every other test pre-seeds past it). |

## CI

Two GitHub Actions workflows automate e2e testing: the pre-signing SDK
suite gates on push/PR to main, and the Freighter suite runs a smoke
subset on PR plus the full suite on manual dispatch.

### Workflows

**`integration-tests-web.yml`** — Pre-signing SDK suite (push/PR to main)

The `integration-tests-web` wasm-bindgen browser tests (`cargo test --target
wasm32-unknown-unknown --manifest-path integration-tests-web/Cargo.toml --
--include-ignored`), compiled from the checked-out commit and run in
headless Chrome against a local `stellar/quickstart` network. These exercise
the pre-signing SDK path (flows signed directly with ephemeral test-account
secrets generated at run time — no Freighter, no deployed app), so they need
no nullifier-detection support in the deployed app. Locally the same suite
runs via `integration-tests-web/run.sh`.

**`integration-tests-app.yml`** — Freighter suite (smoke on PR, full on demand)

On pull requests to main it runs the smoke subset (01-connect,
03-rejection, 05-deposit-transfer) as a fast gate; `workflow_dispatch`
runs the whole suite. Both build and serve the app **from the
checked-out commit** on localhost:8080 via `serve-and-run.sh` — the same
path `make integration-tests-app-e2e` uses locally — so a PR is tested against its own
code, not whatever is deployed. Trigger the full suite with:

```bash
gh workflow run integration-tests-app.yml --repo <OWNER/REPO>
```

Overlapping runs are safe: each run gets its own local `stellar/quickstart`
container and deploys fresh contracts to it, and every test account is
generated and funded ephemerally at run time — there is no shared state for
two runs to interfere with, so no `concurrency` group is needed. Fork PRs
never run this job (untrusted code must not drive a real browser/Docker
session on our runners).

### CI credentials

No GitHub secrets or environments. Each run generates its own ephemeral
accounts (`testAccount.mjs`) and a fixed, non-sensitive Freighter wallet
password (`env.mjs`) — nothing is generated ahead of time to mask.

## Building the profile snapshot

One command does the whole chain (npm deps, the pinned Freighter
extension fetch, Freighter profile provisioning, headed
onboarding completion, the snapshot, and a verification pass):

```bash
make integration-tests-app-setup
```

It is idempotent: with a working existing snapshot it verifies and exits. If
the vendored extension version changed or the profile is corrupted, force a
rebuild with `bash integration-tests-app/scripts/serve-and-run.sh -- bash integration-tests-app/scripts/setup.sh --force`.
The extension comes from the upstream `stellar/freighter` GitHub release and
is pinned in `scripts/fetch-extension.sh`. The onboarding step requires
headed rendering, so run setup on a machine with a desktop session.

What setup.sh does under the hood, if you ever need the pieces:

```bash
# 0. Fetch the pinned Freighter extension into vendor/ (git-ignored)
bash integration-tests-app/scripts/fetch-extension.sh

# 1. Provision a fresh profile, complete onboarding headed, and snapshot it.
#    Idempotent: with a working existing snapshot it verifies and exits
#    instead of rebuilding; --force always rebuilds.
bash integration-tests-app/scripts/provision.sh

# Restore the snapshot into a fresh temp dir, or verify it without rebuilding:
bash integration-tests-app/scripts/provision.sh --restore
bash integration-tests-app/scripts/provision.sh --verify
```

`--restore` prints a fresh temp directory per call — never point two
concurrent runs at the same restored copy (Chrome's profile storage is
single-writer). `scripts/run-e2e.sh` does this automatically and cleans up
afterward.
