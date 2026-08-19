# e2e-freighter

End-to-end tests that drive the deployed app through a real Freighter
extension in Chrome/Chromium, submitting real transactions on Stellar
testnet.

## Requirements

Run `bash scripts/e2e-preflight.sh --fix` from the repo root first — it
checks (and heals what it safely can) everything below, and
`run-all.sh`/`run-e2e.sh` also run it automatically before every test
(`E2E_SKIP_PREFLIGHT=1` opts out). It cannot do the one-time headed
onboarding itself — see [First time run](#first-time-run) — but it will
tell you exactly which command to run for that. The manual requirements it
checks for:

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
never loads and every test fails with "Connect Freighter is still shown". The
preflight detects snap installs (`/snap/*`, `/var/snap/*`,
`/var/lib/snapd/*`) and reports them as MISSING with the PPA install
instructions above.

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
  and falls back to a perl `setpgrp` shim on macOS, so `make freighter-e2e`
  works out of the box — but don't remove the fallback or run the server
  in a way that detaches it from the script's process group, or you'll hit
  "could not determine the server's process group".

For the browser, the tests launch Chromium directly via Playwright
(`launchPersistentContext`) with an unpacked extension. The most reliable
way to get a compatible build is Playwright's own Chrome for Testing:

```bash
cd e2e-freighter && npx playwright install chromium
```

then point `E2E_CHROMIUM_PATH` at the binary inside the downloaded bundle:

```bash
export E2E_CHROMIUM_PATH="$HOME/Library/Caches/ms-playwright/chromium-*/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing"
```

(`brew install --cask chromium` also works; either way, set
`E2E_CHROMIUM_PATH` to the real binary — the app-bundle path above, not the
`Chromium` symlink — and add the `export` to your shell profile or prefix
each command with it.)

## First time run

Prerequisites: the Requirements above, plus the `stellar` CLI (27 or newer —
`spp` passes `--auto-sign` to `stellar tx sign`, which older releases don't
know) and `trunk` installed.

Fastest path — from the repo root:

```bash
bash scripts/e2e-preflight.sh --fix   # provisions accounts + Freighter deps
bash e2e-freighter/scripts/run-all.sh
```

`--fix` provisions the four test accounts and the Freighter node_modules +
vendored extension automatically. It cannot do the one-time headed
onboarding itself (no browser automation runs from the preflight), so if
that's still outstanding it prints the exact command to run — headed on a
desktop session, or the `xvfb-run` form on CI/headless — and exits nonzero
until you run it.

The three commands under the hood, if you'd rather run them yourself:

```bash
# 1. Provision the four test accounts (A/B for the SDK suite, C/D for the
#    Freighter tests): keypairs, friendbot funding, on-chain registration —
#    plus a generated E2E_FREIGHTER_PASSWORD — all recorded in the
#    git-ignored env file. Idempotent; --verify re-checks.
deployments/scripts/e2e-accounts-setup.sh

# 2. Install deps, build the Freighter profile (pinned extension, test
#    account, onboarding completed), snapshot it, verify. Idempotent;
#    --force rebuilds. The onboarding step needs a desktop session.
bash e2e-freighter/scripts/setup.sh

# 3. Run the suite.
bash e2e-freighter/scripts/run-all.sh
```

Disclosure tests (06–09) require a locally built app —
start `env -u NO_COLOR trunk serve` in one terminal and add
`APP_URL=http://localhost:8000` to the run command in the other.

## Subsequent runs

```bash
bash e2e-freighter/scripts/run-all.sh                                     # whole suite
bash e2e-freighter/scripts/run-all.sh e2e-freighter/tests/02-deposit.mjs  # subset
npm run demo                                                              # headed, you approve
npm run ci                                                                # headless, auto
```

Everything self-sources the env file — no manual exporting, any shell.
To override a variable for a run, export it first; explicit environment
wins over the file.

Single tests go through `scripts/run-e2e.sh <TEST_FILE>` (paths relative
to the repo root), controlled by two env vars:

- `APPROVE=auto|human` — `auto` clicks through every Freighter approval
  popup by matching its button text; `human` leaves them alone and waits
  for you to click.
- `HEADFUL=1` — runs Chrome with a visible window instead of headless.

### Mode 1 — Headless, auto-approve (what CI runs)

No visible window, fully unattended.

```bash
APPROVE=auto bash e2e-freighter/scripts/run-e2e.sh e2e-freighter/tests/04-deposit-withdraw.mjs
```

### Mode 2 — Headed, auto-approve (watch it drive itself)

A real Chrome window opens and you can watch it click through the app and
the Freighter popups, but it doesn't wait for you.

```bash
HEADFUL=1 APPROVE=auto bash e2e-freighter/scripts/run-e2e.sh e2e-freighter/tests/04-deposit-withdraw.mjs
```

### Mode 3 — Headed, human approval (the demo path)

A real Chrome window opens; the script drives the app's UI (filling
amounts, clicking Deposit/Withdraw, etc.) but stops and waits whenever a
Freighter approval popup appears — you click Confirm/Cancel yourself.

```bash
HEADFUL=1 APPROVE=human bash e2e-freighter/scripts/run-e2e.sh e2e-freighter/tests/04-deposit-withdraw.mjs
```

(The npm presets run the whole suite via `run-all.sh`; for one test, call
`run-e2e.sh` directly as above.)

### Mode 4 — Smoke check only (no test logic)

Just proves the pipeline reaches a connected state against the app. Useful
as a fast sanity check.

```bash
APPROVE=auto bash e2e-freighter/scripts/run-e2e.sh --smoke
```

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
npm --prefix e2e-freighter run test:unit                         # helper tests
bash e2e-freighter/scripts/serve-and-run.sh e2e-freighter/tests/04-deposit-withdraw.mjs
APPROVE=auto bash e2e-freighter/scripts/run-e2e.sh --smoke        # connection only
bash e2e-freighter/scripts/serve-and-run.sh e2e-freighter/tests/demo.mjs
bash e2e-freighter/scripts/serve-and-run.sh                       # full local suite
```

`demo.mjs` demonstrates indexer and navigation helpers without submitting a
transaction.

## The tests

Each submits real transactions on testnet — run them deliberately, not in
a tight loop.

| File | Proves |
|---|---|
| `tests/01-connect.mjs` | Connect flow: Freighter's grant-access approval, wallet address shown, network is TESTNET. |
| `tests/02-deposit.mjs` | Deposit 0.01 XLM: proving/signing/submitting stages, Freighter signTransaction approval(s), and `SUCCESS` confirmation through Soroban RPC. |
| `tests/03-rejection.mjs` | Rejecting a deposit's signing prompt: the app surfaces it as "Deposit cancelled." (not a crash or generic error) and returns to idle. |
| `tests/04-deposit-withdraw.mjs` | Deposit then withdraw to self back-to-back: two distinct transactions, both confirmed `SUCCESS` on-chain. |
| `tests/05-deposit-transfer.mjs` | Deposit then transfer to a second, registered account (`E2E_ACCOUNT_D_ADDRESS`): recipient resolves through the public-key registry, two distinct transactions, both confirmed `SUCCESS` on-chain. |
| `tests/06-disclose-basic.mjs` | Deposit twice, generate a 1-note selective-disclosure receipt for an unspent note, then verify the receipt through the app's verify flow. |
| `tests/07-disclose-spent.mjs` | Deposit three times, withdraw once, then verify a spent-note receipt and an unspent-note receipt. Supports a locally served app through `APP_URL`. |
| `tests/08-disclose-lifecycle.mjs` | Verify 1/2/3/4-note and spent-note receipts, withdraw again, then re-verify each receipt against current chain state. Requires a locally served app. |
| `tests/09-disclose-negative.mjs` | Verify malformed-input recovery, proof tampering, and context tampering with their respective verification results. Requires a locally served app. |
| `tests/10-advanced-transfers.mjs` | Deposit 0.01 XLM, then transfer it to a registered second account through the Advanced flow and confirm `SUCCESS` on-chain. |
| `tests/11-failure-modes.mjs` | Verify pre-signing failures for insufficient notes, unregistered recipients, and the pool deposit cap, then complete a successful recovery deposit. |

## CI

Two GitHub Actions workflows automate e2e testing: the pre-signing SDK
suite gates on push/PR to main, and the Freighter suite runs a smoke
subset on PR plus the full suite on manual dispatch.

### Workflows

**`e2e-webclient.yml`** — Pre-signing SDK suite (push/PR to main)

The sdk/web wasm-bindgen browser tests (`cargo test --target
wasm32-unknown-unknown -p stellar-private-payments-sdk-web --
--include-ignored`), compiled from the checked-out commit and run in
headless Chrome against testnet. These exercise the pre-signing SDK path
(flows signed directly with the test-account secrets — no Freighter, no
deployed app), so they need no nullifier-detection support in the deployed
app. Locally the same suite runs via `sdk/web/scripts/e2e-browser-test.sh`.

**`e2e-freighter.yml`** — Freighter suite (smoke on PR, full on demand)

On pull requests to main it runs the smoke subset (01-connect,
03-rejection, 05-deposit-transfer) as a fast gate; `workflow_dispatch`
runs the whole suite (01-11). Both build and serve the app **from the
checked-out commit** on localhost:8000 via `serve-and-run.sh` — the same
path `make freighter-e2e` uses locally — so a PR is tested against its own
code, not whatever is deployed. Trigger the full suite with:

```bash
gh workflow run e2e-freighter.yml --repo <OWNER/REPO>
```

Overlapping runs are safe: each run provisions its own ephemeral testnet
accounts (`--ephemeral`), so two runs cannot spend each other's notes and
no `concurrency` group is needed. Fork PRs never run this job (it reads
the protected environment's secrets).

### Environment and secrets

The Freighter workflow requires the protected `e2e-testnet` environment,
which provides exactly one secret:

- `E2E_FREIGHTER_PASSWORD` — password the generated Freighter profile is
  created with and unlocked with (CI-only; the local setup script
  generates one that satisfies Freighter's
  uppercase/lowercase/digit rules)

No account secrets exist in CI. The account addresses, secrets, and the
pool contract id are exported to `$GITHUB_ENV` by the account-provisioning
step at run time (the pool is whatever `deployments.json` currently
names). The webclient workflow uses the same `e2e-testnet` environment
with the same single secret.

### Account provisioning in CI

Both workflows provision ephemeral per-run accounts themselves — nothing
is assumed from pre-seeded state:

1. **Provision test accounts** — runs `e2e-accounts-setup.sh --ephemeral`
   (webclient passes `--accounts a,b`): all keypairs are generated fresh
   on the runner, the first account is friendbot-funded as a faucet and
   distributes XLM to the rest in a single multi-operation transaction,
   and every account is onboarded and registered against whatever pool
   `deployments.json` currently names. The generated secrets are masked
   with `::add-mask::` and exported via `$GITHUB_ENV`.
2. **Generate Freighter profile snapshot** — `setup.sh` runs through
   `serve-and-run.sh --` (the `--` form), which builds+serves the app on
   :8000, exports `APP_URL`, and stops the server afterwards. The
   onboarding wizard navigates to `APP_URL`, so running bare `setup.sh`
   dies with "APP_URL is not set". `xvfb-run` provides the virtual
   display for setup's headed steps.

Because the accounts are registered moments before the tests run, the
preflight's `chain.accounts.*` checks execute for real instead of
skipping. The env-file checks do skip (no `.e2e-accounts.env` is
committed; the vars arrive via `$GITHUB_ENV`), while `env.vars.required`
still verifies against the environment for real.

### Gating

The pre-signing suite gates every push and PR to main, validating the
checked-out commit's SDK code. The Freighter smoke gate runs on the same
events and validates the checked-out app plus environment/state health.
The full Freighter suite does not gate and runs manually against a locally
built app.

Note: `deployment.yml` (Pages build and deploy) is no longer gated by
the e2e signal. It runs independently; the push-triggered e2e jobs
provide visibility into integration health.

## Building the profile snapshot

One command does the whole chain (npm deps, the pinned Freighter
extension fetch, Freighter profile provisioning, headed
onboarding completion, the snapshot, and a verification pass):

```bash
bash e2e-freighter/scripts/setup.sh
```

It is idempotent: with a working existing snapshot it verifies and exits.
Re-run with `--force` if the vendored extension version changes or the
profile is corrupted. The extension comes from the upstream
`stellar/freighter` GitHub release and is pinned in
`scripts/fetch-extension.sh`. The onboarding step requires headed rendering,
so run setup on a machine with a desktop session. The env file is self-sourced
by every step.

What setup.sh does under the hood, if you ever need the pieces:

```bash
# 0. Fetch the pinned Freighter extension into vendor/ (git-ignored)
bash e2e-freighter/scripts/fetch-extension.sh

# 1. Provision a fresh Freighter profile from scratch
bash e2e-freighter/scripts/provision.sh

# 2. Complete the app's onboarding wizard once in headed mode
DISPLAY=:1 bash e2e-freighter/scripts/provision.sh --skip-wizard

# 3. Snapshot the result
bash e2e-freighter/scripts/provision.sh

# 4. Verify a restored copy skips the wizard, headless
APPROVE=auto bash e2e-freighter/scripts/provision.sh
```

`scripts/provision.sh` restores the snapshot into a fresh temp
directory per run — never point two concurrent runs at the same restored
copy (Chrome's profile storage is single-writer). `scripts/run-e2e.sh` does
this automatically and cleans up afterward.
