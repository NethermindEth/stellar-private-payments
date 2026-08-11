# e2e-freighter

End-to-end tests that drive the deployed app through a real Freighter
extension in Chrome/Chromium, submitting real transactions on Stellar
testnet.

## Requirements

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
sudo apt install -y nodejs npm chromium-browser
```

If `chromium-browser` isn't available (some Ubuntu versions ship Chromium
only as a snap), install the snap instead and point `E2E_CHROMIUM_PATH` at
it:

```bash
sudo snap install chromium
export E2E_CHROMIUM_PATH=/snap/bin/chromium
```

The snap package runs Chromium in its own mount namespace with a private
`/tmp`, so the profile snapshot is restored inside `e2e-freighter/.tmp-profiles/`
instead of `/tmp`. If you use another sandboxed browser that cannot see the
host `/tmp` (Flatpak, etc.), set `E2E_PROFILE_TMPDIR` to a directory that the
browser process can see.

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
brew install node
brew install --cask chromium
```

macOS installs Chromium as an app bundle, not a plain binary, so point
`E2E_CHROMIUM_PATH` at the binary inside it:

```bash
export E2E_CHROMIUM_PATH="/Applications/Chromium.app/Contents/MacOS/Chromium"
```

Add that `export` to your shell profile so it's set for every run, or
prefix each command with it inline.

## First time run

Prerequisites: the Requirements above, plus the `stellar` CLI (27 or newer —
`spp` passes `--auto-sign` to `stellar tx sign`, which older releases don't
know) and `trunk` installed. Then three commands:

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

Note: until the deployed app is redeployed with the nullifier-detection
fix, the disclosure tests (06–09) must run against a locally built app —
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

## The tests

Each submits real transactions on testnet — run them deliberately, not in
a tight loop.

| File | Proves |
|---|---|
| `tests/01-connect.mjs` | Connect flow: Freighter's grant-access approval, wallet address shown, network is TESTNET. |
| `tests/02-deposit.mjs` | Deposit 0.01 XLM: proving/signing/submitting stages, real Freighter signTransaction approval(s), transaction confirmed `SUCCESS` via direct Soroban RPC lookup (not the UI balance display — see the file's header comment for why). |
| `tests/03-rejection.mjs` | Rejecting a deposit's signing prompt: the app surfaces it as "Deposit cancelled." (not a crash or generic error) and returns to idle. |
| `tests/04-deposit-withdraw.mjs` | Deposit then withdraw to self back-to-back: two distinct transactions, both confirmed `SUCCESS` on-chain. |
| `tests/05-deposit-transfer.mjs` | Deposit then transfer to a second, registered account (`E2E_ACCOUNT_D_ADDRESS`): recipient resolves through the public-key registry, two distinct transactions, both confirmed `SUCCESS` on-chain. |
| `tests/06-disclose-basic.mjs` | Deposit twice, generate a 1-note selective-disclosure receipt for an unspent note, then verify that receipt through the app's own verify flow: proof and context check out, and the note's status shows unspent. Single account throughout — see the file's header comment for why. |
| `tests/07-disclose-spent.mjs` | Deposit three times, withdraw once (spending one note), then generate and verify disclosure receipts for BOTH a spent note (proof/context/root still pass, but no "Fully verified" badge, status shows spent) and a still-unspent note (fully verified, status shows unspent) — the second guards against an overcorrected check that marks everything spent. Also accepts `APP_URL` pointing at a locally-served build, driving the onboarding wizard on first connect if needed. |
| `tests/08-disclose-lifecycle.mjs` | Full lifecycle: deposit five times, withdraw once, generate 1/2/3/4-note disclosures of the remaining unspent notes plus one of the spent note, verify all five, withdraw again, then RE-VERIFY the same five receipts — whichever receipt(s) disclose the note the second withdraw just spent must flip to spent, every other receipt's result must stay exactly as it was. Proves verification reflects current chain state, not a snapshot frozen at receipt creation. Needs `APP_URL` pointing at a locally-served build with the nullifier fix (the deployed app doesn't have it yet). |
| `tests/09-disclose-negative.mjs` | Adversarial battery against a single valid receipt: garbage/unparsable input fails cleanly with "Invalid JSON" and the import flow recovers right after; a tampered proof fails specifically on "Proof invalid"; a tampered context field fails specifically on "Context mismatch" (proof still valid). Each case asserts the SPECIFIC check that fails, not a generic error. A stale-root case was tried and dropped: the pool's on-chain root history is 90 entries deep, so one extra deposit never evicts a fresh receipt's root — see the file's header for the full explanation. Also needs the local `APP_URL` build. |
| `tests/10-advanced-transfers.mjs` | Deposit 0.01 XLM, then transfer it to a registered second account entirely through the Advanced tab (a fixed-shape single-`transact`-step composer, not a form or JSON plan builder — see the file's header for the full UI discovery): select the deposited note via its own "Use" button, fill a recipient/amount output row, execute, confirm SUCCESS on-chain. |
| `tests/11-failure-modes.mjs` | Failure-mode battery, all pre-signing and non-submitting: over-withdraw and over-transfer (10x the deposited balance) both fail on tx-planner's local "no combination of notes" check; transferring to a freshly-generated, never-registered address fails the same local-registry lookup 05 documents ("No local registration found"); depositing above the on-chain 100 XLM cap fails during simulation with no client-side pre-check at all (confirmed live via `getLedgerEntries` — see the file's header). Ends with a real, successful recovery deposit proving the battery leaves no poisoned state. |

## CI

Three GitHub Actions workflows automate e2e testing: two gates on push and
pull request to main, plus a manual dispatch job for the full suite:

### Workflows

**`e2e-webclient.yml`** — Pre-signing SDK suite (push/PR to main)

The sdk/web wasm-bindgen browser tests (`cargo test --target
wasm32-unknown-unknown -p stellar-private-payments-sdk-web --
--include-ignored`), compiled from the checked-out commit and run in
headless Chrome against testnet. These exercise the pre-signing SDK path
(flows signed directly with the test-account secrets — no Freighter, no
deployed app), so they need no nullifier-detection support in the deployed
app. Locally the same suite runs via `sdk/web/scripts/e2e-browser-test.sh`.

**`e2e-freighter-smoke.yml`** — Selected smoke tests (push/PR to main)

A fast gate that validates core Freighter integration: connect, rejection
UX, and deposit+transfer (01-connect, 03-rejection, 05-deposit-transfer)
against the deployed app on every push and PR to main.

**`e2e-freighter-full.yml`** — Full Freighter suite (manual dispatch only)

Comprehensive validation: all tests (01–11), built and served locally from
the checked-out commit (to include the nullifier fix). Triggered manually
via GitHub Actions UI or CLI:

```bash
gh workflow run e2e-freighter-full.yml --repo <OWNER/REPO>
```

### Environment and secrets

All three workflows require the protected `e2e-testnet` environment,
which provides these secrets:

- `E2E_ACCOUNT_A_ADDRESS` / `E2E_ACCOUNT_A_SECRET` — test account A,
  used by the pre-signing SDK suite (compiled into the test binary)
- `E2E_ACCOUNT_B_ADDRESS` / `E2E_ACCOUNT_B_SECRET` — test account B,
  used by the pre-signing SDK suite
- `E2E_ACCOUNT_C_ADDRESS` / `E2E_ACCOUNT_C_SECRET` — the wallet imported
  into the generated Freighter profile (profile generation in CI)
- `E2E_ACCOUNT_D_ADDRESS` — registered recipient address for the
  Freighter transfer tests (05, 10, 11; address only, no secret needed)
- `E2E_FREIGHTER_PASSWORD` — password the generated Freighter profile is
  created with and unlocked with (the provisioning script generates one that
  satisfies Freighter's uppercase/lowercase/digit rules)

Note the Freighter workflows must set every one of these explicitly: no
`.e2e-accounts.env` file exists in CI, and once `E2E_FREIGHTER_PASSWORD`
is set the scripts deliberately do not source one.

Provision these once using the setup script:

```bash
deployments/scripts/e2e-accounts-setup.sh
# Then copy from deployments/testnet/.e2e-accounts.env into the e2e-testnet
# environment secrets (minus the .env shell syntax)
```

### Profile generation in CI

Nothing is stored outside the workflow run — no release assets, no
caches, nothing committed. Each Freighter workflow generates the profile
snapshot fresh via the same chain used for local setup:

```bash
xvfb-run -a bash e2e-freighter/scripts/setup.sh
```

`setup.sh`'s provisioning and onboarding steps drive a headed browser, so
CI provides a virtual display with `xvfb-run` (preinstalled on
`ubuntu-latest`). The same step also downloads the pinned Freighter
extension from the upstream `stellar/freighter` GitHub release
(`scripts/fetch-extension.sh` — `vendor/` is git-ignored, so nothing
third-party is committed here either). The generated snapshot lands at
`e2e-freighter/profile-snapshot.tar.gz`, exactly where `run-all.sh`
expects it.

### Gating

The pre-signing suite gates every push and PR to main, validating the
checked-out commit's SDK code. The smoke workflow gates the same events
but validates the *deployed* app — it catches environment/state drift,
not app-code regressions in the commit. The full suite does not gate — it
is opt-in only, run manually when you want to validate against a freshly
built app including any pending nullifier fixes.

Note: `deployment.yml` (Pages build and deploy) is no longer gated by
the e2e signal. It runs independently; the push-triggered e2e jobs
provide visibility into integration health.

## Building the profile snapshot

One command does the whole chain (npm deps, the pinned Freighter
extension fetch, Freighter profile provisioning, the one-time headed
onboarding completion, the snapshot, and a verification pass):

```bash
bash e2e-freighter/scripts/setup.sh
```

It is idempotent: with a working existing snapshot it verifies and exits.
Re-run with `--force` if the vendored extension version changes or the
profile gets corrupted. The extension itself comes from the upstream
`stellar/freighter` GitHub release, pinned by version in
`scripts/fetch-extension.sh` — bump the pin there, run it with `--force`,
then rebuild the snapshot. The onboarding step must run headed (it can
stall under headless rendering), so run setup on a machine with a desktop
session. The env file is self-sourced by every step.

What setup.sh does under the hood, if you ever need the pieces:

```bash
# 0. Fetch the pinned Freighter extension into vendor/ (git-ignored)
bash e2e-freighter/scripts/fetch-extension.sh

# 1. Provision a fresh Freighter profile from scratch
node e2e-freighter/scripts/setup-freighter-profile.mjs

# 2. Complete the app's onboarding wizard once, HEADED (it can stall
#    under headless rendering — see the script's header comment)
DISPLAY=:1 node e2e-freighter/scripts/complete-onboarding.mjs

# 3. Snapshot the result
bash e2e-freighter/scripts/snapshot-profile.sh

# 4. Verify a restored copy skips the wizard, headless
APPROVE=auto node e2e-freighter/scripts/verify-onboarded.mjs
```

`scripts/prepare-profile.sh` restores the snapshot into a fresh temp
directory per run — never point two concurrent runs at the same restored
copy (Chrome's profile storage is single-writer). `scripts/run-e2e.sh` does
this automatically and cleans up afterward.
