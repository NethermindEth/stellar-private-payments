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

## One-time setup

```bash
cd e2e-freighter
npm ci
```

The vendored Freighter extension (`vendor/freighter/`) and the Chrome
profile snapshot (`profile-snapshot.tar.gz`) are already checked in
(git-ignored working copies aside) — no extra setup needed unless you're
rebuilding the profile from scratch (see "Rebuilding the profile snapshot"
below).

Every run needs the test account's secret and the Freighter unlock
password, both stored in the git-ignored env file
(`deployments/testnet/.e2e-accounts.env`). `run-e2e.sh` and `run-all.sh`
source it automatically when the variables aren't already exported — no
manual step, from any interactive shell. To override a variable for a
run, export it first; explicit environment wins over the file.

## Running the suite or a single test

`scripts/run-all.sh` runs the whole suite — every `tests/*.mjs` in
order, one fresh profile restore per test — and prints a per-test
summary; with arguments it runs just those files:

```bash
bash e2e-freighter/scripts/run-all.sh                                     # whole suite
bash e2e-freighter/scripts/run-all.sh e2e-freighter/tests/01-connect.mjs  # subset
```

The npm presets wrap it: `npm run ci` (headless, auto-approve) and
`npm run demo` (headed, human approval).

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
| `tests/09-disclose-negative.mjs` | Adversarial battery against a single valid receipt: garbage/unparseable input fails cleanly with "Invalid JSON" and the import flow recovers right after; a tampered proof fails specifically on "Proof invalid"; a tampered context field fails specifically on "Context mismatch" (proof still valid). Each case asserts the SPECIFIC check that fails, not a generic error. A stale-root case was tried and dropped: the pool's on-chain root history is 90 entries deep, so one extra deposit never evicts a fresh receipt's root — see the file's header for the full explanation. Also needs the local `APP_URL` build. |
| `tests/10-advanced-transfers.mjs` | Deposit 0.01 XLM, then transfer it to a registered second account entirely through the Advanced tab (a fixed-shape single-`transact`-step composer, not a form or JSON plan builder — see the file's header for the full UI discovery): select the deposited note via its own "Use" button, fill a recipient/amount output row, execute, confirm SUCCESS on-chain. |
| `tests/11-failure-modes.mjs` | Failure-mode battery, all pre-signing and non-submitting: over-withdraw and over-transfer (10x the deposited balance) both fail on tx-planner's local "no combination of notes" check; transferring to a freshly-generated, never-registered address fails the same local-registry lookup 05 documents ("No local registration found"); depositing above the on-chain 100 XLM cap fails during simulation with no client-side pre-check at all (confirmed live via `getLedgerEntries` — see the file's header). Ends with a real, successful recovery deposit proving the battery leaves no poisoned state. |

## Rebuilding the profile snapshot

The snapshot (`profile-snapshot.tar.gz`) is a pre-onboarded Chrome profile —
Freighter unlocked, the test account imported, and the app's own onboarding
wizard already completed — so ordinary test runs skip both. Rebuild it only
if the vendored extension version changes or the profile gets corrupted:

```bash
# These standalone node scripts need the env exported first (only
# run-e2e.sh / run-all.sh self-source). On fish, export with:
#   for line in (grep -v '^#' deployments/testnet/.e2e-accounts.env | grep '=')
#       set -gx (string split -m 1 '=' -- $line)
#   end
set -a; . deployments/testnet/.e2e-accounts.env; set +a

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
