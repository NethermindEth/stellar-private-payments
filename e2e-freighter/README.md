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
password, both stored in the git-ignored env file. Source it before any
run:

```bash
cd /home/marko/Projects/stellar-private-payments
set -a; . deployments/testnet/.e2e-accounts.env; set +a
```

## Running a test

All runs go through `scripts/run-e2e.sh <TEST_FILE>` (paths relative to the
repo root), controlled by two env vars:

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

Equivalent npm shortcuts exist for the smoke check only (they don't take a
test-file argument yet):

```bash
npm run demo   # HEADFUL=1 APPROVE=human --smoke
npm run ci      # APPROVE=auto --smoke
```

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

## Rebuilding the profile snapshot

The snapshot (`profile-snapshot.tar.gz`) is a pre-onboarded Chrome profile —
Freighter unlocked, the test account imported, and the app's own onboarding
wizard already completed — so ordinary test runs skip both. Rebuild it only
if the vendored extension version changes or the profile gets corrupted:

```bash
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
