// Shared env defaults for the standalone scripts (scripts/*.mjs run via node
// directly). No account/network provisioning file to source anymore — every
// account is created fresh per run (see testAccount.mjs) — just a fixed
// Freighter unlock password, since nothing sensitive rides on it (the wallet
// only ever holds ephemeral localnet keys).
if (!process.env.E2E_FREIGHTER_PASSWORD) {
  process.env.E2E_FREIGHTER_PASSWORD = 'SppE2eFreighter1!';
}

export const CHROMIUM_PATH = process.env.E2E_CHROMIUM_PATH || '/usr/bin/chromium';

// Require APP_URL to be set explicitly — no default fallback.
// Callers must provide APP_URL in their environment or CI workflow.
export function requireAppUrl() {
  if (!process.env.APP_URL) {
    throw new Error(
      'APP_URL is not set. Set it to the URL of the deployed app or ' +
      'a local server (e.g. APP_URL=http://localhost:8080).'
    );
  }
  return process.env.APP_URL;
}
