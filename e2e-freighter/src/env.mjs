// Shared env bootstrap for the standalone scripts (scripts/*.mjs run via
// node directly): loads deployments/testnet/.e2e-accounts.env when the
// variables are not already exported, so scripts work from any shell with
// no manual sourcing. Explicit environment always wins — a variable that
// is already set is never overwritten. The file is git-ignored, mode 600.
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const ENV_FILE = path.join(REPO_ROOT, 'deployments/testnet/.e2e-accounts.env');

if (!process.env.E2E_FREIGHTER_PASSWORD && existsSync(ENV_FILE)) {
  for (const line of readFileSync(ENV_FILE, 'utf8').split('\n')) {
    const match = /^([A-Z0-9_]+)=(.*)$/.exec(line.trim());
    if (match && process.env[match[1]] === undefined) {
      process.env[match[1]] = match[2];
    }
  }
}

// Require APP_URL to be set explicitly — no default fallback.
// Callers must provide APP_URL in their environment or CI workflow.
export function requireAppUrl() {
  if (!process.env.APP_URL) {
    throw new Error(
      'APP_URL is not set. Set it to the URL of the deployed app or ' +
      'a local server (e.g. APP_URL=http://localhost:8000).'
    );
  }
  return process.env.APP_URL;
}
