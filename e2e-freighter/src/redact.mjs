// Redact known secrets from any string before it hits a log line.
//
// CodeQL flags clear-text logging of process-environment data
// (js/clear-text-logging): the e2e suite's secrets (E2E_FREIGHTER_PASSWORD,
// E2E_ACCOUNT_*_SECRET) are read from the environment and could otherwise
// surface inside error messages (e.g. a thrown Error whose message embeds an
// env value). scrub() replaces every known secret value with [REDACTED] so
// assert/error logging can never echo one, whether in CI logs or on a
// developer's machine.
//
// Secrets are discovered lazily and cached: the env file is loaded once by
// env.mjs before any call site runs, so the values are already in
// process.env by the time scrub() is first used. Only values that are
// actually set contribute, so a missing var is not a problem.
import { readFileSync, existsSync } from 'node:fs';

const SECRET_ENV_KEYS = [
  'E2E_FREIGHTER_PASSWORD',
  'E2E_ACCOUNT_A_SECRET',
  'E2E_ACCOUNT_B_SECRET',
  'E2E_ACCOUNT_C_SECRET',
  'E2E_ACCOUNT_D_SECRET',
];

let cached = null;

function secrets() {
  if (cached !== null) return cached;
  const values = [];
  for (const key of SECRET_ENV_KEYS) {
    const v = process.env[key];
    if (v && v.length >= 8 && !values.includes(v)) values.push(v);
  }
  // Belt and braces: also read the env file directly, so a secret that is
  // set there but not yet exported (e.g. a script that never imports
  // env.mjs) is still covered.
  const envFile = new URL('../../deployments/testnet/.e2e-accounts.env', import.meta.url);
  if (existsSync(envFile)) {
    for (const line of readFileSync(envFile, 'utf8').split('\n')) {
      const match = /^(E2E_(?:FREIGHTER_PASSWORD|ACCOUNT_[A-D]_SECRET))=(.*)$/.exec(line.trim());
      if (match && match[2] && match[2].length >= 8 && !values.includes(match[2])) {
        values.push(match[2]);
      }
    }
  }
  cached = values;
  return cached;
}

// Replace every known secret in `text` with [REDACTED]. Non-strings pass
// through unchanged (callers may log err.message, which is always a string).
export function scrub(text) {
  if (typeof text !== 'string') return text;
  let out = text;
  for (const value of secrets()) {
    out = out.split(value).join('[REDACTED]');
  }
  return out;
}
