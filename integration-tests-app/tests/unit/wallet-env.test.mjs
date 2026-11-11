import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import test from 'node:test';

const envUrl = new URL('../../src/env.mjs', import.meta.url).href;
const redactUrl = new URL('../../src/redact.mjs', import.meta.url).href;

function run(source, passwords = {}) {
  const env = { ...process.env };
  delete env.E2E_VARIAL_PASSWORD;
  delete env.E2E_FREIGHTER_PASSWORD;
  return execFileSync(process.execPath, ['--input-type=module', '-e', source], {
    env: { ...env, ...passwords }, encoding: 'utf8',
  }).trim();
}

const readPassword = `await import(${JSON.stringify(envUrl)}); process.stdout.write(process.env.E2E_VARIAL_PASSWORD);`;

test('wallet password preserves the existing profile default', () => {
  assert.equal(run(readPassword), 'SppE2eFreighter1!');
});

test('wallet password accepts the legacy name and prefers the new name', () => {
  assert.equal(run(readPassword, { E2E_FREIGHTER_PASSWORD: 'legacy' }), 'legacy');
  assert.equal(run(readPassword, {
    E2E_FREIGHTER_PASSWORD: 'legacy', E2E_VARIAL_PASSWORD: 'current',
  }), 'current');
});

test('logs redact both password names, including short overrides', () => {
  const source = `const { scrub } = await import(${JSON.stringify(redactUrl)});
    process.stdout.write(scrub('old=legacy; new=current; legacy'));`;
  assert.equal(run(source, {
    E2E_FREIGHTER_PASSWORD: 'legacy', E2E_VARIAL_PASSWORD: 'current',
  }), 'old=[REDACTED]; new=[REDACTED]; [REDACTED]');
});
