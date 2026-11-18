import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import test from 'node:test';

const envUrl = new URL('../../src/env.mjs', import.meta.url).href;
const redactUrl = new URL('../../src/redact.mjs', import.meta.url).href;

function run(source, passwords = {}) {
  const env = { ...process.env };
  delete env.E2E_VARIAL_PASSWORD;
  return execFileSync(process.execPath, ['--input-type=module', '-e', source], {
    env: { ...env, ...passwords }, encoding: 'utf8',
  }).trim();
}

const readPassword = `await import(${JSON.stringify(envUrl)}); process.stdout.write(process.env.E2E_VARIAL_PASSWORD);`;

test('wallet password has a fixed default', () => {
  assert.equal(run(readPassword), 'SppE2eVarial1!');
});

test('wallet password honours an explicit override', () => {
  assert.equal(run(readPassword, { E2E_VARIAL_PASSWORD: 'current' }), 'current');
});

test('logs redact the wallet password, including short overrides', () => {
  const source = `const { scrub } = await import(${JSON.stringify(redactUrl)});
    process.stdout.write(scrub('pw=current; current'));`;
  assert.equal(run(source, { E2E_VARIAL_PASSWORD: 'current' }), 'pw=[REDACTED]; [REDACTED]');
});
