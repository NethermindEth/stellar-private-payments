#!/usr/bin/env node
/**
 * Verify wasm-bindgen artifacts exist and that the shipped circuit wasm files
 * match the hashes baked into the compiled sdk-web code.
 */
import { access, readFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.dirname(fileURLToPath(import.meta.url));
const required = [
  'dist/stellar_private_payments_sdk_web.js',
  'dist/stellar_private_payments_sdk_web_bg.wasm',
  'dist/stellar_private_payments_sdk_web.d.ts',
  'dist/workers/storage-worker.js',
  'dist/workers/prover-worker.js',
  'dist/circuits/policy_tx_2_2.wasm',
  'dist/circuits/policy_tx_2_2.r1cs',
  'dist/circuits/policy_tx_2_2_A.wasm',
  'dist/circuits/policy_tx_2_2_A.r1cs',
  'dist/circuits/policy_tx_2_2_B.wasm',
  'dist/circuits/policy_tx_2_2_B.r1cs',
  'dist/circuits/policy_tx_2_2_AB.wasm',
  'dist/circuits/policy_tx_2_2_AB.r1cs',
  'dist/circuits/selectiveDisclosure_1.wasm',
  'dist/circuits/selectiveDisclosure_1.r1cs',
  'dist/circuits/selectiveDisclosure_2.wasm',
  'dist/circuits/selectiveDisclosure_2.r1cs',
  'dist/circuits/selectiveDisclosure_3.wasm',
  'dist/circuits/selectiveDisclosure_3.r1cs',
  'dist/circuits/selectiveDisclosure_4.wasm',
  'dist/circuits/selectiveDisclosure_4.r1cs',
  'dist/circuits/NOTICE.txt',
  'dist/circuits/source-bundle.tar.gz',
  'dist/licenses/LGPL-3.0.txt',
  'dist/licenses/GPL-3.0.txt',
];

for (const rel of required) {
  const file = path.join(root, '..', rel);
  try {
    await access(file, constants.R_OK);
  } catch {
    console.error(`missing ${rel} — run npm run build`);
    process.exit(1);
  }
}

const sidecarPath = path.join(root, '..', 'dist/circuits/artifact_hashes.json');
let expectedHashes;
try {
  expectedHashes = JSON.parse(await readFile(sidecarPath, 'utf8'));
} catch {
  console.error('missing dist/circuits/artifact_hashes.json — run npm run build');
  process.exit(1);
}

for (const [stem, expectedHex] of Object.entries(expectedHashes)) {
  const wasmPath = path.join(root, '..', 'dist/circuits', `${stem}.wasm`);
  const bytes = await readFile(wasmPath);
  const actualHex = createHash('sha256').update(bytes).digest('hex');
  if (actualHex !== expectedHex) {
    console.error(
      `sha256 mismatch for dist/circuits/${stem}.wasm: expected ${expectedHex}, got ${actualHex}`
    );
    process.exit(1);
  }
}

console.log('sdk/web artifact checks passed');
