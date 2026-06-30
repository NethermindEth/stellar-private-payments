#!/usr/bin/env node
/**
 * Verify wasm-bindgen artifacts exist after build.
 * Extend later to assert wasm .d.ts exports match js/types/wasm.d.ts.
 */
import { access } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const required = [
  'dist/private_payments_web.js',
  'dist/private_payments_web.wasm',
  'dist/private_payments_web.d.ts',
  'dist/workers/storage-worker.js',
  'dist/workers/prover-worker.js',
];

let failed = false;
for (const rel of required) {
  try {
    await access(join(root, rel));
  } catch {
    console.error(`missing ${rel} — run: npm run build`);
    failed = true;
  }
}

if (failed) {
  process.exit(1);
}

console.log('wasm artifacts present');
