#!/usr/bin/env node
/**
 * Verify wasm-bindgen artifacts exist before `tsc` (CI / prepublish).
 */
import { access } from 'node:fs/promises';
import { constants } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.dirname(fileURLToPath(import.meta.url));
const required = [
  'dist/stellar_private_payments_sdk_web.js',
  'dist/stellar_private_payments_sdk_web_bg.wasm',
  'dist/stellar_private_payments_sdk_web.d.ts',
  'dist/workers/storage-worker.js',
  'dist/workers/prover-worker.js',
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
