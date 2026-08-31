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
  'dist/stellar_private_payments_web.js',
  'dist/stellar_private_payments_web_bg.wasm',
  'dist/stellar_private_payments_web.d.ts',
  'dist/workers/storage-worker.js',
  'dist/workers/prover-worker.js',
  'dist/circuits/policy_tx_2_2.graph.bin',
  'dist/circuits/policy_tx_2_2.r1cs',
  'dist/circuits/policy_tx_2_2_proving_key.bin',
  'dist/circuits/policy_tx_2_2_A.graph.bin',
  'dist/circuits/policy_tx_2_2_A.r1cs',
  'dist/circuits/policy_tx_2_2_A_proving_key.bin',
  'dist/circuits/policy_tx_2_2_B.graph.bin',
  'dist/circuits/policy_tx_2_2_B.r1cs',
  'dist/circuits/policy_tx_2_2_B_proving_key.bin',
  'dist/circuits/policy_tx_2_2_AB.graph.bin',
  'dist/circuits/policy_tx_2_2_AB.r1cs',
  'dist/circuits/policy_tx_2_2_AB_proving_key.bin',
  'dist/circuits/selectiveDisclosure_1.graph.bin',
  'dist/circuits/selectiveDisclosure_1.r1cs',
  'dist/circuits/selectiveDisclosure_1_proving_key.bin',
  'dist/circuits/selectiveDisclosure_2.graph.bin',
  'dist/circuits/selectiveDisclosure_2.r1cs',
  'dist/circuits/selectiveDisclosure_2_proving_key.bin',
  'dist/circuits/selectiveDisclosure_3.graph.bin',
  'dist/circuits/selectiveDisclosure_3.r1cs',
  'dist/circuits/selectiveDisclosure_3_proving_key.bin',
  'dist/circuits/selectiveDisclosure_4.graph.bin',
  'dist/circuits/selectiveDisclosure_4.r1cs',
  'dist/circuits/selectiveDisclosure_4_proving_key.bin',
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
