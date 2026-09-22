#!/usr/bin/env node
/** Verify the encryption-enabled npm package without running lifecycle scripts. */
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const web = resolve(fileURLToPath(new URL('..', import.meta.url)));
const root = resolve(web, '../..');
const required = new Set([
  'package.json', 'js/index.js', 'js/types/api-types.d.ts',
  'js/key-vault.js', 'js/types/key-vault.d.ts',
  'dist/stellar_private_payments_web.js', 'dist/stellar_private_payments_web_bg.wasm',
  'dist/workers/storage-worker-module.js', 'dist/workers/storage-worker-module_bg.wasm',
  'dist/licenses/SQLite3MC.txt', 'dist/licenses/sqlite-wasm-vfs-LICENSE.txt',
  'dist/circuits/NOTICE.txt', 'dist/circuits/source-bundle.tar.gz',
]);
const notice = readFileSync(join(root, 'vendor/sqlite3mc-NOTICE.txt'));
const vfsNotice = readFileSync(join(root, 'vendor/sqlite-wasm-vfs/LICENSE'));

function npmPack(...args) {
  const result = JSON.parse(execFileSync('npm', ['pack', '--ignore-scripts', '--json', ...args], {
    cwd: web, encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'],
  }));
  const packages = Array.isArray(result) ? result : Object.values(result);
  if (packages.length !== 1 || !packages[0]?.filename || !Array.isArray(packages[0]?.files)) {
    throw new Error('expected exactly one npm package result');
  }
  return packages[0];
}

function verifyNames(names) {
  for (const name of required) if (!names.has(name)) throw new Error(`package is missing ${name}`);
  for (const name of names) {
    if (isAbsolute(name) || name.split('/').includes('..') || name.includes('test-sqlite3mc') || name.startsWith('scripts/')) {
      throw new Error(`unexpected package entry: ${name}`);
    }
  }
}

function verify(read) {
  if (!read('dist/licenses/SQLite3MC.txt').equals(notice)) throw new Error('SQLite3MC notice differs from reviewed notice');
  if (!read('dist/licenses/sqlite-wasm-vfs-LICENSE.txt').equals(vfsNotice)) throw new Error('VFS notice differs from reviewed notice');
  const bindings = read('dist/stellar_private_payments_web.js').toString();
  for (const method of ['static openEncrypted(', 'static openMigration(', 'migrationAction(']) {
    if (!bindings.includes(method)) throw new Error(`WASM bindings lack ${method}`);
  }
  if (!read('js/index.js').toString().includes('recoverMigrationSetup')) throw new Error('JavaScript facade lacks initialization recovery');
  for (const name of ['dist/stellar_private_payments_web_bg.wasm', 'dist/workers/storage-worker-module_bg.wasm']) {
    if (!read(name).subarray(0, 4).equals(Buffer.from([0, 97, 115, 109]))) throw new Error(`invalid WASM artifact: ${name}`);
  }
}

const outputIndex = process.argv.indexOf('--output-directory');
const dryRun = npmPack('--dry-run');
const names = new Set(dryRun.files.map(({ path }) => path));
verifyNames(names);
verify((name) => readFileSync(join(web, name)));
const report = { passed: true, mode: 'dry-run', files: names.size };

if (outputIndex !== -1) {
  const output = resolve(process.argv[outputIndex + 1] ?? '');
  if (!process.argv[outputIndex + 1]) throw new Error('--output-directory needs a path');
  mkdirSync(output, { recursive: true });
  const packed = npmPack('--pack-destination', output);
  if (basename(packed.filename) !== packed.filename) throw new Error('npm returned an invalid package filename');
  const archive = join(output, packed.filename);
  const entries = execFileSync('tar', ['-tzf', archive], { encoding: 'utf8' }).trim().split('\n');
  if (entries.some((name) => !name.startsWith('package/') || name.endsWith('/'))) throw new Error('unexpected npm archive member');
  const archiveNames = new Set(entries.map((name) => name.slice('package/'.length)));
  verifyNames(archiveNames);
  verify((name) => execFileSync('tar', ['-xOzf', archive, `package/${name}`], { maxBuffer: 16 * 1024 * 1024 }));
  Object.assign(report, {
    mode: 'archive', archive: packed.filename,
    sha256: createHash('sha256').update(readFileSync(archive)).digest('hex'),
  });
  writeFileSync(join(output, 'verification.json'), `${JSON.stringify(report, null, 2)}\n`);
}
console.log(JSON.stringify(report, null, 2));
