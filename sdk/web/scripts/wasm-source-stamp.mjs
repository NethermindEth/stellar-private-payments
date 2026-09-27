/** Content-based Trunk build gate. Generated output and timestamps are excluded. */
import { createHash } from 'node:crypto';
import { readFile, readdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
const root = new URL('../../../', import.meta.url).pathname;
const inputs = [
    'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'contracts', 'sdk/native/Cargo.toml', 'sdk/native/build.rs',
    'sdk/native/sqlite3mc_source.rs', 'sdk/native/sqlite3mc_version.rs', 'sdk/web/Cargo.toml', 'sdk/web/scripts/build.sh',
    'sdk/native/src', 'sdk/web/src', 'circuits/src', 'circuits/Cargo.toml',
    'circuit-keys/src', 'circuit-keys/Cargo.toml', 'tools/sqlite3mc-build',
    'vendor/sqlite-wasm-vfs/src', 'vendor/sqlite-wasm-vfs/Cargo.toml',
    'sdk/web/scripts/wasm-source-stamp.mjs',
];
const hash = createHash('sha256');
async function visit(path) {
    let entries;
    try { entries = await readdir(resolve(root, path), { withFileTypes: true }); }
    catch (error) {
        if (error.code !== 'ENOTDIR') throw error;
        hash.update(path + '\0'); hash.update(await readFile(resolve(root, path))); hash.update('\0');
        return;
    }
    for (const entry of entries.sort((a,b) => a.name.localeCompare(b.name))) await visit(`${path}/${entry.name}`);
}
for (const path of inputs) await visit(path);
const digest = hash.digest('hex');
const stamp = resolve(root, 'sdk/web/dist/source.sha256');
if (process.argv[2] === '--print') console.log(digest);
else if (process.argv[2] === '--write') await writeFile(stamp, digest + '\n');
else if (process.argv[2] === '--check') {
    const previous = await readFile(stamp, 'utf8').catch(() => '');
    if (previous.trim() !== digest) process.exitCode = 1;
} else throw Error('expected --check, --print or --write');
