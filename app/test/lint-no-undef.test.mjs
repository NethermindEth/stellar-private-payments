import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import test from 'node:test';

const exec = promisify(execFile);
const appRoot = fileURLToPath(new URL('..', import.meta.url));

test('no-undef lint rejects a free identifier', async () => {
  const dir = await mkdtemp(join(appRoot, 'test/lint-fixture-'));
  const file = join(dir, 'fixture.js');
  try {
    await writeFile(file, 'export const value = deliberatelyMissing;\n');
    await assert.rejects(
      exec(join(appRoot, 'node_modules/.bin/eslint'), ['--no-ignore', '--config', join(appRoot, 'eslint.config.js'), file]),
      (error) => error.code === 1,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
