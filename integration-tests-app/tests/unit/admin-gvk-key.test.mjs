import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

test('Sync & Audit takes the authority key and clears its field before any await', async () => {
  const src = await readFile(new URL('../../../app/js/admin-gvk.js', import.meta.url), 'utf8');
  assert.match(src, /\n  auditBtnEl\?\.addEventListener\('click', async \(\) => \{\n    const privateKey = privateKeyEl\.value\.trim\(\);\n    privateKeyEl\.value = '';\n/);
  assert.equal(src.match(/privateKeyEl\??\.value/g).length, 2);
});
