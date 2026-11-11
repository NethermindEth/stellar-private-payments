import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

// ' ', not '': the text around a removed comment can't join into a new "<!--".
const html = (await readFile(new URL('../../../app/admin.html', import.meta.url), 'utf8'))
  .replace(/<!--[\s\S]*?-->/g, ' ');

test('the admin policy allows each inline script by its hash', () => {
  const policy = html.match(/<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]*)"\s*\/>/)?.[1];
  assert.ok(policy, 'admin.html has no Content-Security-Policy meta tag');
  const listed = policy.match(/script-src ([^;]*)/)[1].split(' ').filter((s) => s.startsWith("'sha256-"));
  const inline = Array.from(html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g),
    ([, body]) => `'sha256-${createHash('sha256').update(body).digest('base64')}'`);
  assert.deepEqual(listed, inline);
});
