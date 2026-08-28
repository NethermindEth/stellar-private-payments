// The published wrapper, its type declaration, and the README must all expose
// the same Client surface. A method dropped from any one of them is invisible
// to consumers even though the wasm build still has it.
//
// index.js imports ../dist/, a build artifact that need not exist here, so the
// wrapper is asserted over source text -- the same approach pool-ops.test.mjs
// uses for modules that cannot be loaded under plain `node --test`.

import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { CLIENT_METHODS } from '../../../sdk/web/js/client-contract.js';

const repoFile = (rel) => fileURLToPath(new URL(`../../../${rel}`, import.meta.url));
const INDEX_JS = readFileSync(repoFile('sdk/web/js/index.js'), 'utf8');
const INDEX_DTS = readFileSync(repoFile('sdk/web/js/types/index.d.ts'), 'utf8');
const README = readFileSync(repoFile('sdk/web/README.md'), 'utf8');

test('published client contract includes storage-session release', () => {
    assert.ok(CLIENT_METHODS.includes('releaseStorageSession'));
});

/** Body of `function wrapClient(...) { return { ... }; }` in index.js. */
function wrapClientBody() {
    const start = INDEX_JS.indexOf('function wrapClient(');
    assert.notEqual(start, -1, 'index.js must still define wrapClient');
    const end = INDEX_JS.indexOf('\n}', start);
    assert.notEqual(end, -1);
    return INDEX_JS.slice(start, end);
}

/** Body of `export interface Client { ... }` in index.d.ts. */
function clientInterfaceBody() {
    const start = INDEX_DTS.indexOf('export interface Client {');
    assert.notEqual(start, -1, 'index.d.ts must still declare the Client interface');
    const end = INDEX_DTS.indexOf('\n}', start);
    assert.notEqual(end, -1);
    return INDEX_DTS.slice(start, end);
}

test('wrapClient forwards every method in the published contract', () => {
    const body = wrapClientBody();
    for (const method of CLIENT_METHODS) {
        assert.match(
            body,
            new RegExp(`\\b${method}\\s*:`),
            `wrapClient drops ${method}, so consumers of the package entry cannot reach it`,
        );
    }
});

test('the Client type declares every method in the published contract', () => {
    const body = clientInterfaceBody();
    for (const method of CLIENT_METHODS) {
        assert.match(
            body,
            new RegExp(`\\b${method}\\s*\\(`),
            `index.d.ts omits ${method}, so TypeScript consumers see a compile error on a real method`,
        );
    }
});

test('the wrapper exposes nothing the contract does not name', () => {
    // Keys of the object literal wrapClient returns, minus nested option keys.
    const declared = new Set(CLIENT_METHODS);
    const keys = [...wrapClientBody().matchAll(/^\s{4}(\w+)\s*:/gm)].map((m) => m[1]);
    assert.ok(keys.length > 0, 'expected to find wrapper keys');
    for (const key of keys) {
        assert.ok(
            declared.has(key),
            `wrapClient exposes ${key}, which client-contract.js does not list -- ` +
            'the contract is what the forwarding tests and facade checks read',
        );
    }
});

test('every contract method is documented in the README Client table', () => {
    for (const method of CLIENT_METHODS) {
        assert.ok(
            README.includes(`\`${method}(`),
            `README does not document ${method}`,
        );
    }
});

// Release metadata (version, changelog) is deliberately not asserted here:
// the migration write-up for the breaking object-only signer contract lives
// outside the repo, and the version bump is a separate, user-authorized
// release action -- nothing in-repo to check either against.
