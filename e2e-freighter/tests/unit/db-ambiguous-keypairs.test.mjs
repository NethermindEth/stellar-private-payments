// Coverage for the ambiguous-keypairs recovery modal.
//
// db-ambiguous-keypairs.js takes `diagnose` as an injected dependency
// precisely so it (and its wiring into navigation.js/admin.js/disclosure.js)
// can be checked here without loading wasm-facade.js, which imports the wasm
// package and cannot be loaded under plain `node --test` -- the same
// constraint documented in pool-ops.test.mjs and account-session-guard.test.mjs.

import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
    AMBIGUOUS_KEYPAIRS_CODE,
    isAmbiguousKeypairsError,
    showAmbiguousKeypairsModal,
} from '../../../app/js/db-ambiguous-keypairs.js';

const repoFile = (rel) => fileURLToPath(new URL(`../../../${rel}`, import.meta.url));

test('isAmbiguousKeypairsError matches on the stable code, not on message wording', () => {
    assert.equal(
        isAmbiguousKeypairsError(`This wallet's local database holds two different sets... (code: ${AMBIGUOUS_KEYPAIRS_CODE})`),
        true,
    );
});

test('isAmbiguousKeypairsError does not match the sibling migration-failed code', () => {
    assert.equal(isAmbiguousKeypairsError('Couldn\'t open your local wallet database. (code: db-migration-failed)'), false);
});

for (const [label, value] of [
    ['undefined', undefined],
    ['null', null],
    ['a number', 7],
]) {
    test(`isAmbiguousKeypairsError refuses non-string input (${label})`, () => {
        assert.equal(isAmbiguousKeypairsError(value), false);
    });
}

test('showAmbiguousKeypairsModal does not throw, and never calls diagnose, outside a DOM environment', () => {
    let called = false;
    assert.doesNotThrow(() => showAmbiguousKeypairsModal('anything', {
        accountAddress: 'GTEST',
        diagnose: async () => { called = true; },
    }));
    assert.equal(called, false, 'without a DOM there is no button to click, so diagnose must not run');
});

// --- wiring: each call site passes diagnoseAmbiguousKeypairs and a real address ---

for (const [file, importsLine] of [
    ['app/js/ui/navigation.js', /isAmbiguousKeypairsError.*from '\.\.\/db-ambiguous-keypairs\.js'/],
    ['app/js/admin.js', /isAmbiguousKeypairsError.*from '\.\/db-ambiguous-keypairs\.js'/],
    ['app/js/disclosure.js', /isAmbiguousKeypairsError.*from '\.\/db-ambiguous-keypairs\.js'/],
]) {
    test(`${file} imports the ambiguous-keypairs modal helpers`, () => {
        const source = readFileSync(repoFile(file), 'utf8');
        assert.match(source, importsLine);
        assert.match(source, /showAmbiguousKeypairsModal\(/);
        assert.match(source, /diagnose:\s*diagnoseAmbiguousKeypairs/, 'the diagnose function must be wired through, not a stub');
    });
}

test('navigation.js captures the address before disconnect() clears it', () => {
    // disconnect() sets App.state.wallet.address = null (see its own body),
    // so the catch block must read it into a local first, or the modal would
    // always be built with a null address.
    const source = readFileSync(repoFile('app/js/ui/navigation.js'), 'utf8');
    const captureLine = source.indexOf('const failedAddress = App.state.wallet.address;');
    assert.notEqual(captureLine, -1, 'the address must be captured into a local before teardown');

    const disconnectCall = source.indexOf('this.disconnect();', captureLine);
    assert.notEqual(disconnectCall, -1);

    const modalCall = source.indexOf('showAmbiguousKeypairsModal(', captureLine);
    assert.notEqual(modalCall, -1);

    assert.ok(
        captureLine < disconnectCall && disconnectCall < modalCall,
        'address must be read before disconnect(), and the modal built after both',
    );

    const usesCapture = source.slice(modalCall, modalCall + 200).includes('accountAddress: failedAddress');
    assert.ok(usesCapture, 'the modal must be given the captured address, not App.state.wallet.address post-teardown');
});
