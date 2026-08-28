// Coverage for the "local database could not be opened" modal.
//
// The Rust storage worker keeps its user-facing message short and stamps it
// with a stable code (see MigrationFailedError/AmbiguousKeypairsError in
// sdk/native/src/state/storage.rs) instead of embedding the raw, potentially
// SQL-bearing error text -- detection here matches on that code, not on
// message content.
//
// navigation.js imports wasm-facade.js, which imports the wasm package and
// cannot be loaded under plain `node --test`, so its wiring is asserted over
// source text the same way pool-ops.test.mjs checks the pool-op wrapping.

import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
    DB_MIGRATION_FAILED_CODE,
    isDbMigrationFailedError,
    showDbMigrationFailedModal,
} from '../../../app/js/db-migration-failed.js';

const repoFile = (rel) => fileURLToPath(new URL(`../../../${rel}`, import.meta.url));

test('isDbMigrationFailedError matches on the stable code, not on message wording', () => {
    assert.equal(
        isDbMigrationFailedError(`Couldn't open your local wallet database. (code: ${DB_MIGRATION_FAILED_CODE})`),
        true,
    );
});

test('isDbMigrationFailedError does not match unrelated messages', () => {
    assert.equal(isDbMigrationFailedError('Failed to fetch'), false);
    assert.equal(isDbMigrationFailedError("Another tab or window is using this app's local database"), false);
});

for (const [label, value] of [
    ['undefined', undefined],
    ['null', null],
    ['a number', 42],
    ['an object', { message: DB_MIGRATION_FAILED_CODE }],
]) {
    test(`isDbMigrationFailedError refuses non-string input (${label})`, () => {
        assert.equal(isDbMigrationFailedError(value), false);
    });
}

test('showDbMigrationFailedModal does not throw outside a DOM environment', () => {
    assert.doesNotThrow(() => showDbMigrationFailedModal('anything'));
});

// --- the auto-connect path surfaces this modal, not only the interactive one --

const NAVIGATION = readFileSync(repoFile('app/js/ui/navigation.js'), 'utf8');

test('navigation.js imports the migration-failed modal helpers', () => {
    assert.match(NAVIGATION, /isDbMigrationFailedError/);
    assert.match(NAVIGATION, /showDbMigrationFailedModal/);
});

test('a migration-failed connect error shows the modal even when auto is true', () => {
    // db-locked's own branch shows on auto-connect deliberately (a comment
    // says so); the migration-failed branch must sit alongside it, ahead of
    // the `!auto` gate that suppresses the fallback toast on auto-connect --
    // otherwise the failure is silently swallowed on the common trigger path.
    const dbLockedBranch = NAVIGATION.indexOf('isDbLockedError(message)');
    assert.notEqual(dbLockedBranch, -1, 'the db-locked branch must still exist');

    const migrationBranch = NAVIGATION.indexOf('isDbMigrationFailedError(message)');
    assert.notEqual(migrationBranch, -1, 'the migration-failed branch must exist');

    const autoGate = NAVIGATION.indexOf('} else if (!auto)', migrationBranch);
    assert.notEqual(autoGate, -1, 'the auto-suppressed toast fallback must still exist');

    assert.ok(
        dbLockedBranch < migrationBranch && migrationBranch < autoGate,
        'the migration-failed branch must be checked before the branch that ' +
        'suppresses the toast on auto-connect, so a migration failure is never ' +
        'silently swallowed on that path',
    );

    const showCall = NAVIGATION.indexOf('showDbMigrationFailedModal(message)', migrationBranch);
    assert.ok(
        showCall !== -1 && showCall < autoGate,
        'the migration-failed branch must actually show the modal, not just detect the error',
    );
});
