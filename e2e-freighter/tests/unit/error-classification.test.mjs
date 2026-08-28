// Coverage for structured-code error classification: a signer-identity
// mismatch must never be misread as a user cancellation, a wallet-superseded
// session must get friendly text instead of an internal sentence, and once
// an error carries a code at all, message-substring matching must not run.

import assert from 'node:assert/strict';
import test from 'node:test';

import { isUserCancelledError, getFriendlyErrorMessage } from '../../../app/js/ui/errors.js';
import { friendlyErrorMessage, friendlyErrorForCode } from '../../../app/js/facade-errors.js';

// --- isUserCancelledError: code is authoritative once present -------------

test('isUserCancelledError recognizes the SEP-0043 numeric code', () => {
    assert.equal(isUserCancelledError({ code: -4, message: 'declined' }), true);
});

test('isUserCancelledError recognizes the USER_REJECTED string code', () => {
    assert.equal(isUserCancelledError({ code: 'USER_REJECTED', message: 'declined' }), true);
});

test('a SIGNER_ADDRESS_MISMATCH error is never classified as cancelled, even if its message contains rejection wording', () => {
    // The regression this guards: requested/actual addresses are untrusted,
    // wallet-controlled text, and could contain a substring like "rejected".
    // Once a non-cancellation code is present it must settle the question --
    // the message must not be consulted at all.
    const error = {
        code: 'SIGNER_ADDRESS_MISMATCH',
        message: 'wallet signed with GUSER_REJECTEDXYZ, but GEXPECTED was requested',
    };
    assert.equal(isUserCancelledError(error), false);
});

test('isUserCancelledError falls back to message substrings only when no code is present', () => {
    assert.equal(isUserCancelledError({ message: 'User rejected the request' }), true);
    assert.equal(isUserCancelledError({ message: 'network timeout' }), false);
});

test('isUserCancelledError treats a null or undefined code as absent, not as a fourth code value', () => {
    assert.equal(isUserCancelledError({ code: null, message: 'user rejected' }), true);
    assert.equal(isUserCancelledError({ code: undefined, message: 'user rejected' }), true);
});

// --- getFriendlyErrorMessage: SIGNER_ADDRESS_MISMATCH gets friendly, --------
// non-cancellation handling and never echoes the raw message -----------------

test('getFriendlyErrorMessage gives SIGNER_ADDRESS_MISMATCH its own friendly text', () => {
    const error = {
        code: 'SIGNER_ADDRESS_MISMATCH',
        message: 'wallet signed with GACTUAL, but GREQUESTED was requested',
    };
    const friendly = getFriendlyErrorMessage(error);
    assert.notEqual(friendly, 'Transaction was cancelled.', 'must not be classified as a cancellation');
    assert.ok(!friendly.includes('GACTUAL') && !friendly.includes('GREQUESTED'), 'must not echo the raw addresses');
    assert.match(friendly, /different account/i);
});

// --- facade-errors: friendlyErrorForCode ------------------------------------

test('friendlyErrorForCode passes a plain string through friendlyErrorMessage unchanged', () => {
    assert.equal(friendlyErrorForCode('Runtime not initialized'), friendlyErrorMessage('Runtime not initialized'));
    assert.equal(friendlyErrorForCode('some unrelated error'), 'some unrelated error');
});

test('friendlyErrorForCode maps SESSION_SUPERSEDED by code, not message text', () => {
    const error = { code: 'SESSION_SUPERSEDED', message: 'Account session superseded: another account was opened while this one was still opening.' };
    const friendly = friendlyErrorForCode(error);
    assert.notEqual(friendly, error.message, 'the internal sentence must not reach the user verbatim');
    assert.match(friendly, /already in progress|try again/i);
});

test('friendlyErrorForCode falls back to message-pattern matching when the code is unrecognized', () => {
    const error = { code: 'SOME_OTHER_CODE', message: 'Storage not ready' };
    assert.equal(friendlyErrorForCode(error), friendlyErrorMessage('Storage not ready'));
});

test('friendlyErrorForCode falls back to message-pattern matching when there is no code at all', () => {
    const error = { message: 'Account session not open' };
    assert.equal(friendlyErrorForCode(error), friendlyErrorMessage('Account session not open'));
});
