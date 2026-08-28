import assert from 'node:assert/strict';
import test from 'node:test';
import { CLIENT_METHODS } from '../../../sdk/web/js/client-contract.js';

test('published client contract includes storage-session release', () => {
  assert.ok(CLIENT_METHODS.includes('releaseStorageSession'));
});
