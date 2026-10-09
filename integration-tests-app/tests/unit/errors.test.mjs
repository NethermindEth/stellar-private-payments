import assert from 'node:assert/strict';
import test from 'node:test';

import { getFriendlyErrorMessage } from '../../../app/js/ui/errors.js';

test('a pool re-pointed to an allowlist the manifest does not name asks for a reload', () => {
  const unnamed =
    'fetch chain context: pool CPOOL reads the allowlist CTREE, which the deployment manifest ' +
    'does not name: add it to added_asp_memberships with its deployment ledger';
  assert.equal(
    getFriendlyErrorMessage(new Error(unnamed), 'Withdraw'),
    'This pool now uses an allowlist this version of the app does not know. Reload the page. If that does not help, the operator has not published the updated deployment yet.',
  );
});
