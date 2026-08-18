// Demonstrates indexer and navigation helpers without submitting a transaction.
// It is not part of numbered scenario discovery.

import { createLogger } from '../src/logger.mjs';
import { waitForIndexerProgress, waitForSyncedLedger } from '../src/indexer.mjs';
import {
  gotoAdvanced,
  gotoDashboard,
  gotoDisclosure,
  gotoMoveFunds,
} from '../src/navigation.mjs';

const log = createLogger('demo');

const VIEWS = [
  { name: 'dashboard', goto: gotoDashboard },
  { name: 'move-funds', goto: gotoMoveFunds },
  { name: 'advanced', goto: gotoAdvanced },
  { name: 'disclosure', goto: gotoDisclosure },
];

export async function run({ page }) {
  log.info('waiting for first indexer sync log...');
  const first = await waitForSyncedLedger(page);
  log.info(`synced ledger (1st): ${first.ledger}`);

  log.info('waiting for next ledger...');
  const next = await waitForIndexerProgress(page, { after: first.ledger });
  log.info(`synced ledger (next): ${next.ledger}`);

  for (const view of VIEWS) {
    const result = await view.goto(page);
    log.info(`view '${view.name}' became active after ${result.elapsedMs}ms`);
  }
}
