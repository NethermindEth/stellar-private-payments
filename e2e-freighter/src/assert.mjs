// Shared assert utility for e2e-freighter tests.

import { scrub } from './redact.mjs';

export function assert(condition, message) {
  if (!condition) {
    console.error('FAIL:', scrub(message));
    throw new Error(scrub(message));
  }
}
