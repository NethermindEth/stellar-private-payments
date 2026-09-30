// Shared assert utility for integration-tests-app tests.

import { scrub } from './redact.mjs';

export function assert(condition, message) {
  if (!condition) {
    console.error('FAIL:', scrub(message));
    throw new Error(scrub(message));
  }
}
