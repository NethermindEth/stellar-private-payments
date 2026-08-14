// Shared assert utility for e2e-freighter tests.
// Each test previously defined its own inline assert that used log.error.
// This version uses console.error (same stderr output) and keeps the
// same throw-on-failure pattern.

import { scrub } from './redact.mjs';

export function assert(condition, message) {
  if (!condition) {
    console.error('FAIL:', scrub(message));
    throw new Error(scrub(message));
  }
}