// Shared assert utility for e2e-freighter tests.
// Each test previously defined its own inline assert that used log.error.
// This version uses console.error (same stderr output) and keeps the
// same throw-on-failure pattern.

export function assert(condition, message) {
  if (!condition) {
    console.error('FAIL:', message);
    throw new Error(message);
  }
}