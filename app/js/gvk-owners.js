import { normalizeFieldKey } from './gvk-notes.js';

/**
 * Registry owners of GVK-audited note keys, as a map from normalized PK to
 * its registering addresses. A PK stays pending (absent) until a lookup
 * against a fully synced registry answers for it: before that a later
 * registration can still add an address, so pending addresses stay hidden.
 */
export function createOwnerBook() {
  return new Map();
}

/** 'pending', 'unregistered' or 'registered' (by one address or several); null without a PK. */
export function ownerStatus(book, pk) {
  const key = normalizeFieldKey(pk);
  if (!key) return null;
  const addresses = book.get(key);
  if (!addresses) return 'pending';
  return addresses.length > 0 ? 'registered' : 'unregistered';
}

/** Registering addresses, in lookup order; empty while pending. */
export function ownerAddresses(book, pk) {
  return book.get(normalizeFieldKey(pk)) ?? [];
}

/** The distinct normalized PKs of `pks` still pending. */
export function pendingPks(book, pks) {
  const pending = new Set();
  for (const pk of pks) {
    const key = normalizeFieldKey(pk);
    if (key && !book.has(key)) pending.add(key);
  }
  return [...pending];
}

/**
 * Settles `queried` (normalized PKs) from the `{ noteKey, address }` pairs a
 * fully synced registry returned for them; a key without a pair is
 * unregistered. The lookup lists each pair once.
 */
export function applyOwnerLookup(book, queried, owners) {
  for (const key of queried) book.set(key, []);
  for (const { noteKey, address } of owners) book.get(normalizeFieldKey(noteKey))?.push(address);
}

/** CSV fields `[owner_addresses, owner_status]`: addresses joined with ';' (none while pending), both empty without a PK. */
export function ownerCsvFields(book, pk) {
  const status = ownerStatus(book, pk);
  return status ? [ownerAddresses(book, pk).join(';'), status] : ['', ''];
}

const OWNERS_RETRY = { baseMs: 5_000, maxWaitMs: 60_000, maxErrors: 3 };

export function createOwnersRetry() {
  return { waits: 0, errors: 0 };
}

/**
 * 'stopped' once `maxErrors` lookups in a row failed, 'waiting' while the
 * last valid answer came from a registry still syncing, else 'ok'.
 */
export function ownersRetryState(retry) {
  if (retry.errors >= OWNERS_RETRY.maxErrors) return 'stopped';
  return retry.waits > 0 ? 'waiting' : 'ok';
}

/**
 * Plans the next automatic lookup after `outcome`: 'settled' (nothing
 * pending), 'waiting' (a valid answer from a registry still syncing) or
 * 'error'. Waiting is not a failure: it backs off up to `maxWaitMs` and never
 * stops. Errors back off too and stop after `maxErrors` in a row. Returns the
 * delay in ms, or null for no retry.
 */
export function nextOwnersRetry(retry, outcome) {
  if (outcome === 'error') {
    retry.errors += 1;
    return ownersRetryState(retry) === 'stopped' ? null : backoffMs(retry.errors - 1);
  }
  retry.errors = 0;
  if (outcome === 'waiting') {
    retry.waits += 1;
    return backoffMs(retry.waits - 1);
  }
  retry.waits = 0;
  return null;
}

function backoffMs(attempt) {
  return Math.min(OWNERS_RETRY.baseMs * 2 ** attempt, OWNERS_RETRY.maxWaitMs);
}
