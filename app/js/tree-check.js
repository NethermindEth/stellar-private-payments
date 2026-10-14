/**
 * Re-point checks: compares a tree's code, settings, and entries with the pool,
 * the manifest, and the operator's records. Kept out of `admin.js` so Node unit
 * tests can import it.
 */
import { scValToNative, xdr } from '@stellar/stellar-sdk';

/**
 * Reads a contract's instance entry.
 *
 * @returns {Promise<{wasmHash: (Uint8Array|undefined), stored: Map<string, *>}>}
 *   `wasmHash` is absent for a contract running no Wasm, such as a Stellar asset
 *   contract. `stored` maps each `DataKey` variant's name to its value.
 */
export async function readInstance(server, contractId) {
  const { val } = await server.getContractData(contractId, xdr.ScVal.scvLedgerKeyContractInstance());
  const { executable, storage } = val.contractData.val.instance;
  return {
    wasmHash: executable.wasmHash?.value,
    stored: new Map((storage ?? []).map(({ key, val: value }) => [scValToNative(key)[0], scValToNative(value)])),
  };
}

/**
 * Reads every event a contract published from `startLedger` on. The RPC scans a
 * window of ledgers per request, so an empty page is not the end; the read ends
 * when the cursor stops moving.
 *
 * @throws {Error} when the RPC no longer holds `startLedger`.
 */
export async function eventsSince(server, contractId, startLedger) {
  const { oldestLedger } = await server.getHealth();
  if (startLedger < oldestLedger) {
    throw new Error(`the RPC no longer holds ledger ${startLedger}, where the tree's events start, only ledgers from ${oldestLedger} on`);
  }
  const filters = [{ type: 'contract', contractIds: [contractId] }];
  const events = [];
  let cursor;
  for (;;) {
    const page = await server.getEvents(cursor ? { filters, cursor } : { startLedger, filters });
    events.push(...page.events);
    if (page.cursor === cursor) return events;
    ({ cursor } = page);
  }
}

/**
 * Returns the ledger the re-point check reads a tree's events from: an added
 * allowlist's manifest ledger, the operator's ledger for a blocklist, or the
 * earliest pool's ledger for the manifest's own allowlist. That last one comes
 * after the allowlist's deployment, so a leaf added in between fails the read
 * instead of going unseen.
 *
 * @param {{allowlist: boolean, tree: string, manifest: Object, blocklistLedger: number}} options
 * @throws {Error} when the manifest names no ledger for the allowlist, or the
 *   operator entered none for the blocklist.
 */
export function historyStart({ allowlist, tree, manifest, blocklistLedger }) {
  const ledger = !allowlist
    ? blocklistLedger
    : tree === manifest.asp_membership
      ? Math.min(...manifest.pools.map(({ deploymentLedger }) => deploymentLedger))
      : (manifest.added_asp_memberships ?? []).find(({ contractId }) => contractId === tree)?.deploymentLedger;
  if (!(ledger > 0)) {
    throw new Error(allowlist ? 'the manifest names no deployment ledger for the allowlist' : 'enter the blocklist\'s deployment ledger');
  }
  return ledger;
}

// Returns the hex form of a byte array, such as a Wasm hash.
const hex = (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

/**
 * Checks that a tree runs the code the pool accepts for its kind, and returns the
 * check's line.
 *
 * @param {Uint8Array[]} acceptedHashes The pool's `get_asp_wasm_hashes()`.
 * @param {(Uint8Array|undefined)} treeHash From `readInstance`.
 * @param {boolean} allowlist
 * @throws {Error} when the tree runs other code, or no Wasm.
 */
export function codeLine(acceptedHashes, treeHash, allowlist) {
  const accepted = hex(acceptedHashes[allowlist ? 0 : 1]);
  const runs = treeHash ? hex(treeHash) : 'no Wasm';
  if (runs !== accepted) {
    throw new Error(`the tree runs ${runs}, and the pool accepts ${accepted}`);
  }
  return `the tree runs ${accepted}, the code the pool accepts`;
}

/**
 * Checks that a new allowlist has the current one's depth, which its code does not
 * fix, and returns the check's line.
 *
 * @throws {Error} when the depths differ.
 */
export function levelsLine(current, levels, treeLevels) {
  if (treeLevels !== levels) {
    throw new Error(`the tree has ${treeLevels ?? 'no'} levels, and the pool's current allowlist ${current} has ${levels}`);
  }
  return `${levels}, as in the pool's current allowlist`;
}

/**
 * Checks who runs a tree, and returns the check's line when the pool's admin does.
 *
 * @throws {Error} carrying `treeAdmin` as `confirm` when another party runs the
 *   tree; the check passes once the operator confirms that party.
 */
export function adminLine(treeAdmin, poolAdmin) {
  if (treeAdmin === poolAdmin) return `${treeAdmin}, the pool's admin`;
  throw Object.assign(new Error(`${treeAdmin}, not the pool's admin`), { confirm: treeAdmin });
}

/**
 * Checks that the manifest names an allowlist, since clients index only those, and
 * returns the check's line.
 *
 * @throws {Error} when neither `asp_membership` nor `added_asp_memberships` names it.
 */
export function manifestLine(manifest, tree) {
  if (tree === manifest.asp_membership || (manifest.added_asp_memberships ?? []).some(({ contractId }) => contractId === tree)) {
    return 'names the allowlist, so clients index it';
  }
  throw new Error('names the allowlist in neither asp_membership nor added_asp_memberships, so clients cannot prove against it');
}

// Returns a `getEvents` tree event's name (its first topic) and fields (a map).
const decode = ({ topic: [name], value }) => ({ name: scValToNative(name), ...scValToNative(value) });

/**
 * Returns the leaves an allowlist's `LeafAdded` events added, in index order.
 *
 * @param {bigint} nextIndex The tree's stored `NextIndex`.
 * @throws {Error} when the events skip an index or hold other than `nextIndex`
 *   leaves, as they do when the read starts after the first leaves.
 */
export function allowlistLeavesFromEvents(events, nextIndex) {
  const added = events
    .map(decode)
    .filter(({ name }) => name === 'LeafAdded')
    .sort((a, b) => Number(a.index - b.index));
  const gap = added.findIndex(({ index }, position) => index !== BigInt(position));
  if (gap !== -1) {
    throw new Error(`the events hold no leaf at index ${gap}, so they miss part of the allowlist's history`);
  }
  if (BigInt(added.length) !== nextIndex) {
    throw new Error(`the events hold ${added.length} leaves and the tree ${nextIndex}, so they miss part of the allowlist's history`);
  }
  return added.map(({ leaf }) => leaf);
}

/**
 * Returns the keys a blocklist holds: those `LeafInserted` events added and no
 * later `LeafDeleted` removed. Expects events in `getEvents` order.
 */
export function blocklistKeysFromEvents(events) {
  const keys = new Set();
  for (const { name, key } of events.map(decode)) {
    if (name === 'LeafInserted') keys.add(key);
    if (name === 'LeafDeleted') keys.delete(key);
  }
  return [...keys];
}

/**
 * Compares a tree's entries with the operator's records.
 *
 * @returns {{missing: bigint[], unexpected: bigint[]}} Records the tree lacks, and
 *   entries no record names.
 */
export function compareEntries(onChain, records) {
  const held = new Set(onChain);
  const expected = new Set(records);
  return {
    missing: records.filter((value) => !held.has(value)),
    unexpected: onChain.filter((value) => !expected.has(value)),
  };
}

/**
 * Parses an allowlist's records, one `0x` hex leaf per line.
 *
 * @throws {Error} naming the first line that is not a hex value.
 */
export function parseRecords(text) {
  return text.split('\n').flatMap((line, index) => {
    const value = line.trim();
    if (!value) return [];
    if (!/^0x[0-9a-fA-F]+$/.test(value)) {
      throw new Error(`Line ${index + 1} is not a 0x hex value`);
    }
    return [BigInt(value)];
  });
}
