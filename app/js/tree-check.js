/**
 * Re-point checks: reads a tree's code, settings, and entries and compares
 * them with the pool, the manifest, and the operator's records.
 *
 * Separate from `admin.js` so Node can import it in unit tests.
 */
import { scValToNative, xdr } from '@stellar/stellar-sdk';

/**
 * Reads a contract's instance entry: the hash of the Wasm it runs, and its
 * instance storage by key.
 *
 * `stored` maps each `DataKey` variant's name to its value.
 *
 * @param {rpc.Server} server - The RPC client.
 * @param {string} contractId
 * @returns {Promise<{wasmHash: (Uint8Array|undefined), stored: Map<string, *>}>}
 *   `wasmHash` is absent for a contract that runs no Wasm, such as a Stellar
 *   asset contract.
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
 * Reads every event a contract published from `startLedger` on.
 *
 * The RPC scans a window of ledgers per request, so an empty page is not the
 * end: the reading ends when the cursor stops moving.
 *
 * @param {rpc.Server} server - The RPC client.
 * @param {string} contractId
 * @param {number} startLedger
 * @returns {Promise<Array>} The events, as `getEvents` returns them.
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
 * Returns the ledger from which the re-point check reads a tree's events.
 *
 * An added allowlist starts at its manifest entry's ledger, and a blocklist at
 * the ledger the operator enters. The manifest's own allowlist starts at the
 * earliest pool's ledger, after its own deployment, so a leaf added in between
 * fails the read rather than going unseen.
 *
 * @param {Object} options
 * @param {boolean} options.allowlist - Whether the tree is an allowlist.
 * @param {string} options.tree - The tree's address.
 * @param {Object} options.manifest - The deployment manifest.
 * @param {number} options.blocklistLedger - The ledger the operator entered,
 *   read only for a blocklist.
 * @returns {number}
 * @throws {Error} when the manifest names no ledger for the allowlist, or
 *   the operator entered none for the blocklist.
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
 * Checks that a tree runs the code a pool accepts for the tree's kind.
 *
 * @param {Uint8Array[]} acceptedHashes - The pool's `get_asp_wasm_hashes()`
 *   value: the allowlist's hash, then the blocklist's.
 * @param {(Uint8Array|undefined)} treeHash - The hash of the Wasm the tree
 *   runs, as `readInstance` returns it.
 * @param {boolean} allowlist - Whether the tree is an allowlist.
 * @returns {string} The check's line.
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
 * Checks that a new allowlist has the depth of the pool's current one, which
 * the tree's code does not fix.
 *
 * @param {string} current - The pool's current allowlist.
 * @param {number} levels - The current allowlist's `Levels`.
 * @param {(number|undefined)} treeLevels - The new allowlist's `Levels`.
 * @returns {string} The check's line.
 * @throws {Error} when the depths differ.
 */
export function levelsLine(current, levels, treeLevels) {
  if (treeLevels !== levels) {
    throw new Error(`the tree has ${treeLevels ?? 'no'} levels, and the pool's current allowlist ${current} has ${levels}`);
  }
  return `${levels}, as in the pool's current allowlist`;
}

/**
 * Checks who runs a tree.
 *
 * @param {string} treeAdmin - The tree's admin.
 * @param {string} poolAdmin - The pool's admin.
 * @returns {string} The check's line, when the pool's admin runs the tree.
 * @throws {Error} carrying `treeAdmin` as `confirm` when another party runs
 *   the tree, which passes only once the operator confirms that party.
 */
export function adminLine(treeAdmin, poolAdmin) {
  if (treeAdmin === poolAdmin) return `${treeAdmin}, the pool's admin`;
  throw Object.assign(new Error(`${treeAdmin}, not the pool's admin`), { confirm: treeAdmin });
}

/**
 * Checks that the manifest names an allowlist, since clients index only the
 * allowlists it names.
 *
 * @param {Object} manifest - The deployment manifest.
 * @param {string} tree - The allowlist's address.
 * @returns {string} The check's line.
 * @throws {Error} when the manifest names the allowlist in neither
 *   `asp_membership` nor `added_asp_memberships`.
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
 * @param {Array} events - The allowlist's events, as `getEvents` returns them.
 * @returns {bigint[]}
 * @throws {Error} when the events skip an index, which they do when the read
 *   starts after the allowlist's first leaves.
 */
export function allowlistLeavesFromEvents(events) {
  const added = events
    .map(decode)
    .filter(({ name }) => name === 'LeafAdded')
    .sort((a, b) => Number(a.index - b.index));
  const gap = added.findIndex(({ index }, position) => index !== BigInt(position));
  if (gap !== -1) {
    throw new Error(`the events hold no leaf at index ${gap}, so they miss part of the allowlist's history`);
  }
  return added.map(({ leaf }) => leaf);
}

/**
 * Returns the keys a blocklist holds: those its `LeafInserted` events added
 * and no later `LeafDeleted` event removed.
 *
 * @param {Array} events - The blocklist's events, in the order `getEvents`
 *   returns them.
 * @returns {bigint[]}
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
 * Compares the entries a tree holds with the operator's records.
 *
 * @param {bigint[]} onChain - The entries the tree holds.
 * @param {bigint[]} records - The entries the operator expects it to hold.
 * @returns {{missing: bigint[], unexpected: bigint[]}} `missing` holds the
 *   records the tree lacks, and `unexpected` the entries no record names.
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
 * @param {string} text
 * @returns {bigint[]}
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
