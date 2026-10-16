/**
 * Re-point checks: compares a tree's code, settings, and entries with the pool,
 * the manifest, and the operator's records. Kept out of `admin.js` so Node unit
 * tests can import it.
 */
import { Address, nativeToScVal, scValToNative, xdr } from '@stellar/stellar-sdk';

import { hex, shortAddress } from './admin-transactions.js';

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

const HISTORY_GONE = 'the network no longer has this allowlist\'s full history';

/**
 * Reads every event a contract published from `startLedger` on. The RPC scans a
 * window of ledgers per request, so an empty page is not the end; the read ends
 * when the cursor stops moving.
 *
 * @throws {Error} when the RPC no longer holds `startLedger`.
 */
export async function eventsSince(server, contractId, startLedger) {
  const { oldestLedger } = await server.getHealth();
  if (startLedger < oldestLedger) throw new Error(HISTORY_GONE);
  const filters = [{ type: 'contract', contractIds: [contractId] }];
  const events = [];
  let cursor;
  for (;;) {
    const page = await server.getEvents(cursor ? { filters, cursor } : { startLedger, filters }).catch((err) => {
      // A load-balanced RPC node can hold less history than getHealth said.
      throw /startLedger must be within the ledger range/.test(err.message) ? new Error(HISTORY_GONE) : err;
    });
    events.push(...page.events);
    if (page.cursor === cursor) return events;
    ({ cursor } = page);
  }
}

/**
 * Returns the ledger the re-point check reads an allowlist's events from: an
 * added allowlist's manifest ledger, or the earliest pool's ledger for the
 * manifest's own allowlist. That last one comes after the allowlist's
 * deployment, so a leaf added in between fails the read instead of going unseen.
 *
 * @param {{tree: string, manifest: Object}} options
 * @throws {Error} when the manifest names no ledger for the allowlist.
 */
export function historyStart({ tree, manifest }) {
  const ledger = tree === manifest.asp_membership
    ? Math.min(...manifest.pools.map(({ deploymentLedger }) => deploymentLedger))
    : (manifest.added_asp_memberships ?? []).find(({ contractId }) => contractId === tree)?.deploymentLedger;
  if (!(ledger > 0)) throw new Error('deployments.json gives no deployment ledger for this allowlist');
  return ledger;
}

/** `PolicyFlags` bit 1 is the allowlist, 2 the blocklist; no flags means both. */
export const usesList = (policyFlags, allowlist) => policyFlags === undefined || (policyFlags & (allowlist ? 1 : 2)) !== 0;

export function unusedListWarning(list, usedLists, allowlist) {
  if (usedLists.includes(list)) return null;
  return allowlist
    ? `No pool uses allowlist ${shortAddress(list)}, so this member can't use any pool yet. Continue anyway?`
    : `No pool uses blocklist ${shortAddress(list)}, so this change has no effect yet. Continue anyway?`;
}

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
  if (runs !== accepted) throw new Error('the pool can\'t use it, since its code is different');
  return 'the pool accepts it';
}

export function replacesLine(current, tree) {
  if (tree === current) throw new Error('the pool already uses it');
  return `${shortAddress(current)}, which the pool uses now`;
}

/**
 * Checks that a new allowlist has the current one's depth, which its code does not
 * fix, and returns the check's line.
 *
 * @throws {Error} when the depths differ.
 */
export function levelsLine(levels, treeLevels) {
  if (treeLevels !== levels) {
    throw new Error(`${treeLevels ?? 'none'}, but the pool needs ${levels}. Use an allowlist built with ${levels} levels.`);
  }
  return `${levels}, same as the current allowlist`;
}

export function adminLine(treeAdmin, poolAdmin) {
  if (treeAdmin === poolAdmin) return `the pool's admin, ${shortAddress(treeAdmin)}`;
  // In full: a vanity key can match a short form.
  throw Object.assign(new Error(`run by ${treeAdmin}, not the pool's admin ${shortAddress(poolAdmin)}`), {
    confirm: `Accept ${shortAddress(treeAdmin)} as its admin`,
  });
}

/**
 * Checks that the manifest names an allowlist, since clients index only those, and
 * returns the check's line.
 *
 * @throws {Error} when neither `asp_membership` nor `added_asp_memberships` names it.
 */
export function manifestLine(manifest, tree) {
  if (tree === manifest.asp_membership || (manifest.added_asp_memberships ?? []).some(({ contractId }) => contractId === tree)) {
    return 'listed, so users can use it';
  }
  throw new Error('not listed, so users can\'t use it. Add it to added_asp_memberships in deployments.json.');
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
  const complete = BigInt(added.length) === nextIndex && added.every(({ index }, position) => index === BigInt(position));
  if (!complete) throw new Error(`the allowlist's events hold only part of its ${nextIndex} entries`);
  return added.map(({ leaf }) => leaf);
}

/**
 * Returns the keys a blocklist holds, read from its nodes from `root` down.
 *
 * @param {bigint} root The tree's stored `Root`, 0 when it is empty.
 * @throws {Error} when the RPC returns no entry for a node.
 */
export async function blocklistKeys(server, contractId, root) {
  const contract = new Address(contractId).toScAddress();
  const nodeKey = (hash) => xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({
    contract,
    key: xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('Node'), nativeToScVal(hash, { type: 'u256' })]),
    durability: xdr.ContractDataDurability.persistent,
  }));
  const keys = [];
  // One level a pass, at most 200 entries a request, the RPC's limit.
  let level = root ? [root] : [];
  while (level.length > 0) {
    const next = [];
    for (let i = 0; i < level.length; i += 200) {
      const hashes = level.slice(i, i + 200);
      const { entries } = await server.getLedgerEntries(...hashes.map(nodeKey));
      if (entries.length !== hashes.length) throw new Error('the network is missing part of this blocklist');
      for (const { val } of entries) {
        // A leaf is `[1, key, value]`, an internal node `[left, right]` with 0 for no child.
        const node = scValToNative(val.contractData.val);
        if (node.length === 3) keys.push(node[1]);
        else next.push(...node.filter((child) => child !== 0n));
      }
    }
    level = next;
  }
  return keys;
}

/** With no file (`compared` null), pass `{ current }` (allowlist) or `{ released }` (blocklist). */
export function entriesLine(allowlist, count, compared, unfiled = {}) {
  const problems = [
    compared?.missing.length > 0 && `missing ${compared.missing.join(', ')}`,
    compared?.unexpected.length > 0 && `not expected ${compared.unexpected.join(', ')}`,
  ].filter(Boolean);
  if (problems.length > 0) throw new Error(problems.join('; '));
  if (Number(count) === 0) {
    throw Object.assign(new Error(allowlist
      ? 'empty, so no one could use the pool or withdraw'
      : 'empty, so every blocked key could spend again'), {
      confirm: `Use an empty ${allowlist ? 'allowlist' : 'blocklist'}`,
    });
  }
  const { current, released = 0 } = unfiled;
  if (current !== undefined && BigInt(count) < BigInt(current)) {
    throw Object.assign(new Error(`${count}, but the current allowlist has ${current}. Anyone missing couldn't use the pool, withdrawals included. Compare with a file above to see who.`), {
      confirm: 'Use the smaller allowlist',
    });
  }
  if (released > 0) {
    const keys = released === 1 ? 'key' : 'keys';
    throw Object.assign(new Error(`${count}, but it lacks ${released} ${keys} the current blocklist blocks. They could spend again.`), {
      confirm: `Release ${released} blocked ${keys}`,
    });
  }
  if (compared) return `${count}, all as expected`;
  if (!allowlist) return `${count}, blocking every key the current blocklist blocks`;
  return BigInt(count) === BigInt(current) ? `${count}, as many as the current allowlist` : `${count}, more than the current allowlist's ${current}`;
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
