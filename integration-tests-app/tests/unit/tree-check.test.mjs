import assert from 'node:assert/strict';
import test from 'node:test';

import { Address, nativeToScVal, xdr } from '@stellar/stellar-sdk';

import {
  adminLine,
  allowlistLeavesFromEvents,
  blocklistKeysFromEvents,
  codeLine,
  compareEntries,
  eventsSince,
  historyStart,
  levelsLine,
  manifestLine,
  parseRecords,
  readInstance,
} from '../../../app/js/tree-check.js';

// A tree event named `name` carrying `fields`, as the RPC's `getEvents` returns it.
const event = (name, fields) => ({ topic: [xdr.ScVal.scvSymbol(name)], value: nativeToScVal(fields) });

// The events a tree publishes when the deployer hands it to the admin account,
// which every tree a pool is re-pointed to carries beside its entries.
const handover = [
  event('admin_transfer_proposed', { admin: 'DEPLOYER', pending_admin: 'ADMIN' }),
  event('admin_transfer_accepted', { old_admin: 'DEPLOYER', new_admin: 'ADMIN' }),
];

test('blocklistKeysFromEvents drops a deleted key and keeps a re-inserted one', () => {
  const events = [
    event('LeafInserted', { key: 1n, value: 1n, root: 10n }),
    event('LeafInserted', { key: 2n, value: 2n, root: 11n }),
    event('LeafInserted', { key: 3n, value: 3n, root: 12n }),
    event('LeafDeleted', { key: 1n, root: 13n }),
    event('LeafDeleted', { key: 3n, root: 14n }),
    event('LeafInserted', { key: 3n, value: 3n, root: 15n }),
    ...handover,
  ];
  assert.deepEqual(blocklistKeysFromEvents(events), [2n, 3n]);
});

test('compareEntries reports records the tree lacks and entries no record names', () => {
  assert.deepEqual(compareEntries([1n, 2n, 4n], [1n, 2n, 3n]), { missing: [3n], unexpected: [4n] });
});

test('allowlistLeavesFromEvents orders the leaves by index', () => {
  const events = [
    event('LeafAdded', { leaf: 30n, index: 2n, root: 12n }),
    event('LeafAdded', { leaf: 10n, index: 0n, root: 10n }),
    event('LeafAdded', { leaf: 20n, index: 1n, root: 11n }),
    ...handover,
  ];
  assert.deepEqual(allowlistLeavesFromEvents(events), [10n, 20n, 30n]);
});

test('allowlistLeavesFromEvents refuses events that start after the first leaf', () => {
  const events = [
    event('LeafAdded', { leaf: 20n, index: 1n, root: 11n }),
    event('LeafAdded', { leaf: 30n, index: 2n, root: 12n }),
  ];
  assert.throws(() => allowlistLeavesFromEvents(events), /no leaf at index 0/);
});

test('parseRecords skips blank lines and names the first line that is not hex', () => {
  assert.deepEqual(parseRecords('0x1\n\n0x2'), [1n, 2n]);
  assert.throws(() => parseRecords('0x1\nzz'), { message: 'Line 2 is not a 0x hex value' });
});

test('historyStart takes a blocklist\'s ledger from the field and refuses an empty one', () => {
  const manifest = { asp_membership: 'ALLOWLIST', pools: [{ deploymentLedger: 50 }] };
  assert.equal(historyStart({ allowlist: false, tree: 'BLOCKLIST', manifest, blocklistLedger: 70 }), 70);
  assert.throws(
    () => historyStart({ allowlist: false, tree: 'BLOCKLIST', manifest, blocklistLedger: 0 }),
    { message: 'enter the blocklist\'s deployment ledger' },
  );
});

test('historyStart reads the manifest\'s own allowlist from the earliest pool', () => {
  const manifest = { asp_membership: 'ALLOWLIST', pools: [{ deploymentLedger: 50 }, { deploymentLedger: 40 }] };
  assert.equal(historyStart({ allowlist: true, tree: 'ALLOWLIST', manifest }), 40);
});

test('historyStart reads an added allowlist from its entry and refuses one the manifest omits', () => {
  const manifest = {
    asp_membership: 'ALLOWLIST',
    pools: [{ deploymentLedger: 50 }],
    added_asp_memberships: [{ contractId: 'ADDED', deploymentLedger: 60 }],
  };
  assert.equal(historyStart({ allowlist: true, tree: 'ADDED', manifest }), 60);
  assert.throws(() => historyStart({ allowlist: true, tree: 'OTHER', manifest }), /names no deployment ledger/);
});

test('codeLine compares an allowlist with the pool\'s first hash and a blocklist with its second', () => {
  const [allowlistHash, blocklistHash] = [Buffer.alloc(32, 1), Buffer.alloc(32, 2)];
  const accepted = [allowlistHash, blocklistHash];
  assert.equal(codeLine(accepted, blocklistHash, false), `the tree runs ${'02'.repeat(32)}, the code the pool accepts`);
  assert.throws(
    () => codeLine(accepted, allowlistHash, false),
    { message: `the tree runs ${'01'.repeat(32)}, and the pool accepts ${'02'.repeat(32)}` },
  );
  assert.equal(codeLine(accepted, allowlistHash, true), `the tree runs ${'01'.repeat(32)}, the code the pool accepts`);
  assert.throws(() => codeLine(accepted, undefined, true), /the tree runs no Wasm/);
});

test('levelsLine fails an 11-level allowlist in place of a 10-level one', () => {
  assert.throws(
    () => levelsLine('CURRENT', 10, 11),
    { message: 'the tree has 11 levels, and the pool\'s current allowlist CURRENT has 10' },
  );
  assert.equal(levelsLine('CURRENT', 10, 10), '10, as in the pool\'s current allowlist');
});

test('adminLine passes the pool\'s admin and asks to confirm any other by name', () => {
  assert.equal(adminLine('POOL_ADMIN', 'POOL_ADMIN'), 'POOL_ADMIN, the pool\'s admin');
  assert.throws(() => adminLine('OTHER', 'POOL_ADMIN'), { message: 'OTHER, not the pool\'s admin', confirm: 'OTHER' });
});

test('manifestLine fails an allowlist the manifest names in neither place', () => {
  const manifest = { asp_membership: 'ALLOWLIST', added_asp_memberships: [{ contractId: 'ADDED' }] };
  assert.equal(manifestLine(manifest, 'ALLOWLIST'), 'names the allowlist, so clients index it');
  assert.equal(manifestLine(manifest, 'ADDED'), 'names the allowlist, so clients index it');
  assert.throws(() => manifestLine(manifest, 'OTHER'), /in neither asp_membership nor added_asp_memberships/);
});

test('eventsSince reads past an empty page and stops when the cursor stops moving', async () => {
  const pages = [{ events: [], cursor: 'c1' }, { events: ['a', 'b'], cursor: 'c2' }, { events: [], cursor: 'c2' }];
  const requests = [];
  const server = {
    getHealth: async () => ({ oldestLedger: 100 }),
    getEvents: async (request) => {
      requests.push(request);
      return pages.shift();
    },
  };
  assert.deepEqual(await eventsSince(server, 'TREE', 100), ['a', 'b']);
  // The RPC refuses a request that carries both a start ledger and a cursor.
  const filters = [{ type: 'contract', contractIds: ['TREE'] }];
  assert.deepEqual(requests, [{ startLedger: 100, filters }, { filters, cursor: 'c1' }, { filters, cursor: 'c2' }]);
});

test('eventsSince refuses a start ledger the RPC no longer holds before reading any event', async () => {
  const server = {
    getHealth: async () => ({ oldestLedger: 100 }),
    getEvents: async () => assert.fail('no event is read before the RPC holds the start ledger'),
  };
  await assert.rejects(eventsSince(server, 'TREE', 99), /no longer holds ledger 99, .* only ledgers from 100 on/);
});

const CONTRACT = 'CBZAWV3AKKKIIO3LEIF7DHODHHHTTL47M7WQSZYTU3ZYSBMM32MUM5H4';

// An RPC stub whose `getContractData` returns an instance entry for
// `executable` holding `storage`.
const instanceServer = (executable, storage = []) => ({
  getContractData: async () => ({
    val: xdr.LedgerEntryData.contractData(new xdr.ContractDataEntry({
      ext: xdr.ExtensionPoint.v0(),
      contract: new Address(CONTRACT).toScAddress(),
      key: xdr.ScVal.scvLedgerKeyContractInstance(),
      durability: xdr.ContractDataDurability.persistent,
      val: xdr.ScVal.scvContractInstance(new xdr.ScContractInstance({ executable, storage })),
    })),
  }),
});

test('readInstance keys the storage by variant name and gives no hash for a Stellar asset contract', async () => {
  const server = instanceServer(
    xdr.ContractExecutable.contractExecutableStellarAsset(),
    [new xdr.ScMapEntry({ key: xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('Levels')]), val: xdr.ScVal.scvU32(10) })],
  );
  const { wasmHash, stored } = await readInstance(server, CONTRACT);
  assert.equal(wasmHash, undefined);
  assert.deepEqual([...stored], [['Levels', 10]]);
});

test('readInstance returns the hash of the Wasm a contract runs', async () => {
  const server = instanceServer(xdr.ContractExecutable.contractExecutableWasm(Buffer.alloc(32, 7)));
  const { wasmHash } = await readInstance(server, CONTRACT);
  assert.deepEqual(Buffer.from(wasmHash), Buffer.alloc(32, 7));
});
