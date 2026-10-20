import assert from 'node:assert/strict';
import test from 'node:test';

import { Address, nativeToScVal, scValToNative, xdr } from '@stellar/stellar-sdk';

import {
  adminLine,
  allowlistLeavesFromEvents,
  blocklistKeys,
  codeLine,
  compareEntries,
  entriesLine,
  eventsSince,
  historyStart,
  levelsLine,
  manifestLine,
  parseRecords,
  readInstance,
  replacesLine,
  unusedListWarning,
  usesList,
} from '../../../app/js/tree-check.js';

const event = (name, fields) => ({ topic: [xdr.ScVal.scvSymbol(name)], value: nativeToScVal(fields) });

// Handover events every re-pointed tree carries.
const handover = [
  event('admin_transfer_proposed', { admin: 'DEPLOYER', pending_admin: 'ADMIN' }),
  event('admin_transfer_accepted', { old_admin: 'DEPLOYER', new_admin: 'ADMIN' }),
];

test('usesList reads the allowlist from flag value 1 and the blocklist from value 2', () => {
  assert.deepEqual([0, 1, 2, 3, undefined].map((flags) => [usesList(flags, true), usesList(flags, false)]), [
    [false, false],
    [true, false],
    [false, true],
    [true, true],
    // No flags: every check runs.
    [true, true],
  ]);
});

test('entriesLine asks to confirm an empty tree, with a file or without, and compares any file', () => {
  const none = { missing: [], unexpected: [] };
  for (const [count, compared] of [[0, null], [0n, null], [0, none]]) {
    assert.throws(() => entriesLine(false, count, compared), {
      message: 'empty, so every blocked key could spend again',
      confirm: 'Use an empty blocklist',
    });
  }
  assert.throws(() => entriesLine(true, 0n, null), { confirm: 'Use an empty allowlist' });
  assert.throws(() => entriesLine(true, 0, { missing: ['0x1'], unexpected: [] }), { message: 'missing 0x1' });
  assert.throws(() => entriesLine(true, 2n, { missing: [], unexpected: ['0x3'] }), { message: 'not expected 0x3' });
  assert.equal(entriesLine(true, 2, none), '2, all as expected');
});

test('entriesLine asks to confirm an allowlist smaller than the pool\'s current one when no file was chosen', () => {
  assert.throws(() => entriesLine(true, 3n, null, { current: 10n }), {
    message: '3, but the current allowlist has 10. Anyone missing couldn\'t use the pool, withdrawals included. Compare with a file above to see who.',
    confirm: 'Use the smaller allowlist',
  });
  assert.equal(entriesLine(true, 10n, null, { current: 10n }), '10, as many as the current allowlist');
  assert.equal(entriesLine(true, 11n, null, { current: 10n }), '11, more than the current allowlist\'s 10');
});

test('entriesLine asks to confirm a blocklist that releases keys the current one blocks when no file was chosen', () => {
  assert.throws(() => entriesLine(false, 12, null, { released: 28 }), {
    message: '12, but it lacks 28 keys the current blocklist blocks. They could spend again.',
    confirm: 'Release 28 blocked keys',
  });
  assert.throws(() => entriesLine(false, 39, null, { released: 1 }), { confirm: 'Release 1 blocked key' });
  assert.equal(entriesLine(false, 40, null, { released: 0 }), '40, blocking every key the current blocklist blocks');
});

test('unusedListWarning warns of a list no pool uses, and of no other', () => {
  const old = 'CCMCAW7AFVATPKIAQAMAGHJ2AHS3SMK6CALUPO3FV2XR3D7X2UECLHN6';
  assert.equal(unusedListWarning(old, ['NEW'], false), 'No pool uses blocklist CCMCAW...LHN6, so this change has no effect yet. Continue anyway?');
  assert.equal(
    unusedListWarning(old, ['NEW', null], true),
    'No pool uses allowlist CCMCAW...LHN6, so this member can\'t use any pool yet. Continue anyway?',
  );
  assert.equal(unusedListWarning('NEW', ['NEW', 'NEW'], true), null);
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
  assert.deepEqual(allowlistLeavesFromEvents(events, 3n), [10n, 20n, 30n]);
});

test('allowlistLeavesFromEvents refuses events that start after the first leaf', () => {
  const events = [
    event('LeafAdded', { leaf: 20n, index: 1n, root: 11n }),
    event('LeafAdded', { leaf: 30n, index: 2n, root: 12n }),
  ];
  assert.throws(() => allowlistLeavesFromEvents(events, 3n), { message: 'the allowlist\'s events hold only part of its 3 entries' });
});

test('allowlistLeavesFromEvents compares the leaf count with NextIndex, zero included', () => {
  const events = [event('LeafAdded', { leaf: 10n, index: 0n, root: 10n }), event('LeafAdded', { leaf: 20n, index: 1n, root: 11n })];
  for (const [read, nextIndex] of [[events, 3n], [events, 1n], [handover, 2n]]) {
    assert.throws(() => allowlistLeavesFromEvents(read, nextIndex), { message: `the allowlist's events hold only part of its ${nextIndex} entries` });
  }
  assert.deepEqual(allowlistLeavesFromEvents(handover, 0n), []);
});

test('parseRecords skips blank lines and names the first line that is not hex', () => {
  assert.deepEqual(parseRecords('0x1\n\n0x2'), [1n, 2n]);
  assert.throws(() => parseRecords('0x1\nzz'), { message: 'Line 2 is not a 0x hex value' });
});

test('historyStart reads the manifest\'s own allowlist from the earliest pool', () => {
  const manifest = { asp_membership: 'ALLOWLIST', pools: [{ deploymentLedger: 50 }, { deploymentLedger: 40 }] };
  assert.equal(historyStart({ tree: 'ALLOWLIST', manifest }), 40);
});

test('historyStart reads an added allowlist from its entry and refuses one the manifest omits', () => {
  const manifest = {
    asp_membership: 'ALLOWLIST',
    pools: [{ deploymentLedger: 50 }],
    added_asp_memberships: [{ contractId: 'ADDED', deploymentLedger: 60 }],
  };
  assert.equal(historyStart({ tree: 'ADDED', manifest }), 60);
  assert.throws(() => historyStart({ tree: 'OTHER', manifest }), /gives no deployment ledger/);
});

test('codeLine compares an allowlist with the pool\'s first hash and a blocklist with its second', () => {
  const [allowlistHash, blocklistHash] = [Buffer.alloc(32, 1), Buffer.alloc(32, 2)];
  const accepted = [allowlistHash, blocklistHash];
  assert.equal(codeLine(accepted, blocklistHash, false), 'the pool accepts it');
  assert.throws(() => codeLine(accepted, allowlistHash, false), { message: 'the pool can\'t use it, since its code is different' });
  assert.equal(codeLine(accepted, allowlistHash, true), 'the pool accepts it');
  assert.throws(() => codeLine(accepted, undefined, true), /its code is different/);
});

test('replacesLine fails the contract the pool already uses', () => {
  assert.equal(replacesLine('CCMCAW7AFVATPKIAQAMAGHJ2AHS3SMK6CALUPO3FV2XR3D7X2UECLHN6', 'NEW'), 'CCMCAW...LHN6, which the pool uses now');
  assert.throws(() => replacesLine('CURRENT', 'CURRENT'), { message: 'the pool already uses it' });
});

test('levelsLine fails an 11-level allowlist in place of a 10-level one', () => {
  assert.throws(() => levelsLine(10, 11), { message: '11, but the pool needs 10. Use an allowlist built with 10 levels.' });
  assert.throws(() => levelsLine(10, undefined), { message: 'none, but the pool needs 10. Use an allowlist built with 10 levels.' });
  assert.equal(levelsLine(10, 10), '10, same as the current allowlist');
});

test('adminLine passes the pool\'s admin and names both admins when they differ', () => {
  const [poolAdmin, other] = ['GPOOL1ADMIN1111', 'GTREE2ADMIN2222'];
  assert.equal(adminLine(poolAdmin, poolAdmin), 'the pool\'s admin, GPOOL1...1111');
  assert.throws(() => adminLine(other, poolAdmin), {
    message: 'run by GTREE2ADMIN2222, not the pool\'s admin GPOOL1...1111',
    confirm: 'Accept GTREE2...2222 as its admin',
  });
});

test('manifestLine fails an allowlist the manifest names in neither place', () => {
  const manifest = { asp_membership: 'ALLOWLIST', added_asp_memberships: [{ contractId: 'ADDED' }] };
  assert.equal(manifestLine(manifest, 'ALLOWLIST'), 'listed, so users can use it');
  assert.equal(manifestLine(manifest, 'ADDED'), 'listed, so users can use it');
  assert.throws(() => manifestLine(manifest, 'OTHER'), { message: 'not listed, so users can\'t use it. Add it to added_asp_memberships in deployments.json.' });
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
  // The RPC refuses startLedger together with a cursor.
  const filters = [{ type: 'contract', contractIds: ['TREE'] }];
  assert.deepEqual(requests, [{ startLedger: 100, filters }, { filters, cursor: 'c1' }, { filters, cursor: 'c2' }]);
});

test('eventsSince refuses a start ledger the RPC no longer holds before reading any event', async () => {
  const server = {
    getHealth: async () => ({ oldestLedger: 100 }),
    getEvents: async () => assert.fail('no event is read before the RPC holds the start ledger'),
  };
  await assert.rejects(eventsSince(server, 'TREE', 99), { message: 'the network no longer has this allowlist\'s full history' });
});

test('eventsSince reads the RPC\'s ledger range refusal as the retention limit', async () => {
  // Load-balanced nodes can hold different history.
  const server = {
    getHealth: async () => ({ oldestLedger: 100 }),
    getEvents: async () => Promise.reject({ code: -32600, message: 'startLedger must be within the ledger range: 150 - 900' }),
  };
  await assert.rejects(eventsSince(server, 'TREE', 120), { message: 'the network no longer has this allowlist\'s full history' });
  const other = { code: -32603, message: 'request timed out after 30 seconds' };
  await assert.rejects(eventsSince({ ...server, getEvents: async () => Promise.reject(other) }, 'TREE', 120), (err) => err === other);
});

const CONTRACT = 'CBZAWV3AKKKIIO3LEIF7DHODHHHTTL47M7WQSZYTU3ZYSBMM32MUM5H4';

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

// Nothing for a hash `nodes` lacks.
const nodeServer = (nodes) => ({
  getLedgerEntries: async (...keys) => {
    // The RPC refuses more than 200 keys a request.
    assert.ok(keys.length <= 200);
    return {
      entries: keys
        .map(({ contractData: { contract, key, durability } }) => {
          assert.equal(Address.fromScAddress(contract).toString(), CONTRACT);
          assert.equal(durability.name, 'persistent');
          return nodes.get(scValToNative(key)[1]);
        })
        .filter(Boolean)
        .map((node) => ({ val: { contractData: { val: xdr.ScVal.scvVec(node.map((v) => nativeToScVal(v, { type: 'u256' }))) } } })),
    };
  },
});

test('blocklistKeys reads every leaf below the root and skips empty children', async () => {
  const nodes = new Map([
    [100n, [101n, 0n]],
    [101n, [102n, 103n]],
    [102n, [1n, 11n, 1n]],
    [103n, [1n, 33n, 1n]],
  ]);
  assert.deepEqual(await blocklistKeys(nodeServer(nodes), CONTRACT, 100n), [11n, 33n]);
  assert.deepEqual(await blocklistKeys(nodeServer(nodes), CONTRACT, 0n), []);
});

test('blocklistKeys reads a level wider than one request', async () => {
  // Heap-indexed: node n has children 2n and 2n + 1; leaves are 256 to 511.
  const nodes = new Map(Array.from({ length: 511 }, (_, i) => {
    const hash = BigInt(i + 1);
    return [hash, hash < 256n ? [2n * hash, 2n * hash + 1n] : [1n, hash, 1n]];
  }));
  const keys = await blocklistKeys(nodeServer(nodes), CONTRACT, 1n);
  assert.deepEqual(keys, Array.from({ length: 256 }, (_, i) => BigInt(256 + i)));
});

test('blocklistKeys refuses a tree the RPC returns part of', async () => {
  const nodes = new Map([[100n, [101n, 102n]], [101n, [1n, 11n, 1n]]]);
  await assert.rejects(blocklistKeys(nodeServer(nodes), CONTRACT, 100n), /missing part of this blocklist/);
});
