import assert from 'node:assert/strict';
import test from 'node:test';
import { poolControls, poolSelectLabel } from '../../../app/js/pool-policy.js';

const XLM = { kind: 'native' };
const pool = (poolContractId, policyFlags, gvkMode, asset = XLM) => ({ poolContractId, asset, policyFlags, gvkMode });
// A 56-character contract ID that abbreviates to `<prefix>...<suffix>`.
const fakeId = (prefix, suffix = 'AAAA', fill = 'A') =>
  `${prefix}${fill.repeat(56 - prefix.length - suffix.length)}${suffix}`;

const BLOCKLIST = pool('CA73PEBSX2GXZSMMVL46PTCXY424AIMPXKI7WWUMYJXV22AVY2DXC6DQ', ['blocklist'], 'off');
const TRACEABLE = pool('CCIVQDB36TYWZ5ZN4P33OJ3BMHTMNFCT7KSSBBEVSLC2BCV36LAHGWFL', ['blocklist'], 'traceable');
const VIEW_ONLY = pool('CCMYN7CJI3W5OYNLMY4RURZ2AIQCMIAE33ACDJTOBK5T2VP4YNKMFMIG', ['blocklist'], 'viewOnly');

const labels = (pools) => pools.map((p) => poolSelectLabel(p, pools));

test('policy flags map to open, or allowlist then blocklist', () => {
  assert.deepEqual(poolControls(pool('C', [], 'off')), ['open']);
  assert.deepEqual(poolControls(pool('C', ['blocklist', 'allowlist'], 'off')), ['allowlist', 'blocklist']);
});

test('a missing or off gvkMode adds no view key control', () => {
  assert.deepEqual(poolControls(pool('C', ['allowlist'], undefined)), ['allowlist']);
  assert.deepEqual(poolControls(pool('C', ['allowlist'], 'off')), ['allowlist']);
});

test('an open pool with a view key shows both controls', () => {
  const open = pool(fakeId('CBOPEN'), [], 'traceable');
  assert.deepEqual(poolControls(open), ['open', 'traceable']);
  assert.equal(poolSelectLabel(open, [open, BLOCKLIST]), 'XLM · Open · Traceable · CBOPEN...AAAA');
});

test('a pool alone on its asset still shows its controls and short ID', () => {
  assert.deepEqual(labels([TRACEABLE]), ['XLM · Blocklist · Traceable · CCIVQD...GWFL']);
  const usdc = pool(fakeId('CBUSDC'), [], 'off', { kind: 'classic', code: 'USDC' });
  assert.deepEqual(labels([BLOCKLIST, usdc]), ['XLM · Blocklist · CA73PE...C6DQ', 'USDC · Open · CBUSDC...AAAA']);
});

test('pools sharing an asset show their controls and short ID', () => {
  const pools = [BLOCKLIST, TRACEABLE, VIEW_ONLY];
  assert.deepEqual(labels(pools), [
    'XLM · Blocklist · CA73PE...C6DQ',
    'XLM · Blocklist · Traceable · CCIVQD...GWFL',
    'XLM · Blocklist · View-only · CCMYN7...FMIG',
  ]);
});

test('labels name open, allowlist, blocklist and both lists', () => {
  const pools = [
    pool(fakeId('CAOPEN'), [], 'off'),
    pool(fakeId('CAALLO'), ['allowlist'], 'off'),
    pool(fakeId('CABLOC'), ['blocklist'], 'off'),
    pool(fakeId('CABOTH'), ['blocklist', 'allowlist'], 'off'),
  ];
  assert.deepEqual(labels(pools), [
    'XLM · Open · CAOPEN...AAAA',
    'XLM · Allowlist · CAALLO...AAAA',
    'XLM · Blocklist · CABLOC...AAAA',
    'XLM · Allowlist · Blocklist · CABOTH...AAAA',
  ]);
});

test('pools with the same asset and controls differ by ID', () => {
  const twin = pool(fakeId('CDTWIN'), ['blocklist'], 'off');
  assert.deepEqual(labels([BLOCKLIST, twin]), ['XLM · Blocklist · CA73PE...C6DQ', 'XLM · Blocklist · CDTWIN...AAAA']);
});

test('short labels that still collide fall back to full IDs', () => {
  const first = pool(fakeId('CCIVQD', 'GWFL', 'A'), ['blocklist'], 'off');
  const second = pool(fakeId('CCIVQD', 'GWFL', 'B'), ['blocklist'], 'off');
  assert.deepEqual(labels([first, second, TRACEABLE]), [
    `XLM · Blocklist · ${first.poolContractId}`,
    `XLM · Blocklist · ${second.poolContractId}`,
    'XLM · Blocklist · Traceable · CCIVQD...GWFL',
  ]);
});
