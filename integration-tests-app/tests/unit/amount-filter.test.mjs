import assert from 'node:assert/strict';
import test from 'node:test';
import { parseAmountRange } from '../../../app/js/amount-filter.js';

const parse = raw => {
  if (!/^\d+$/.test(raw)) throw new Error('Invalid amount');
  return BigInt(raw);
};

test('valid bounds preserve bigint precision and zero', () => {
  const range = parseAmountRange('0', '9007199254740993', 0, parse);
  assert.equal(range.valid, true);
  assert.equal(range.amountMin, 0n);
  assert.equal(range.amountMax, 9007199254740993n);
});

test('invalid and inverted bounds invalidate the whole filter', () => {
  for (const [min, max] of [['.', '10'], ['0', 'bad'], ['10', '9']]) {
    const range = parseAmountRange(min, max, 0, parse);
    assert.equal(range.valid, false);
    assert.ok(range.errors.some(Boolean));
  }
});

test('unknown precision permits an unfiltered audit but rejects an entered bound', () => {
  assert.equal(parseAmountRange('', '', null, parse).valid, true);
  const range = parseAmountRange('1', '', null, () => { throw new Error('must not parse'); });
  assert.equal(range.valid, false);
  assert.equal(range.errors[0], 'Token precision unavailable');
});
