import assert from 'node:assert/strict';
import test from 'node:test';

import { parseAmountInput } from '../../../app/js/amount-input.js';

// Mirrors the SDK's parser (sdk/native/src/types/amounts.rs) and its messages.
function parse(raw, decimals) {
  const negative = raw.startsWith('-');
  const digits = raw.replace(/^[-+]/, '');
  if (!/^\d*\.?\d*$/.test(digits) || !/\d/.test(digits)) throw new Error('invalid decimal amount');
  const [whole, fraction = ''] = digits.split('.');
  if (fraction.length > decimals) throw new Error(`too many decimal places (max ${decimals})`);
  const value = BigInt((whole || '0') + fraction.padEnd(decimals, '0'));
  if (negative && value !== 0n) throw new Error('amount must be non-negative');
  return value;
}

test('an empty field is zero', () => {
  assert.deepEqual(parseAmountInput('  ', 7, parse), { ok: true, value: 0n });
});

test('a decimal comma reads as a dot', () => {
  assert.deepEqual(parseAmountInput('1,5', 7, parse), { ok: true, value: 15_000_000n });
  assert.deepEqual(parseAmountInput('0,25', 2, parse), { ok: true, value: 25n });
});

test('a comma that may separate thousands is refused, suggesting a dot', () => {
  for (const raw of ['1,500', '1,000.5', '1,2,3']) {
    const result = parseAmountInput(raw, 7, parse);
    assert.equal(result.ok, false, raw);
    assert.match(result.error, /for example 1\.5/);
  }
});

test('parser messages are reworded', () => {
  assert.deepEqual(parseAmountInput('abc', 7, parse), { ok: false, error: 'Enter the amount as a number, for example 1.5.' });
  assert.deepEqual(parseAmountInput('-1', 7, parse), { ok: false, error: 'The amount can\'t be negative.' });
  assert.deepEqual(parseAmountInput('0.00000001', 7, parse), { ok: false, error: 'This token allows at most 7 decimal places.' });
  assert.deepEqual(parseAmountInput('1.5', 0, parse), { ok: false, error: 'This token has no decimal places. Enter a whole number.' });
});
