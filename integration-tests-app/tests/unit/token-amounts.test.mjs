import assert from 'node:assert/strict';
import test from 'node:test';
import { App, Utils } from '../../../app/js/ui/core.js';

test('wallet formatting uses pool precision, including zero decimals', () => {
  App.state.pools = [
    { poolContractId: 'zero', asset: { kind: 'contract', symbol: 'WHOLE' }, decimals: 0 },
    { poolContractId: 'six', asset: { kind: 'contract', symbol: 'SIX' }, decimals: 6 },
    { poolContractId: 'unknown', asset: { kind: 'contract', symbol: 'UNKNOWN' } },
  ];
  assert.equal(Utils.formatPoolAmount(123n, 'zero'), '123 WHOLE');
  assert.equal(Utils.formatPoolAmount(1_250_000n, 'six'), '1.25 SIX');
  assert.equal(Utils.formatPoolAmount(123n, 'unknown'), '123 base units');
  assert.equal(Utils.formatTokenAmount(-12n, 'WHOLE', 0), '-12 WHOLE');
  assert.equal(Utils.formatTokenAmount(1n, 'TINY', 0xffff_ffff), '1e-4294967295 TINY');
});

test('shared disclosure formatter never assumes seven decimals', async () => {
  const { formatAmount, createNoteRow } = await import('../../../app/js/ui/notes-view.js');
  assert.equal(formatAmount(100_000_000n, 'TOKEN', 8), '1 TOKEN');
  assert.equal(formatAmount(100_000_000n, 'TOKEN'), '100000000 base units');
  const previous = globalThis.document;
  const previousNode = globalThis.Node;
  class Element {
    dataset = {};
    children = [];
    classList = { add() {} };
    append(...children) { this.children.push(...children); }
    appendChild(child) { this.children.push(child); }
  }
  globalThis.Node = Element;
  globalThis.document = { createElement: () => new Element() };
  try {
    const note = { id: 'abc', amount: 100_000_000n, spent: false };
    const text = node => [node.textContent, ...node.children.map(text)].filter(Boolean).join(' ');
    assert.match(text(createNoteRow(note, { symbol: 'TOKEN', decimals: 8, showBadge: false })), /1 TOKEN/);
    assert.match(text(createNoteRow(note, { symbol: 'TOKEN', showBadge: false })), /100000000 base units/);
  } finally {
    globalThis.document = previous;
    globalThis.Node = previousNode;
  }
});
