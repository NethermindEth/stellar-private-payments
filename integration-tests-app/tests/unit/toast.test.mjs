import assert from 'node:assert/strict';
import test from 'node:test';

// Just enough DOM for ui/toast.js: a tree of elements with dataset, attributes,
// listeners and removal.
class Element {
  constructor(tagName) {
    this.tagName = tagName.toUpperCase();
    this.attributes = new Map();
    this.dataset = {};
    this.children = [];
    this.parent = null;
    this.listeners = {};
    this.className = '';
    this.textContent = '';
  }
  get parentElement() { return this.parent; }
  setAttribute(name, value) { this.attributes.set(name, String(value)); }
  getAttribute(name) { return this.attributes.get(name) ?? null; }
  append(...nodes) {
    for (const node of nodes) {
      node.parent = this;
      this.children.push(node);
    }
  }
  remove() {
    if (!this.parent) return;
    this.parent.children = this.parent.children.filter((child) => child !== this);
    this.parent = null;
  }
  contains(node) {
    for (let n = node; n; n = n.parent) if (n === this) return true;
    return false;
  }
  // Supports `[data-testid="..."]` only.
  querySelector(selector) {
    const testId = selector.match(/^\[data-testid="(.+)"\]$/)?.[1];
    for (const child of this.children) {
      if (testId !== undefined && child.dataset.testid === testId) return child;
      const found = child.querySelector(selector);
      if (found) return found;
    }
    return null;
  }
  addEventListener(type, listener) { (this.listeners[type] ??= []).push(listener); }
  dispatch(type, init = {}) {
    const event = { type, target: this, ...init };
    (this.listeners[type] ?? []).forEach((listener) => listener(event));
  }
}

const container = new Element('div');
container.id = 'toast-container';
const body = new Element('body');

globalThis.Node = Element;
globalThis.document = {
  body,
  createElement: (tag) => new Element(tag),
  getElementById: (id) => (id === container.id ? container : null),
  querySelectorAll: () => [],
};

const { showToast } = await import('../../../app/js/ui/toast.js');

const messages = () => container.children
  .filter((toast) => toast.dataset.state === 'visible')
  .map((toast) => toast.querySelector('[data-testid="toast-message"]').textContent);

test.beforeEach((t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  container.children = [];
});

test('at most three toasts are visible and the oldest gives way', () => {
  showToast('one', 'info', 10_000);
  showToast('two', 'info', 10_000);
  showToast('three', 'info', 10_000);
  assert.deepEqual(messages(), ['one', 'two', 'three']);

  showToast('four', 'info', 10_000);
  assert.deepEqual(messages(), ['two', 'three', 'four']);
});

test('a toast held by the pointer is not evicted while it is read', (t) => {
  showToast('one', 'error', 10_000, { details: 'raw one' });
  showToast('two', 'error', 1_000_000);
  showToast('three', 'error', 1_000_000);
  const oldest = container.children[0];

  oldest.dispatch('mouseenter');
  showToast('four', 'error', 1_000_000);
  assert.deepEqual(messages(), ['one', 'two', 'three', 'four']);

  // Its countdown is held too, so neither the clock nor a new toast removes it.
  t.mock.timers.tick(20_000);
  assert.deepEqual(messages(), ['one', 'two', 'three', 'four']);

  oldest.dispatch('mouseleave');
  assert.deepEqual(messages(), ['two', 'three', 'four']);
});

test('a toast held by focus is not evicted while it is read', () => {
  showToast('one', 'error', 10_000, { details: 'raw one' });
  showToast('two', 'error', 10_000);
  showToast('three', 'error', 10_000);
  const oldest = container.children[0];

  oldest.dispatch('focusin');
  showToast('four', 'error', 10_000);
  assert.deepEqual(messages(), ['one', 'two', 'three', 'four']);

  oldest.dispatch('focusout', { relatedTarget: null });
  assert.deepEqual(messages(), ['two', 'three', 'four']);
});

test('a transaction toast keeps its explorer link when older toasts give way', () => {
  showToast('sent', 'success', 10_000, { transactionHash: 'abc', linkUrl: 'https://explorer.example/tx/abc' });
  showToast('two', 'info', 10_000);
  showToast('three', 'info', 10_000);

  showToast('four', 'info', 10_000);
  assert.deepEqual(messages(), ['sent', 'three', 'four']);
});
