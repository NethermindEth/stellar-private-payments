import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

// Just enough DOM for ui/pool-controls.js: a tree of elements with dataset,
// attributes, bubbling listeners and focus.
class Element {
  constructor(tagName) {
    this.tagName = tagName.toUpperCase();
    this.attributes = new Map();
    this.dataset = {};
    this.children = [];
    this.parent = null;
    this.listeners = {};
    this.hidden = false;
    this.textContent = '';
  }
  setAttribute(name, value) { this.attributes.set(name, String(value)); }
  getAttribute(name) { return this.attributes.get(name) ?? null; }
  append(...nodes) {
    for (const node of nodes) {
      node.parent = this;
      this.children.push(node);
    }
  }
  replaceChildren(...nodes) {
    this.children.forEach((child) => { child.parent = null; });
    this.children = [];
    this.append(...nodes);
  }
  contains(node) {
    for (let n = node; n; n = n.parent) if (n === this) return true;
    return false;
  }
  // Supports `[data-name]` only.
  querySelector(selector) {
    const key = selector.slice('[data-'.length, -1).replace(/-([a-z])/g, (_, c) => c.toUpperCase());
    for (const child of this.children) {
      if (key in child.dataset) return child;
      const found = child.querySelector(selector);
      if (found) return found;
    }
    return null;
  }
  addEventListener(type, listener) { (this.listeners[type] ??= []).push(listener); }
  dispatch(type, init = {}) {
    const event = { type, target: this, ...init };
    for (let n = this; n; n = n.parent) (n.listeners[type] ?? []).forEach((listener) => listener(event));
  }
  click() { this.dispatch('click'); }
  focus() { document.activeElement = this; }
}

function section(scope) {
  const root = new Element('section');
  root.dataset.poolControls = scope;
  root.hidden = true;
  const tags = new Element('div');
  tags.dataset.poolControlsTags = '';
  const panels = new Element('div');
  panels.dataset.poolControlsPanels = '';
  root.append(new Element('h3'), tags, panels);
  return root;
}

const roots = { move: section('move'), advanced: section('advanced') };
globalThis.document = {
  activeElement: null,
  createElement: (tag) => new Element(tag),
  createElementNS: (_, tag) => new Element(tag),
  querySelectorAll: (selector) => (selector === '[data-pool-controls]' ? Object.values(roots) : []),
};

const { App } = await import('../../../app/js/ui/core.js');
const { POOL_CONTROLS } = await import('../../../app/js/pool-policy.js');
const { PoolControls } = await import('../../../app/js/ui/pool-controls.js');

const XLM = { kind: 'native' };
const pool = (poolContractId, policyFlags, gvkMode) => ({ poolContractId, asset: XLM, policyFlags, gvkMode });
const BLOCKLIST = pool('CA73', ['blocklist'], 'off');
const TRACEABLE = pool('CCIV', ['blocklist'], 'traceable');
const VIEW_ONLY = pool('CCMY', ['blocklist'], 'viewOnly');
const OPEN_VIEW_ONLY = pool('CBOP', [], 'viewOnly');

const text = (node) => [node.textContent, ...node.children.map(text)].filter(Boolean).join(' ');
const tagsOf = (root) => root.querySelector('[data-pool-controls-tags]').children;
const panelsOf = (root) => root.querySelector('[data-pool-controls-panels]').children;
const labels = (root) => tagsOf(root).map(text);
const expanded = (root) => tagsOf(root).map((button) => button.getAttribute('aria-expanded'));
const visible = (root) => panelsOf(root).map((panel) => !panel.hidden);

function select(selected, pools = [selected]) {
  App.state.pools = pools;
  App.state.selectedPoolId = selected?.poolContractId ?? null;
  App.events.dispatchEvent(new CustomEvent('pool:selected'));
}

PoolControls.init();
test.beforeEach(() => select(null, []));

test('without a pool the sections stay hidden and empty', () => {
  for (const root of Object.values(roots)) {
    assert.equal(root.hidden, true);
    assert.deepEqual(labels(root), []);
  }
});

test('blocklist + traceable shows two tags with their explanations, in order', () => {
  select(TRACEABLE);
  const root = roots.move;
  assert.equal(root.hidden, false);
  assert.deepEqual(labels(root), ['Blocklist', 'Admin view key · traceable']);
  const [blocklist, traceable] = tagsOf(root);
  const [blocklistPanel, traceablePanel] = panelsOf(root);
  assert.equal(blocklist.type, 'button');
  assert.equal(blocklist.getAttribute('aria-controls'), blocklistPanel.id);
  assert.equal(traceable.getAttribute('aria-controls'), traceablePanel.id);
  assert.notEqual(blocklistPanel.id, traceablePanel.id);
  assert.equal(text(blocklistPanel), ['Blocklist', POOL_CONTROLS.blocklist.explanation, POOL_CONTROLS.blocklist.impact].join(' '));
  assert.equal(text(traceablePanel), [POOL_CONTROLS.traceable.tag, POOL_CONTROLS.traceable.explanation, POOL_CONTROLS.traceable.impact].join(' '));
  assert.deepEqual(expanded(root), ['false', 'false']);
  assert.deepEqual(visible(root), [false, false]);
});

test('open + view-only shows both controls, neutral then violet', () => {
  select(OPEN_VIEW_ONLY);
  assert.deepEqual(labels(roots.move), ['Open', 'Admin view key · view-only']);
  const [open, viewOnly] = tagsOf(roots.move);
  assert.match(open.className, /text-slate-200/);
  assert.match(viewOnly.className, /text-violet-200/);
  select(BLOCKLIST);
  assert.match(tagsOf(roots.move)[0].className, /text-cyan-100/);
});

test('hover previews a tag, allows reading its panel, and closes on leaving the section', () => {
  select(TRACEABLE);
  const root = roots.move;
  const [blocklist, traceable] = tagsOf(root);
  blocklist.dispatch('pointerenter', { pointerType: 'mouse' });
  assert.deepEqual(visible(root), [true, false]);
  traceable.dispatch('pointerenter', { pointerType: 'mouse' });
  assert.deepEqual(visible(root), [false, true]);
  panelsOf(root)[1].dispatch('pointerenter', { pointerType: 'mouse' });
  assert.deepEqual(visible(root), [false, true]);
  root.dispatch('pointerleave', { pointerType: 'mouse' });
  assert.deepEqual(visible(root), [false, false]);
});

test('click pins a hovered explanation; another click or Escape dismisses it', () => {
  select(TRACEABLE);
  const root = roots.move;
  const button = tagsOf(root)[1];
  button.dispatch('pointerenter', { pointerType: 'mouse' });
  button.click();
  root.dispatch('pointerleave', { pointerType: 'mouse' });
  assert.deepEqual(visible(root), [false, true]);
  button.click();
  assert.deepEqual(visible(root), [false, false]);
  button.dispatch('pointerenter', { pointerType: 'mouse' });
  button.dispatch('keydown', { key: 'Escape' });
  assert.deepEqual(visible(root), [false, false]);
});

test('keyboard focus previews and leaving focus closes; touch still toggles on tap', () => {
  select(TRACEABLE);
  const root = roots.move;
  const button = tagsOf(root)[1];
  button.dispatch('focus');
  assert.deepEqual(visible(root), [false, true]);
  button.dispatch('focusout', { relatedTarget: null });
  assert.deepEqual(visible(root), [false, false]);
  button.dispatch('pointerenter', { pointerType: 'touch' });
  assert.deepEqual(visible(root), [false, false]);
  button.click();
  assert.deepEqual(visible(root), [false, true]);
  button.click();
  assert.deepEqual(visible(root), [false, false]);
});

test('a tag toggles its explanation, and opening another closes the first', () => {
  select(TRACEABLE);
  const root = roots.move;
  const [blocklist, traceable] = tagsOf(root);
  blocklist.click();
  assert.deepEqual(expanded(root), ['true', 'false']);
  assert.deepEqual(visible(root), [true, false]);
  traceable.click();
  assert.deepEqual(expanded(root), ['false', 'true']);
  assert.deepEqual(visible(root), [false, true]);
  traceable.click();
  assert.deepEqual(expanded(root), ['false', 'false']);
  assert.deepEqual(visible(root), [false, false]);
});

test('Escape closes the explanation and returns focus to its tag from the panel', () => {
  select(TRACEABLE);
  const root = roots.move;
  const [blocklist] = tagsOf(root);
  const [panel] = panelsOf(root);
  blocklist.click();
  panel.children[1].focus();
  panel.children[1].dispatch('keydown', { key: 'Escape' });
  assert.deepEqual(visible(root), [false, false]);
  assert.deepEqual(expanded(root), ['false', 'false']);
  assert.equal(document.activeElement, blocklist);
});

test('Escape leaves focus where it is when it was outside the panel', () => {
  select(TRACEABLE);
  const root = roots.move;
  const [blocklist, traceable] = tagsOf(root);
  blocklist.click();
  traceable.focus();
  traceable.dispatch('keydown', { key: 'Escape' });
  assert.deepEqual(visible(root), [false, false]);
  assert.equal(document.activeElement, traceable);

  blocklist.click();
  blocklist.dispatch('keydown', { key: 'Enter' });
  assert.deepEqual(visible(root), [true, false]);
});

test('switching pools updates the tags and closes the explanation', () => {
  const pools = [BLOCKLIST, TRACEABLE, VIEW_ONLY];
  select(TRACEABLE, pools);
  tagsOf(roots.move)[1].click();
  assert.deepEqual(visible(roots.move), [false, true]);
  select(VIEW_ONLY, pools);
  assert.deepEqual(labels(roots.move), ['Blocklist', 'Admin view key · view-only']);
  assert.deepEqual(expanded(roots.move), ['false', 'false']);
  assert.deepEqual(visible(roots.move), [false, false]);
});

test('a config refresh for the same pool keeps the explanation open', () => {
  select(TRACEABLE);
  tagsOf(roots.move)[1].click();
  App.state.pools = [{ ...TRACEABLE, decimals: 7 }];
  App.events.dispatchEvent(new CustomEvent('pool:config'));
  assert.deepEqual(visible(roots.move), [false, true]);
});

test('Move funds and Advanced both follow the selected pool, each with its own explanation', () => {
  const pools = [BLOCKLIST, TRACEABLE];
  select(TRACEABLE, pools);
  assert.deepEqual(labels(roots.move), labels(roots.advanced));
  assert.notEqual(tagsOf(roots.move)[0].getAttribute('aria-controls'), tagsOf(roots.advanced)[0].getAttribute('aria-controls'));
  tagsOf(roots.advanced)[0].click();
  assert.deepEqual(visible(roots.advanced), [true, false]);
  assert.deepEqual(visible(roots.move), [false, false]);
  select(BLOCKLIST, pools);
  assert.deepEqual(labels(roots.move), ['Blocklist']);
  assert.deepEqual(labels(roots.advanced), ['Blocklist']);
});

test('index.html puts a Pool controls section under both token selectors', async () => {
  const html = await readFile(new URL('../../../app/index.html', import.meta.url), 'utf8');
  for (const [select, scope] of [['primary-pool-select', 'move'], ['advanced-pool-select', 'advanced']]) {
    const start = html.indexOf(`data-pool-controls="${scope}"`);
    assert.ok(start > html.indexOf(`id="${select}"`), `${scope} section follows #${select}`);
    const body = html.slice(start, html.indexOf('</section>', start));
    assert.match(body, /data-pool-controls-tags/);
    assert.match(body, /data-pool-controls-panels/);
  }
});
