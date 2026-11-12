import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { Element, installDom, balanceCard } from '../helpers/ui-dom.mjs';

installDom();
const { App } = await import('../../../app/js/ui/core.js');
const { POOL_CONTROLS, poolControls } = await import('../../../app/js/pool-policy.js');
const dataUrl = source => `data:text/javascript;base64,${Buffer.from(source).toString('base64')}`;

// Keep the UI and shared state real; replace wallet/RPC dependencies at the
// module boundary, following the existing app-wallet-network tests.
async function loadUi(name, stubs) {
  const url = new URL(`../../../app/js/ui/${name}.js`, import.meta.url);
  const source = (await readFile(url, 'utf8')).replace(/^import\s+([\s\S]*?)\s+from\s+(['"])(.*?)\2;/gm, (statement, names, _, path) => {
    if (path === './core.js' || (!(path in stubs) && name !== 'navigation')) {
      return statement.replace(`${_}${path}${_}`, JSON.stringify(new URL(path, url).href));
    }
    const stub = stubs[path] ?? names.replace(/[{}\s]/g, '').split(',').filter(Boolean).map(name => `export const ${name} = () => null;`).join('\n');
    return statement.replace(`${_}${path}${_}`, JSON.stringify(dataUrl(stub)));
  });
  return import(dataUrl(source));
}
const { Dashboard } = await loadUi('dashboard', {
  '../wasm-facade.js': 'export const client = () => globalThis.dashboardSdk;',
  './op-history.js': 'export const OpHistory = {list: (...args) => globalThis.listHistory(...args)};',
});
const { Shell } = await loadUi('navigation', {});

const grid = new Element('div', { id: 'dashboard-balance-grid' });
const heading = new Element('h3', { id: 'move-pool-controls-heading' });
const selectors = [new Element('select', { dataset: { poolSelect: '' } }), new Element('select', { dataset: { poolSelect: '' } })];
const views = ['dashboard', 'move-funds', 'advanced'].map(view => new Element('button', { dataset: { view } }));
const flows = ['deposit', 'transfer', 'withdraw'].map(moveFlow => new Element('button', { dataset: { moveFlow } }));
document.body.append(grid, heading, ...selectors, ...views, ...flows);
App.templates.balanceCard = { content: { cloneNode: () => ({ firstElementChild: balanceCard() }) } };
Shell.init();
Dashboard.init();
const pool = (poolContractId, policyFlags = [], gvkMode = 'off') => ({ poolContractId, policyFlags, gvkMode, asset: { kind: 'native' }, decimals: 7 });
const A = pool('A', ['blocklist'], 'traceable');
const B = pool('B', [], 'viewOnly');
const C = pool('C', ['allowlist']);
const balance = (id, amount = '10000000', noteCount = 1) => ({ poolContractId: id, tokenContractId: 'TOKEN', tokenLabel: 'XLM', amount, noteCount });
const trigger = card => card.querySelector('[data-overview-pool-controls]');
const panel = card => card.querySelector('section');
const details = card => panel(card).querySelector('a');
const emit = (name, detail) => App.events.dispatchEvent(new CustomEvent(name, { detail }));
function render(pools = [A, B, C], balances = [balance('A'), balance('B')]) {
  App.state.pools = pools;
  App.state.balances = balances;
  App.state.selectedPoolId = 'C';
  Dashboard.renderBalances();
  return grid.children;
}

test.beforeEach(() => {
  Dashboard.clear();
  App.state.wallet.address = 'OWNER';
  App.state.views.active = 'dashboard';
  App.state.views.moveFlow = 'withdraw';
  document.activeElement = document.body;
  window.innerWidth = 1024;
  window.innerHeight = 768;
});

test('all 12 ASP/GVK configurations use full names, exact shared copy, order and tones', () => {
  for (const flags of [[], ['allowlist'], ['blocklist'], ['blocklist', 'allowlist']]) {
    for (const mode of ['off', 'viewOnly', 'traceable']) {
      const configured = pool('A', flags, mode);
      const [card] = render([configured], [balance('A')]);
      const controls = poolControls(configured);
      assert.equal(trigger(card).getAttribute('aria-label'), `Pool controls: ${controls.map(key => POOL_CONTROLS[key].tag).join(', ')}`);
      assert.equal(trigger(card).getAttribute('aria-controls'), panel(card).id);
      assert.equal(panel(card).children[0].textContent, 'Pool controls');
      assert.deepEqual(panel(card).children.slice(1, -1).map(row => row.children.map(node => node.textContent)), controls.map(key => [POOL_CONTROLS[key].tag, POOL_CONTROLS[key].impact]));
      controls.forEach((key, index) => assert.match(panel(card).children[index + 1].children[0].className, key === 'open' ? /text-slate-200/ : ['allowlist', 'blocklist'].includes(key) ? /text-cyan-100/ : /text-violet-200/));
    }
  }
});

test('same-asset cards use their own IDs while a third pool is selected', () => {
  const [a, b] = render();
  assert.notEqual(panel(a).id, panel(b).id);
  assert.match(trigger(a).getAttribute('aria-label'), /Blocklist, Admin view key · traceable/);
  assert.match(trigger(b).getAttribute('aria-label'), /Open, Admin view key · view-only/);
  const navigated = [];
  const listener = event => navigated.push(event.detail);
  App.events.addEventListener('dashboard:view-pool-controls', listener);
  for (const card of [a, b]) {
    trigger(card).click();
    details(card).click();
    assert.equal(App.state.selectedPoolId, card.dataset.poolId);
    assert.deepEqual(selectors.map(select => select.value), [card.dataset.poolId, card.dataset.poolId]);
    assert.equal(App.state.views.active, 'move-funds');
    assert.equal(App.state.views.moveFlow, 'withdraw');
    assert.equal(document.activeElement, heading);
    assert.equal(panel(card).hidden, true);
  }
  assert.deepEqual(navigated, [{ poolId: 'A' }, { poolId: 'B' }]);
  App.events.removeEventListener('dashboard:view-pool-controls', listener);
});

test('missing configuration stays unavailable, with no details action or inferred Open', () => {
  const [card] = render([C], [balance('UNKNOWN')]);
  assert.equal(trigger(card).getAttribute('aria-label'), 'Pool controls unavailable');
  assert.equal(panel(card).children[1].textContent, 'Pool controls unavailable');
  assert.equal(details(card), null);
  trigger(card).click();
  assert.equal(panel(card).hidden, false);
  App.state.pools.push(pool('UNKNOWN'));
  emit('pool:config');
  assert.equal(panel(card).hidden, true);
  assert.equal(trigger(card).getAttribute('aria-label'), 'Pool controls: Open');
  assert.ok(details(card));
});

test('toggle, one-open-only, no hover/focus activation and outside dismissal', () => {
  const [a, b] = render();
  trigger(a).dispatch('pointerenter', { pointerType: 'mouse' });
  trigger(a).focus();
  assert.equal(panel(a).hidden, true);
  trigger(a).click();
  assert.equal(trigger(a).getAttribute('aria-expanded'), 'true');
  assert.equal(panel(a).hidden, false);
  panel(a).click();
  assert.equal(panel(a).hidden, false);
  trigger(b).click();
  assert.equal(panel(a).hidden, true);
  assert.equal(trigger(a).getAttribute('aria-expanded'), 'false');
  assert.equal(panel(b).hidden, false);
  trigger(b).click();
  assert.equal(panel(b).hidden, true);
  trigger(a).click();
  document.body.click();
  assert.equal(panel(a).hidden, true);
});

test('Escape returns focus from inside, leaves outside focus alone and prevents default only when open', () => {
  const [a, b] = render();
  trigger(a).click();
  details(a).focus();
  assert.equal(details(a).dispatch('keydown', { key: 'Escape' }).defaultPrevented, true);
  assert.equal(panel(a).hidden, true);
  assert.equal(document.activeElement, trigger(a));
  trigger(a).click();
  trigger(b).focus();
  trigger(b).dispatch('keydown', { key: 'Escape' });
  assert.equal(document.activeElement, trigger(b));
  assert.equal(trigger(b).dispatch('keydown', { key: 'Escape' }).defaultPrevented, undefined);
});

test('refresh retains the card, panel, details focus and single action handlers, including reordering', () => {
  const [a, b] = render();
  trigger(a).click();
  const action = details(a);
  action.focus();
  for (let index = 0; index < 3; index++) render([A, B, C], [balance('B'), balance('A', '25000000', 2)]);
  assert.equal(grid.children[1], a);
  assert.equal(grid.children[0], b);
  assert.equal(panel(a).hidden, false);
  assert.equal(details(a), action);
  assert.equal(document.activeElement, action);
  assert.equal(a.querySelector('.balance-amount').textContent, '2.5 XLM');
  assert.equal(a.querySelector('.balance-notes').textContent, '2 notes');
  let notes = 0;
  const listener = () => notes++;
  App.events.addEventListener('dashboard:view-notes', listener);
  a.querySelector('[data-view-notes]').click();
  assert.equal(notes, 1);
  App.events.removeEventListener('dashboard:view-notes', listener);
  assert.equal(trigger(a).listeners.click.length, 1);
});

test('changed controls close and restore focus; a disappearing card closes its panel', () => {
  const [a] = render();
  trigger(a).click();
  details(a).focus();
  App.state.pools = [pool('A', ['allowlist']), B, C];
  emit('pool:config');
  assert.equal(panel(a).hidden, true);
  assert.equal(document.activeElement, trigger(a));
  assert.equal(trigger(a).getAttribute('aria-label'), 'Pool controls: Allowlist');
  trigger(a).click();
  render([A, B, C], [balance('B')]);
  assert.equal(a.isConnected, false);
  assert.equal(panel(a).hidden, true);
});

test('navigation, disconnect and clear close the disclosure', () => {
  const [a] = render();
  trigger(a).click();
  views[1].click();
  assert.equal(panel(a).hidden, true);
  trigger(a).click();
  emit('wallet:disconnected');
  assert.equal(panel(a).hidden, true);
  assert.equal(grid.children.length, 0);
});

test('details rejects unknown pools before changing selection, view or focus', () => {
  render();
  const selected = [];
  const listener = event => selected.push(event.detail);
  App.events.addEventListener('pool:selected', listener);
  document.body.focus();
  emit('dashboard:view-pool-controls', { poolId: 'UNKNOWN' });
  emit('dashboard:view-pool-controls');
  assert.equal(App.state.selectedPoolId, 'C');
  assert.equal(App.state.views.active, 'dashboard');
  assert.equal(document.activeElement, document.body);
  assert.deepEqual(selected, []);
  App.events.removeEventListener('pool:selected', listener);
});

test('details emits pool:selected after synchronizing state and both selectors, before navigation', () => {
  render();
  let observation;
  App.events.addEventListener('pool:selected', () => {
    observation = { id: App.state.selectedPoolId, selectors: selectors.map(select => select.value), view: App.state.views.active };
  }, { once: true });
  emit('dashboard:view-pool-controls', { poolId: 'B' });
  assert.deepEqual(observation, { id: 'B', selectors: ['B', 'B'], view: 'dashboard' });
  assert.equal(App.state.views.moveFlow, 'withdraw');
});

test('notes, quick flows and history still target their card after repeated refreshes', async () => {
  render();
  const [a] = render();
  a.querySelector('[data-view-notes]').click();
  assert.equal(App.state.selectedPoolId, 'A');
  assert.equal(App.state.views.active, 'advanced');
  for (const flow of ['deposit', 'transfer', 'withdraw']) {
    a.querySelector(`[data-quick-flow="${flow}"]`).click();
    assert.equal(App.state.selectedPoolId, 'A');
    assert.equal(App.state.views.active, 'move-funds');
    assert.equal(App.state.views.moveFlow, flow);
  }
  let history;
  const original = Dashboard.openHistory;
  Dashboard.openHistory = id => { history = id; };
  a.querySelector('[data-view-history]').click();
  assert.equal(history, 'A');
  Dashboard.openHistory = original;
});

test('in-flight refresh cannot recreate cards after a wallet disconnect', async () => {
  render();
  let resolve;
  globalThis.dashboardSdk = {
    account: () => ({ portfolio: () => new Promise(done => { resolve = done; }) }),
    operationalFeed: async () => [], recipientLookup: async () => ({}),
  };
  const pending = Dashboard.refresh();
  App.state.wallet.address = null;
  emit('wallet:disconnected');
  resolve([balance('A')]);
  await pending;
  assert.equal(grid.children.length, 0);
});

test('position flips, clamps width/height, scrolls internally, and follows scroll and resize', () => {
  const [a] = render();
  window.innerWidth = 320;
  window.innerHeight = 300;
  trigger(a).rect = { left: 270, right: 314, top: 240, bottom: 284 };
  trigger(a).click();
  assert.equal(panel(a).style.width, '304px');
  assert.equal(panel(a).style.left, '8px');
  assert.ok(parseFloat(panel(a).style.top) < 240);
  assert.match(panel(a).className, /overflow-y-auto/);
  const previous = panel(a).style.top;
  trigger(a).rect = { left: 100, right: 144, top: 200, bottom: 244 };
  window.innerHeight = 900;
  window.dispatch('scroll');
  assert.notEqual(panel(a).style.top, previous);
  window.innerWidth = 240;
  window.dispatch('resize');
  assert.equal(panel(a).style.width, '224px');
});

test('template provides a neutral 44px shield, visible keyboard focus and a focusable details heading', async () => {
  const html = await readFile(new URL('../../../app/index.html', import.meta.url), 'utf8');
  assert.match(html, /data-overview-pool-controls[^>]*class="[^"]*h-11 w-11[^"]*focus-visible:outline-2/);
  assert.match(html, /id="move-pool-controls-heading" tabindex="-1"/);
});
