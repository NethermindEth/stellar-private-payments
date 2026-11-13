import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { Element, installDom, balanceCard } from '../helpers/ui-dom.mjs';

installDom();
const { App } = await import('../../../app/js/ui/core.js');
const { POOL_CONTROLS, poolControls } = await import('../../../app/js/pool-policy.js');
const { PoolDepositStatus } = await import('../../../app/js/ui/pool-deposit-status.js');
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
const moveDepositStatus = new Element('p', { id: 'move-pool-deposit-status' });
const depositButton = new Element('button', { id: 'btn-deposit' });
const selectors = [new Element('select', { dataset: { poolSelect: '' } }), new Element('select', { dataset: { poolSelect: '' } })];
const views = ['dashboard', 'move-funds', 'advanced'].map(view => new Element('button', { dataset: { view } }));
const flows = ['deposit', 'transfer', 'withdraw'].map(moveFlow => new Element('button', { dataset: { moveFlow } }));
document.body.append(grid, heading, moveDepositStatus, depositButton, ...selectors, ...views, ...flows);
App.templates.balanceCard = { content: { cloneNode: () => ({ firstElementChild: balanceCard() }) } };
document.body.append(
  new Element('dialog', { id: 'settings-drawer' }),
  new Element('div', { dataset: { signingAccount: 'move' } }),
  new Element('p', { dataset: { maxSpend: '' } }),
);
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
const isOpen = card => panel(card).matches(':popover-open');
const statusData = (contractId, depositsPaused) => ({ pools: [{ contractId, depositsPaused }] });
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
  globalThis.dashboardSdk = { poolContractsData: async id => statusData(id, false) };
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
      const triggers = card.querySelectorAll('[data-overview-pool-controls]');
      const panels = card.querySelectorAll('section');
      assert.equal(triggers.length, controls.length);
      controls.forEach((key, index) => {
        // An element created outside the SVG namespace does not render.
        const icon = triggers[index].querySelector('svg');
        assert.equal(icon?.namespaceURI, 'http://www.w3.org/2000/svg');
        assert.equal(icon.getAttribute('aria-hidden'), 'true');
        assert.ok(icon.children.length > 0);
        for (const shape of icon.children) assert.equal(shape.namespaceURI, icon.namespaceURI);
        assert.equal(triggers[index].getAttribute('aria-label'), `Pool controls: ${POOL_CONTROLS[key].tag}`);
        assert.equal(triggers[index].getAttribute('aria-controls'), panels[index].id);
        assert.equal(panels[index].children[0].textContent, POOL_CONTROLS[key].tag);
        assert.deepEqual(panels[index].querySelectorAll('[data-pool-control-row]').map(row => row.children.map(node => node.textContent)), [[POOL_CONTROLS[key].tag, POOL_CONTROLS[key].explanation]]);
        triggers[index].click();
        assert.equal(panels[index].matches(':popover-open'), true);
        panels.forEach((other, otherIndex) => {
          if (otherIndex !== index) assert.equal(other.matches(':popover-open'), false);
        });
      });
    }
  }
});

test('same-asset cards use their own IDs while a third pool is selected', () => {
  const [a, b] = render();
  assert.notEqual(panel(a).id, panel(b).id);
  assert.match(trigger(a).getAttribute('aria-label'), /Blocklist/);
  assert.match(trigger(b).getAttribute('aria-label'), /Open/);
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
    assert.equal(isOpen(card), false);
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
  assert.equal(isOpen(card), true);
  App.state.pools.push(pool('UNKNOWN'));
  emit('pool:config');
  assert.equal(isOpen(card), false);
  assert.equal(trigger(card).getAttribute('aria-label'), 'Pool controls: Open');
  assert.ok(details(card));
});

test('toggle, one-open-only, no focus activation and outside dismissal', () => {
  const [a, b] = render();
  trigger(a).focus();
  assert.equal(isOpen(a), false);
  trigger(a).click();
  assert.equal(trigger(a).getAttribute('aria-expanded'), 'true');
  assert.equal(isOpen(a), true);
  panel(a).click();
  assert.equal(isOpen(a), true);
  trigger(b).click();
  assert.equal(isOpen(a), false);
  assert.equal(trigger(a).getAttribute('aria-expanded'), 'false');
  assert.equal(isOpen(b), true);
  trigger(b).click();
  assert.equal(isOpen(b), false);
  trigger(a).click();
  document.body.click();
  assert.equal(isOpen(a), false);
});

test('mouse hover opens immediately, crosses the popup gap, and closes after leaving', (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const [a, b] = render();
  trigger(a).dispatch('pointerenter', { pointerType: 'touch' });
  assert.equal(isOpen(a), false);
  trigger(a).dispatch('pointerenter', { pointerType: 'mouse' });
  assert.equal(isOpen(a), true);
  trigger(a).dispatch('click', { detail: 1 });
  assert.equal(isOpen(a), true, 'mouse click does not undo hover');
  trigger(a).dispatch('pointerleave', { pointerType: 'mouse' });
  t.mock.timers.tick(100);
  assert.equal(isOpen(a), true, 'popup stays open while crossing the gap');
  panel(a).dispatch('pointerenter', { pointerType: 'mouse' });
  t.mock.timers.tick(200);
  assert.equal(isOpen(a), true);
  panel(a).dispatch('pointerleave', { pointerType: 'mouse' });
  details(a).focus();
  t.mock.timers.tick(200);
  assert.equal(isOpen(a), true, 'keyboard focus inside keeps the popup accessible');
  document.body.focus();
  panel(a).dispatch('focusout');
  t.mock.timers.tick(200);
  assert.equal(isOpen(a), false);
  trigger(a).dispatch('pointerenter', { pointerType: 'mouse' });
  trigger(b).dispatch('pointerenter', { pointerType: 'mouse' });
  assert.equal(isOpen(a), false);
  assert.equal(isOpen(b), true);
  trigger(b).dispatch('pointerleave', { pointerType: 'mouse' });
  t.mock.timers.tick(200);
  assert.equal(isOpen(b), false);
});

test('Escape returns focus from inside, leaves outside focus alone and prevents default only when open', () => {
  const [a, b] = render();
  trigger(a).click();
  details(a).focus();
  assert.equal(details(a).dispatch('keydown', { key: 'Escape' }).defaultPrevented, true);
  assert.equal(isOpen(a), false);
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
  assert.equal(isOpen(a), true);
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
  assert.equal(isOpen(a), false);
  assert.equal(document.activeElement, trigger(a));
  assert.equal(trigger(a).getAttribute('aria-label'), 'Pool controls: Allowlist');
  trigger(a).click();
  render([A, B, C], [balance('B')]);
  assert.equal(a.isConnected, false);
  assert.equal(isOpen(a), false);
});

test('navigation, disconnect and clear close the disclosure', () => {
  const [a] = render();
  trigger(a).click();
  views[1].click();
  assert.equal(isOpen(a), false);
  trigger(a).click();
  emit('wallet:disconnected');
  assert.equal(isOpen(a), false);
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

test('template provides wrapping badges with visible keyboard focus and a focusable details heading', async () => {
  const html = await readFile(new URL('../../../app/index.html', import.meta.url), 'utf8');
  assert.match(html, /data-pool-badges/);
  assert.match(html, /id="move-pool-controls-heading" tabindex="-1"/);
});

test('live statuses use the card pool ID, update an open popover in place and disable only its deposit action', async () => {
  const [a, b] = render();
  trigger(a).click();
  const action = details(a);
  action.focus();
  const ids = [];
  const sdk = { poolContractsData: async id => {
    ids.push(id);
    return statusData(id, id === 'A');
  } };
  assert.equal(a.querySelector('[data-pool-deposit-status]').hidden, true);
  assert.equal(a.querySelector('[data-pool-paused-indicator]').hidden, true);
  await PoolDepositStatus.refresh(sdk);
  assert.deepEqual(ids, ['A', 'B', 'C']);
  assert.equal(App.state.selectedPoolId, 'C');
  assert.equal(a.querySelector('[data-pool-deposit-status]').textContent, 'Deposits paused');
  assert.equal(a.querySelector('[data-pool-deposit-status]').hidden, false);
  assert.equal(a.querySelector('[data-pool-paused-indicator]').hidden, false);
  assert.equal(a.querySelector('[data-quick-flow="deposit"]').disabled, true);
  assert.equal(b.querySelector('[data-quick-flow="deposit"]').disabled, false);
  assert.equal(b.querySelector('[data-pool-deposit-status]').hidden, true);
  assert.equal(panel(a).querySelector('[data-overview-deposit-status]').textContent, 'Deposits are paused. Transfers and withdrawals still work.');
  assert.equal(isOpen(a), true);
  assert.equal(details(a), action);
  assert.equal(document.activeElement, action);
  assert.match(trigger(a).getAttribute('aria-label'), /Blocklist/);
  a.querySelector('[data-quick-flow="deposit"]').click();
  assert.equal(App.state.views.active, 'dashboard');
  assert.equal(App.state.selectedPoolId, 'C');
  for (const flow of ['transfer', 'withdraw']) {
    assert.notEqual(a.querySelector(`[data-quick-flow="${flow}"]`).disabled, true);
    a.querySelector(`[data-quick-flow="${flow}"]`).click();
    assert.equal(App.state.views.moveFlow, flow);
    assert.equal(App.state.selectedPoolId, 'A');
  }
  assert.equal(depositButton.disabled, true);
  assert.equal(moveDepositStatus.textContent, 'Deposits are paused. Transfers and withdrawals still work.');
});

test('pause and unpause changes update both views without affecting an in-flight deposit', async () => {
  const [a] = render();
  let paused = true;
  const sdk = { poolContractsData: async id => statusData(id, paused) };
  await PoolDepositStatus.refresh(sdk);
  emit('dashboard:view-pool-controls', { poolId: 'A' });
  assert.equal(depositButton.disabled, true);
  paused = false;
  depositButton.dataset.status = 'submitting';
  await PoolDepositStatus.refresh(sdk);
  assert.equal(depositButton.disabled, true, 'a refresh cannot re-enable a busy button');
  assert.equal(a.querySelector('[data-quick-flow="deposit"]').disabled, false);
  depositButton.dataset.status = 'idle';
  PoolDepositStatus.renderMoveFunds();
  assert.equal(depositButton.disabled, false);
  assert.equal(moveDepositStatus.hidden, true);
  assert.equal(a.querySelector('[data-pool-deposit-status]').hidden, true);
});

test('one failed pool becomes unavailable while other same-asset pools keep updating', async () => {
  const [a, b] = render();
  await PoolDepositStatus.refresh({ poolContractsData: async id => {
    if (id === 'A') throw new Error('RPC unavailable');
    return statusData(id, false);
  } });
  assert.equal(PoolDepositStatus.get('A'), 'unavailable');
  assert.equal(a.querySelector('[data-pool-deposit-status]').hidden, true);
  assert.equal(a.querySelector('[data-pool-paused-indicator]').hidden, true);
  assert.equal(PoolDepositStatus.get('B'), 'accepting');
  assert.equal(b.querySelector('[data-pool-deposit-status]').hidden, true);
  assert.equal(PoolDepositStatus.get('UNKNOWN'), 'unavailable');
  emit('dashboard:view-pool-controls', { poolId: 'A' });
  assert.match(moveDepositStatus.textContent, /unavailable/);
  await PoolDepositStatus.refresh(globalThis.dashboardSdk);
  assert.equal(PoolDepositStatus.get('A'), 'accepting');
  assert.equal(a.querySelector('[data-pool-deposit-status]').hidden, true);
  await PoolDepositStatus.refresh({ poolContractsData: async () => { throw new Error('offline'); } });
  assert.equal(PoolDepositStatus.get('A'), 'unavailable', 'failed refresh never retains an enabled status');
});

test('a slow pool does not delay another status or duplicate reads on overlapping refreshes', async () => {
  render();
  const reads = [];
  let finish;
  const sdk = { poolContractsData: async id => {
    reads.push(id);
    if (id === 'A') return new Promise(done => { finish = done; });
    return statusData(id, id === 'B');
  } };
  const first = PoolDepositStatus.refresh(sdk);
  await Promise.resolve();
  assert.equal(PoolDepositStatus.get('A'), 'loading');
  assert.equal(PoolDepositStatus.get('B'), 'paused');
  const second = PoolDepositStatus.refresh(sdk);
  assert.deepEqual(reads, ['A', 'B', 'C']);
  finish(statusData('A', false));
  await Promise.all([first, second]);
  assert.equal(PoolDepositStatus.get('A'), 'accepting');
});

test('late reads after disconnect cannot overwrite a reconnected session or a removed pool', async () => {
  render();
  let finish;
  const sdk = { poolContractsData: async id => {
    if (id === 'A') return new Promise(done => { finish = done; });
    return statusData(id, false);
  } };
  const old = PoolDepositStatus.refresh(sdk);
  emit('wallet:disconnected');
  render();
  await PoolDepositStatus.refresh({ poolContractsData: async id => statusData(id, true) });
  finish(statusData('A', false));
  await old;
  assert.equal(PoolDepositStatus.get('A'), 'paused');
  const removed = PoolDepositStatus.refresh(sdk);
  App.state.pools = [B, C];
  assert.equal(PoolDepositStatus.get('A'), 'unavailable');
  finish(statusData('A', false));
  await removed;
  // The removed pool cannot receive the response. Its old entry is pruned
  // at the next refresh and must be read again if configured later.
  await PoolDepositStatus.refresh(globalThis.dashboardSdk);
  assert.equal(PoolDepositStatus.get('A'), 'unavailable');
});

test('malformed and mismatched pool responses never become deposits enabled', async () => {
  render();
  for (const response of [
    { pools: [] },
    { pools: [{ contractId: 'OTHER', depositsPaused: false }] },
    { pools: [{ contractId: 'A' }] },
    statusData('A', 'false'),
  ]) {
    await PoolDepositStatus.refresh({ poolContractsData: async () => response });
    assert.equal(PoolDepositStatus.get('A'), 'unavailable');
  }
});

test('dashboard refresh reads live statuses even when portfolio refresh fails', async (t) => {
  const warnings = [];
  t.mock.method(console, 'warn', (...args) => warnings.push(args[0]));
  const [a] = render();
  globalThis.dashboardSdk = {
    poolContractsData: async id => statusData(id, id === 'A'),
    account: () => ({ portfolio: async () => { throw new Error('portfolio unavailable'); } }),
    operationalFeed: async () => [], recipientLookup: async () => ({}),
  };
  await Dashboard.refresh();
  assert.equal(a.querySelector('[data-quick-flow="deposit"]').disabled, true);
  assert.deepEqual(warnings, ['[Dashboard] balances refresh failed:']);
});
