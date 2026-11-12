// DOM-only Chrome regression suite: production HTML/CSS and UI modules, with
// wallet/RPC dependencies stubbed. No wallet, network or blockchain required.
// First compile CSS with the project's Tailwind version, then run:
// node integration-tests-app/tests/browser/overview-pool-controls.mjs /path/to/app.css
import assert from 'node:assert/strict';
import { readFile, mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import { build } from '../../../app/node_modules/esbuild/lib/main.js';

const root = fileURLToPath(new URL('../../../', import.meta.url));
const css = await readFile(process.argv[2], 'utf8');
const html = (await readFile(join(root, 'app/index.html'), 'utf8'))
  .replace(/<script\b[^>]*>[\s\S]*?<\/script>/g, '')
  .replace(/<link\b[^>]*>/g, '')
  .replace('</head>', '<link rel="stylesheet" href="/app.css"></head>')
  .replace('</body>', '<script src="/fixture.js"></script></body>');
const bundle = await build({
  stdin: {
    resolveDir: root,
    contents: `
      import { App } from './app/js/ui/core.js';
      import { Templates } from './app/js/ui/templates.js';
      import { Dashboard } from './app/js/ui/dashboard.js';
      import { Shell } from './app/js/ui/navigation.js';
      import { PoolControls } from './app/js/ui/pool-controls.js';
      Templates.init(); Shell.init(); Dashboard.init(); PoolControls.init();
      document.getElementById('storage-locked-notice').hidden = true;
      window.overviewFixture = { App, Dashboard, set(pools, balances) {
        App.state.wallet.address = 'TEST_OWNER';
        App.state.wallet.connected = true;
        App.state.pools = pools;
        App.state.balances = balances;
        App.state.selectedPoolId = 'C';
        document.querySelectorAll('[data-pool-select]').forEach(select => {
          select.replaceChildren(...pools.map(pool => {
            const option = document.createElement('option');
            option.value = pool.poolContractId; option.textContent = pool.poolContractId; return option;
          }));
          select.value = 'C';
        });
        App.events.dispatchEvent(new CustomEvent('pool:selected'));
        Dashboard.renderBalances();
      }};
    `,
  },
  bundle: true, write: false, format: 'iife',
  plugins: [{
    name: 'wallet-boundary',
    setup(builder) {
      builder.onResolve({ filter: /.*/ }, async args => {
        const navigationDependency = args.importer.endsWith('/ui/navigation.js') && !['./core.js', '../pool-policy.js', '../network-config.js'].includes(args.path);
        if (!navigationDependency && !args.path.endsWith('wasm-facade.js') && !args.path.endsWith('op-history.js')) return;
        const source = await readFile(args.importer, 'utf8');
        const names = new Set([...source.matchAll(/^import\s+\{([^}]+)\}\s+from\s+['"]([^'"]+)['"]/gm)]
          .filter(match => match[2] === args.path).flatMap(match => match[1].split(',').map(name => name.trim()).filter(Boolean)));
        return { path: `${args.importer}:${args.path}`, namespace: 'wallet-stub', pluginData: [...names] };
      });
      builder.onLoad({ filter: /.*/, namespace: 'wallet-stub' }, args => ({
        contents: args.pluginData.map(name => name === 'OpHistory' ? 'export const OpHistory = {list: async () => []};' : `export const ${name} = () => null;`).join('\n'),
      }));
    },
  }],
});
const server = createServer((request, response) => {
  const [type, data] = request.url === '/fixture.js' ? ['text/javascript', bundle.outputFiles[0].text]
    : request.url === '/app.css' ? ['text/css', css] : ['text/html', html];
  response.writeHead(200, { 'Content-Type': type }); response.end(data);
});
await new Promise(done => server.listen(0, '127.0.0.1', done));
const url = `http://127.0.0.1:${server.address().port}`;
const screenshotDir = await mkdtemp(join(tmpdir(), 'overview-controls-'));
const browser = await chromium.launch({ channel: 'chrome', headless: true });
const pool = (poolContractId, policyFlags = [], gvkMode = 'off') => ({ poolContractId, policyFlags, gvkMode, asset: { kind: 'native' }, decimals: 7 });
const pools = [pool('A', ['blocklist'], 'traceable'), pool('B', [], 'viewOnly'), pool('C', ['allowlist', 'blocklist'])];
const balance = id => ({ poolContractId: id, tokenContractId: 'TOKEN', tokenLabel: 'XLM', amount: '10000000', noteCount: 1 });
const balances = pools.slice(0, 2).map(pool => balance(pool.poolContractId));
try {
  for (const viewport of [{ width: 1280, height: 900 }, { width: 375, height: 667 }]) {
    const context = await browser.newContext({ viewport, hasTouch: viewport.width < 600 });
    const page = await context.newPage();
    page.setDefaultTimeout(10_000);
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.goto(url);
    await page.evaluate(({ pools, balances }) => window.overviewFixture.set(pools, balances), { pools, balances });
    const a = page.locator('article[data-pool-id="A"]');
    const b = page.locator('article[data-pool-id="B"]');
    const shield = a.locator('[data-overview-pool-controls]');
    const panel = a.locator('section');
    const details = panel.getByRole('link', { name: 'Details in Move funds' });
    assert.equal(await shield.getAttribute('aria-label'), 'Pool controls: Blocklist, Admin view key · traceable');
    assert.equal(await panel.isVisible(), false);
    assert.equal(await a.getByRole('link', { name: 'Details in Move funds' }).count(), 0, 'hidden panel excluded from accessible roles');
    const target = await shield.boundingBox();
    assert.equal(target.width, 44); assert.equal(target.height, 44);
    await shield.focus();
    assert.equal(await panel.isVisible(), false, 'focus does not open');
    await page.keyboard.press('Enter');
    assert.equal(await panel.isVisible(), true);
    await page.keyboard.press('Tab');
    assert.equal(await details.evaluate(node => node === document.activeElement), true, 'Tab enters disclosure normally');
    await page.keyboard.press('Tab');
    assert.equal(await panel.evaluate(node => node.contains(document.activeElement)), false, 'Tab leaves without a focus trap');
    await page.keyboard.press('Shift+Tab');
    assert.equal(await details.evaluate(node => node === document.activeElement), true);
    await page.keyboard.press('Escape');
    assert.equal(await shield.evaluate(node => node === document.activeElement), true);
    assert.equal(await panel.isVisible(), false);
    const focus = await shield.evaluate(node => ({ width: getComputedStyle(node).outlineWidth, style: getComputedStyle(node).outlineStyle }));
    assert.notEqual(focus.width, '0px'); assert.notEqual(focus.style, 'none');
    await page.keyboard.press('Space');
    assert.equal(await panel.isVisible(), true);
    await page.keyboard.press('Tab');
    const retained = await page.evaluate(() => {
      const { App, Dashboard } = window.overviewFixture;
      const active = document.activeElement;
      App.state.balances = App.state.balances.map(balance => ({ ...balance, amount: '25000000', noteCount: 2 })).reverse();
      Dashboard.renderBalances();
      App.state.balances.reverse();
      Dashboard.renderBalances(); Dashboard.renderBalances();
      return active === document.activeElement;
    });
    assert.equal(retained, true, 'refresh and reorder preserve focus');
    assert.equal(await panel.isVisible(), true);
    assert.equal(await panel.evaluate(node => node.matches(':popover-open')), true, 'moving the open card preserves its top layer');
    await details.click();
    assert.deepEqual(await page.evaluate(() => ({
      pool: window.overviewFixture.App.state.selectedPoolId,
      selectors: [...document.querySelectorAll('[data-pool-select]')].map(select => select.value),
      focus: document.activeElement.id,
    })), { pool: 'A', selectors: ['A', 'A'], focus: 'move-pool-controls-heading' });
    assert.deepEqual(await page.locator('[data-pool-controls="move"] [data-pool-controls-tags] button').allTextContents(), ['Blocklist', 'Admin view key · traceable']);
    await page.getByTestId('nav-dashboard').click();
    await page.getByTestId('nav-move-funds').click();
    await page.locator('[data-move-flow="withdraw"]').click();
    await page.getByTestId('nav-dashboard').click();
    await shield.click(); await details.click();
    assert.equal(await page.evaluate(() => window.overviewFixture.App.state.views.moveFlow), 'withdraw');
    await page.getByTestId('nav-dashboard').click();
    await shield.click();
    await b.locator('[data-overview-pool-controls]').click();
    assert.equal(await panel.isVisible(), false);
    assert.equal(await b.locator('section').isVisible(), true);
    await b.locator('section').getByRole('link', { name: 'Details in Move funds' }).click();
    assert.equal(await page.evaluate(() => window.overviewFixture.App.state.selectedPoolId), 'B');
    await page.getByTestId('nav-dashboard').click();
    await shield.scrollIntoViewIfNeeded();
    if (viewport.width < 600) await shield.tap(); else await shield.click();
    assert.equal(await panel.isVisible(), true);
    const assertBounds = async () => {
      const box = await panel.boundingBox();
      const size = page.viewportSize();
      assert.ok(box.x >= 7 && box.y >= 7 && box.x + box.width <= size.width - 7 && box.y + box.height <= size.height - 7, JSON.stringify({ viewport: size, box }));
      assert.equal(await panel.evaluate(node => node.matches(':popover-open')), true);
    };
    await assertBounds();
    await page.screenshot({ path: join(screenshotDir, `${viewport.width}.png`) });
    const beforeScroll = await shield.boundingBox();
    await page.evaluate(() => { document.body.style.minHeight = '300vh'; window.scrollBy(0, 20); });
    await page.waitForFunction(previous => document.querySelector('article[data-pool-id="A"] [data-overview-pool-controls]').getBoundingClientRect().top !== previous, beforeScroll.y);
    await assertBounds();
    // Force the trigger to the viewport bottom to exercise flipping and
    // limited height while retaining the real backdrop-filter ancestors.
    await shield.evaluate((node, viewport) => {
      const article = node.closest('article');
      const ancestors = []; for (let parent = article.parentElement; parent; parent = parent.parentElement) ancestors.push(parent);
      ancestors.forEach(parent => parent.style.backdropFilter = 'none');
      article.style.position = 'fixed'; article.style.top = `${viewport.height - 70}px`; article.style.right = '20px'; article.style.zIndex = '10';
      window.dispatchEvent(new Event('resize'));
    }, viewport);
    await assertBounds();
    const [triggerBox, panelBox] = await Promise.all([shield.boundingBox(), panel.boundingBox()]);
    assert.ok(panelBox.y + panelBox.height <= triggerBox.y - 7, 'flips above near bottom');
    await page.setViewportSize({ width: 320, height: 240 });
    await a.evaluate(node => { node.style.top = '170px'; window.dispatchEvent(new Event('resize')); });
    await assertBounds();
    assert.equal(await panel.evaluate(node => node.scrollHeight > node.clientHeight), true, 'small viewport constrains panel height');
    await panel.evaluate(node => { node.scrollTop = node.scrollHeight; });
    assert.ok(await panel.evaluate(node => node.scrollTop) > 0, 'panel scrolls internally');
    if (viewport.width < 600) await page.touchscreen.tap(2, 2); else await page.mouse.click(2, 2);
    assert.equal(await panel.isVisible(), false, 'outside click dismisses');
    if (viewport.width < 600) await shield.tap(); else await shield.click();
    assert.equal(await panel.isVisible(), true);
    await page.evaluate(() => {
      window.overviewFixture.App.events.dispatchEvent(new CustomEvent('wallet:disconnected'));
    });
    assert.equal(await page.locator('[data-overview-pool-controls]').count(), 0);
    assert.deepEqual(errors, []);
    console.log(`PASS keyboard, touch, refresh/focus, same-asset navigation, scroll and viewport bounds at ${viewport.width}x${viewport.height} and 320x240`);
    await context.close();
  }
  console.log(`Screenshots: ${screenshotDir}`);
} finally {
  await browser.close();
  await new Promise(done => server.close(done));
}
