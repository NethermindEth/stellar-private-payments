import assert from 'node:assert/strict';
import test from 'node:test';

import {
  gotoAdvanced,
  gotoDashboard,
  gotoDisclosure,
  gotoMoveFlow,
  gotoMoveFunds,
} from '../../src/navigation.mjs';

function pageWithViews() {
  let activeView = 'dashboard';

  return {
    getByTestId(testId) {
      const [kind, ...parts] = testId.split('-');
      const view = parts.join('-');

      if (kind === 'nav') {
        return {
          async click() { activeView = view; },
          async getAttribute(name) {
            return name === 'aria-current' && activeView === view ? 'page' : null;
          },
        };
      }

      if (kind === 'view') {
        return {
          async isVisible() { return activeView === view; },
          async getAttribute(name) {
            return name === 'data-state' && activeView === view ? 'active' : 'inactive';
          },
        };
      }

      throw new Error(`Unexpected test id: ${testId}`);
    },
  };
}

function pageWithMoveFlows() {
  let activeFlow = 'deposit';
  return {
    getByTestId(testId) {
      const [, kind, ...parts] = testId.split('-');
      const flow = parts.join('-');
      if (kind === 'flow') {
        return {
          async click() { activeFlow = flow; },
          async getAttribute(name) {
            if (name === 'data-state') return activeFlow === flow ? 'active' : 'inactive';
            if (name === 'aria-pressed') return activeFlow === flow ? 'true' : 'false';
            return null;
          },
        };
      }
      if (kind === 'panel') {
        return {
          async isVisible() { return activeFlow === flow; },
          async getAttribute(name) { return name === 'data-state' && activeFlow === flow ? 'active' : 'inactive'; },
        };
      }
      throw new Error(`Unexpected test id: ${testId}`);
    },
  };
}

for (const [name, navigate] of [
  ['dashboard', gotoDashboard],
  ['move-funds', gotoMoveFunds],
  ['advanced', gotoAdvanced],
  ['disclosure', gotoDisclosure],
]) {
  test(`goto${name} waits for active navigation and panel state`, async () => {
    const result = await navigate(pageWithViews());
    assert.equal(result.value.panelVisible, true);
    assert.equal(result.value.panelState, 'active');
    assert.equal(result.value.navCurrent, 'page');
  });
}

test('gotoMoveFlow waits for the selected tab and panel state', async () => {
  const result = await gotoMoveFlow(pageWithMoveFlows(), 'transfer');
  assert.equal(result.value.panelVisible, true);
  assert.equal(result.value.panelState, 'active');
  assert.equal(result.value.tabPressed, 'true');
});
