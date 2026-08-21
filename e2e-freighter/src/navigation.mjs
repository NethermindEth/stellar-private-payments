// Top-level view navigation helpers. The production UI exposes matching nav
// and panel state, so navigation completes when the requested view is actually
// active instead of after an arbitrary transition delay.

import { waitForCondition } from './waits.mjs';

async function gotoView(page, view) {
  const nav = page.getByTestId(`nav-${view}`);
  const panel = page.getByTestId(`view-${view}`);
  await nav.click();

  return waitForCondition({
    operation: `navigate:${view}`,
    observe: async () => ({
      panelVisible: await panel.isVisible(),
      panelState: await panel.getAttribute('data-state'),
      navCurrent: await nav.getAttribute('aria-current'),
    }),
    isReady: ({ panelVisible, panelState, navCurrent }) => (
      panelVisible && panelState === 'active' && navCurrent === 'page'
    ),
  });
}

export async function gotoDashboard(page) {
  return gotoView(page, 'dashboard');
}

export async function gotoMoveFunds(page) {
  return gotoView(page, 'move-funds');
}

export async function gotoMoveFlow(page, flow) {
  const tab = page.getByTestId(`move-flow-${flow}`);
  const panel = page.getByTestId(`move-panel-${flow}`);
  await tab.click();

  return waitForCondition({
    operation: `move-flow:${flow}`,
    observe: async () => ({
      panelVisible: await panel.isVisible(),
      panelState: await panel.getAttribute('data-state'),
      tabState: await tab.getAttribute('data-state'),
      tabPressed: await tab.getAttribute('aria-pressed'),
    }),
    isReady: ({ panelVisible, panelState, tabState, tabPressed }) => (
      panelVisible && panelState === 'active' && tabState === 'active' && tabPressed === 'true'
    ),
  });
}

export async function gotoAdvanced(page) {
  return gotoView(page, 'advanced');
}

export async function gotoDisclosure(page) {
  return gotoView(page, 'disclosure');
}
