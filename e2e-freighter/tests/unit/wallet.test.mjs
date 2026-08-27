import assert from 'node:assert/strict';
import test from 'node:test';

import {
  approveOrWatch,
  expectNoFreighterApproval,
  rejectInFreighter,
  switchFreighterAccount,
  waitForAnyFreighterApproval,
  waitForFreighterApproval,
} from '../../src/wallet.mjs';

const extensionUrl = (route = '') => `chrome-extension://bcacfldlkkdogcmkkibnjlakofdplcbk/index.html${route}`;

function fakePage({ route = '', buttons = [], closeBeforeWait = false } = {}) {
  let closed = false;
  const listeners = new Map();
  const clicks = [];
  const visibleButtons = new Set(buttons);
  const page = {
    url: () => extensionUrl(route),
    isClosed: () => closed,
    clicks,
    on(event, listener) {
      const bucket = listeners.get(event) || new Set();
      bucket.add(listener);
      listeners.set(event, bucket);
    },
    off(event, listener) { listeners.get(event)?.delete(listener); },
    listenerCount(event) { return listeners.get(event)?.size || 0; },
    close() {
      closed = true;
      for (const listener of [...(listeners.get('close') || [])]) listener();
    },
    getByRole(_role, { name }) {
      return { isVisible: async () => !closed && visibleButtons.has(name) };
    },
    getByText(text) {
      const locator = {
        first: () => locator,
        async waitFor() {
          if (closeBeforeWait) page.close();
          if (closed) throw new Error('page closed');
          if (!visibleButtons.has(text)) throw new Error(`${text} not visible`);
        },
        async click() {
          if (closed) throw new Error('page closed');
          clicks.push(text);
          visibleButtons.delete(text);
        },
      };
      return locator;
    },
  };
  return page;
}

function fakeContext(initialPages = []) {
  const allPages = initialPages;
  return { pages: () => allPages, allPages };
}

// switchFreighterAccount only touches the extension's account-view button
// and the `.detail-name` rows in the account list it opens, so the fake only
// needs to model those two locators (plus `goto`, which extensionHomePage
// calls unconditionally on the page it finds or creates). `confirmsSwitch`
// controls whether selecting a row actually updates the header text the
// post-click confirmation wait reads back — false reproduces the
// account-header-never-confirms case.
function fakeAccountSwitchPage({ initialActive = 'Account 2', visibleRows = [], confirmsSwitch = true } = {}) {
  const clicks = [];
  let active = initialActive;
  const page = {
    url: () => extensionUrl(),
    clicks,
    async goto() {},
    locator(selector, options) {
      if (selector === '[data-testid="account-view-account-name"]') {
        return {
          async waitFor() {},
          async click() { clicks.push('open-account-list'); },
          async innerText() { return active; },
        };
      }
      if (selector === '.detail-name') {
        const wanted = options?.hasText;
        const visible = visibleRows.includes(wanted);
        const row = {
          first: () => row,
          async waitFor() {
            if (!visible) throw new Error(`${wanted} not visible`);
          },
          async click() {
            clicks.push(`select:${wanted}`);
            if (confirmsSwitch) active = wanted;
          },
        };
        return row;
      }
      throw new Error(`fakeAccountSwitchPage: unexpected selector '${selector}'`);
    },
  };
  return page;
}

function advancingWaitOptions(onSleep = () => {}) {
  let now = 0;
  return {
    now: () => now,
    sleep: async (ms) => { now += ms; onSleep(); },
  };
}

test('discovers approvals in a dedicated popup and in an extension tab', async () => {
  const popup = fakePage({ route: '#/sign-transaction?request=1' });
  const popupContext = fakeContext([popup]);
  assert.equal(await waitForFreighterApproval(popupContext, 'signTransaction'), popup);

  const tab = fakePage({ buttons: ['Confirm'] });
  const tabContext = fakeContext([tab]);
  const found = await waitForAnyFreighterApproval(tabContext, ['signAuthEntry']);
  assert.deepEqual(found, { page: tab, kind: 'signAuthEntry' });
});

test('supports sequential approval kinds as extension pages change', async () => {
  const context = fakeContext();
  let firstSleep = true;
  const first = await waitForAnyFreighterApproval(context, ['signMessage', 'signTransaction'], {
    timeoutMs: 20,
    intervalMs: 5,
    waitOptions: advancingWaitOptions(() => {
      if (firstSleep) {
        firstSleep = false;
        context.allPages.push(fakePage({ route: '#/sign-message?request=1' }));
      }
    }),
  });
  assert.equal(first.kind, 'signMessage');

  context.allPages.splice(0, 1, fakePage({ route: '#/sign-transaction?request=2' }));
  const second = await waitForAnyFreighterApproval(context, ['signMessage', 'signTransaction']);
  assert.equal(second.kind, 'signTransaction');
});

test('approval timeout includes requested kinds and final extension pages', async () => {
  const context = fakeContext();
  await assert.rejects(
    waitForFreighterApproval(context, 'connect', {
      timeoutMs: 10,
      intervalMs: 5,
      waitOptions: advancingWaitOptions(),
    }),
    (error) => {
      assert.equal(error.operation, 'freighter-approval:connect');
      assert.deepEqual(error.lastObservedState, {
        approval: null,
        extensionPages: [],
        requestedKinds: ['connect'],
      });
      return true;
    },
  );
});

test('expectNoFreighterApproval succeeds only when the bounded approval wait times out', async () => {
  await assert.doesNotReject(expectNoFreighterApproval(fakeContext(), ['signTransaction'], {
    timeoutMs: 10,
    intervalMs: 5,
    waitOptions: advancingWaitOptions(),
  }));

  await assert.rejects(
    expectNoFreighterApproval(fakeContext([fakePage({ route: '#/sign-transaction' })]), ['signTransaction']),
    /unexpected Freighter approval: signTransaction/,
  );
});

test('auto approval and rejection click the expected extension controls', async () => {
  const approvePage = fakePage({ route: '#/sign-transaction', buttons: ['Confirm'] });
  const approved = await approveOrWatch(fakeContext([approvePage]), 'signTransaction', { mode: 'auto' });
  assert.equal(approved.pageClosed, false);
  assert.deepEqual(approvePage.clicks, ['Confirm']);

  const rejectPage = fakePage({ route: '#/sign-transaction', buttons: ['Cancel'] });
  const rejected = await rejectInFreighter(fakeContext([rejectPage]), 'signTransaction');
  assert.equal(rejected.pageClosed, false);
  assert.deepEqual(rejectPage.clicks, ['Cancel']);
});

test('handles an approval page closing before action and while a human approves', async () => {
  const closingPage = fakePage({ route: '#/sign-transaction', buttons: ['Confirm'], closeBeforeWait: true });
  const autoResult = await approveOrWatch(fakeContext([closingPage]), 'signTransaction', { mode: 'auto' });
  assert.equal(autoResult.pageClosed, true);

  const humanPage = fakePage({ route: '#/sign-message', buttons: ['Confirm'] });
  const humanPromise = approveOrWatch(fakeContext([humanPage]), 'signMessage', { mode: 'human' });
  await new Promise((resolve) => setImmediate(resolve));
  humanPage.close();
  const humanResult = await humanPromise;
  assert.equal(humanResult.pageClosed, true);
  assert.equal(humanPage.listenerCount('close'), 0);
});

test('switchFreighterAccount opens the account list, selects the named row, and confirms the header updated', async () => {
  const page = fakeAccountSwitchPage({ visibleRows: ['Account 2', 'Account 3'] });
  const context = fakeContext([page]);

  const result = await switchFreighterAccount(context, 'Account 3');

  assert.equal(result, page);
  assert.deepEqual(page.clicks, ['open-account-list', 'select:Account 3']);
});

test('switchFreighterAccount reuses an already-open extension page instead of opening a new one', async () => {
  const page = fakeAccountSwitchPage({ initialActive: 'Account 2', visibleRows: ['Account 2'] });
  let newPageCalls = 0;
  const context = {
    pages: () => [page],
    newPage: async () => { newPageCalls += 1; throw new Error('should not open a new page'); },
  };

  await switchFreighterAccount(context, 'Account 2');

  assert.equal(newPageCalls, 0);
});

test('switchFreighterAccount rejects when the named account row never appears', async () => {
  const page = fakeAccountSwitchPage({ visibleRows: ['Account 2'] });
  const context = fakeContext([page]);

  await assert.rejects(switchFreighterAccount(context, 'Account 3'), /Account 3 not visible/);
  // The account list was still opened before the row lookup failed.
  assert.deepEqual(page.clicks, ['open-account-list']);
});

test('switchFreighterAccount rejects if the row is clicked but the header never confirms the switch', async () => {
  // Reproduces the real flake this guards against: the row click resolves,
  // but Freighter's own commit of the new active account (redux store +
  // extension-storage write) never lands, so the header keeps showing the
  // previously active account.
  const page = fakeAccountSwitchPage({
    initialActive: 'Account 2',
    visibleRows: ['Account 2', 'Account 3'],
    confirmsSwitch: false,
  });
  const context = fakeContext([page]);

  await assert.rejects(
    switchFreighterAccount(context, 'Account 3', { timeoutMs: 20, waitOptions: advancingWaitOptions() }),
    /account header never confirmed the switch/,
  );
  assert.deepEqual(page.clicks, ['open-account-list', 'select:Account 3']);
});
