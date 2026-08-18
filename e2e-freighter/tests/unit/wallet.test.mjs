import assert from 'node:assert/strict';
import test from 'node:test';

import {
  approveOrWatch,
  expectNoFreighterApproval,
  rejectInFreighter,
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
