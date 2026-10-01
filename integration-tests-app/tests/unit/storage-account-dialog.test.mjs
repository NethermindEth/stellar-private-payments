import assert from 'node:assert/strict';
import test from 'node:test';
import { confirmStorageAccount } from '../../../app/js/storage-account-dialog.js';

function documentFixture(t) {
  const elements = [];
  const document = {
    body: { append() {} },
    createElement(tag) {
      const element = {
        tag, dataset: {}, handlers: {}, children: [],
        setAttribute() {},
        addEventListener(name, callback) { this.handlers[name] = callback; },
        append(...children) { this.children.push(...children); },
        showModal() {}, close() {}, remove() { this.removed = true; },
      };
      elements.push(element);
      return element;
    },
  };
  const previous = globalThis.document;
  globalThis.document = document;
  t.after(() => { globalThis.document = previous; });
  return elements;
}

test('enrollment displays wallet account changes live and stops watching on confirmation', async t => {
  const elements = documentFixture(t);
  let onChange;
  let stopped = false;
  const result = confirmStorageAccount({ address: 'owner-a', fresh: true,
    watchAccount: options => {
      onChange = options.onChange;
      return () => { stopped = true; };
    },
  });
  const account = elements.find(element => element.textContent === 'owner-a');
  const proceed = elements.find(element => element.dataset.testid === 'storage-account-continue');
  onChange({ address: 'owner-b' });
  assert.equal(account.textContent, 'owner-b');
  assert.equal(proceed.disabled, false);
  onChange({ address: '' });
  assert.equal(proceed.disabled, true);
  assert.match(account.textContent, /Select an account/);
  onChange({ address: 'owner-c' });
  assert.equal(account.textContent, 'owner-c');
  assert.equal(proceed.disabled, false);
  proceed.handlers.click();
  assert.equal(await result, 'owner-c');
  assert.equal(stopped, true);
  assert.equal(elements[0].removed, true);
  onChange({ address: 'owner-d' });
  assert.equal(account.textContent, 'owner-c');
});

test('cancellation stops watching and existing unlocks keep the enrolled account', async t => {
  const elements = documentFixture(t);
  let stopped = false;
  const result = confirmStorageAccount({ address: 'owner-a', fresh: true,
    watchAccount: () => () => { stopped = true; },
  });
  elements.find(element => element.textContent === 'Cancel').handlers.click();
  await assert.rejects(result, { code: 'unlock-cancelled' });
  assert.equal(stopped, true);
  elements.length = 0;
  const existing = confirmStorageAccount({ address: 'owner-a', fresh: false,
    watchAccount: () => assert.fail('must not replace the enrolled account with the active account'),
  });
  elements.find(element => element.dataset.testid === 'storage-account-continue').handlers.click();
  assert.equal(await existing, 'owner-a');
});
