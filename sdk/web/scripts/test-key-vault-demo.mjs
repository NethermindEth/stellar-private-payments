import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';
import { DatabaseKeyVault } from '../js/key-vault.js';
import { MemoryKeyStore, fakeCredentials } from './key-vault-fixture.mjs';

// Exercise the real page controller with synthetic DOM events and real crypto.
// Only DOM, persistence and authenticator boundaries are substituted here.
const html = await readFile(new URL('./key-vault-demo.html', import.meta.url), 'utf8');
const source = await readFile(new URL('./key-vault-demo.js', import.meta.url), 'utf8');
class Element {
  value = ''; hidden = false; disabled = false; textContent = ''; dataset = {};
  events = {}; children = []; focused = false; scrolled = false;
  constructor(tag) { this.tag = tag; }
  addEventListener(name, callback) { this.events[name] = callback; }
  append(item) { this.children.push(item); }
  focus() { this.focused = true; }
  scrollIntoView() { this.scrolled = true; }
  reportValidity() { return true; }
}
async function page(store, fake, persisted = new Map()) {
  const elements = Object.fromEntries([...html.matchAll(/<(\w+)\b[^>]*\bid="([^"]+)"/g)].map(m => [m[2], new Element(m[1])]));
  const reports = [];
  class Vault extends DatabaseKeyVault {
    constructor() { super({ databaseId: 'spp.key-vault-demo.v1', store, credentials: fake.credentials, origin: 'https://vault.test' }); }
  }
  const context = vm.createContext({ crypto, TextEncoder, TextDecoder, btoa, atob,
    document: { getElementById: id => elements[id], createElement: tag => new Element(tag),
      querySelectorAll: selector => Object.values(elements).filter(e => e.tag === (selector === 'button' ? 'button' : 'input')) },
    localStorage: { getItem: k => persisted.get(k) ?? null, setItem: (k, v) => persisted.set(k, v) },
    navigator: { userAgent: 'synthetic-controller-test' }, location: { reload() {} },
    fetch: async (_url, options) => { reports.push(JSON.parse(options.body)); },
  });
  const dependency = new vm.SyntheticModule(['DatabaseKeyVault', 'IndexedDbKeyStore'], function () {
    this.setExport('DatabaseKeyVault', Vault); this.setExport('IndexedDbKeyStore', class {});
  }, { context });
  const module = new vm.SourceTextModule(source, { context });
  await module.link(() => dependency); await module.evaluate();
  async function dispatch(id, event = 'submit') {
    const count = reports.length;
    elements[id].events[event]({ preventDefault() {} });
    for (let i = 0; i < 500; i++) {
      if (reports.length > count && !elements.reload.disabled) return;
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    throw new Error('UI operation did not complete');
  }
  return { elements, reports, dispatch, persisted };
}

test('wrong password is visibly rejected; enrollment and passkey unlock are distinct verified actions', async () => {
  const store = new MemoryKeyStore(); const fake = fakeCredentials();
  let p = await page(store, fake);
  const password = 'synthetic controller test password';
  p.elements['new-password'].value = password;
  p.elements['confirm-password'].value = password;
  await p.dispatch('create-form');
  assert.equal(p.reports.at(-1).ok, true);
  assert.equal(p.elements['enroll-form'].hidden, false);
  assert.equal(p.elements.passkey.disabled, true);
  p.elements.password.value = 'wrong';
  await p.dispatch('unlock-form');
  assert.equal(p.reports.at(-1).code, 'unlock-failed');
  assert.equal(p.elements.result.dataset.kind, 'error');
  assert.match(p.elements.result.textContent, /Nothing was unlocked/);
  assert(p.elements.result.focused && p.elements.result.scrolled);
  assert.equal(fake.state.gets, 0);
  assert.equal(p.elements.password.value, '');
  p.elements['enrollment-password'].value = password;
  await p.dispatch('enroll-form');
  assert.equal(p.reports.at(-1).action, 'Passkey enrollment');
  assert.equal(p.reports.at(-1).ok, true);
  assert.equal(fake.state.creates, 1);
  assert.equal(fake.state.gets, 1);
  assert.equal(p.elements.passkey.disabled, false);
  assert.equal(p.elements['enroll-form'].hidden, true);
  p = await page(store, fake, p.persisted);
  assert.equal(fake.state.gets, 1); // Reload alone does not perform an unlock.
  await p.dispatch('passkey', 'click');
  assert.equal(fake.state.gets, 2);
  assert.equal(p.reports.at(-1).action, 'Passkey unlock');
  assert.equal(p.reports.at(-1).ok, true);
  fake.state.fault = 'cancel-get';
  await p.dispatch('passkey', 'click');
  assert.equal(p.reports.at(-1).ok, false);
  assert.equal(p.reports.at(-1).code, 'cancelled-or-unavailable');
  assert.equal(p.elements.result.dataset.kind, 'error');
  assert(!JSON.stringify(p.reports).includes(password));
});

test('unavailable persistence displays an error and disables actions', async () => {
  const store = { read: async () => { throw Error('Storage unavailable'); } };
  const p = await page(store, fakeCredentials());
  assert.match(p.elements.result.textContent, /Storage unavailable/);
  assert.equal(p.elements.result.dataset.kind, 'error');
  assert.equal(p.elements.create.disabled, true);
  assert.equal(p.elements.reload.disabled, false);
});
