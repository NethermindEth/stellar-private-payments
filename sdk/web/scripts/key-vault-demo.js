import { DatabaseKeyVault, IndexedDbKeyStore } from '/key-vault.js';
const id = 'spp.key-vault-demo.v1';
const proofName = 'spp.key-vault-demo.proof.v1';
const vault = new DatabaseKeyVault({ databaseId: id, store: new IndexedDbKeyStore('spp-key-vault-demo') });
const element = name => document.getElementById(name);
let status = { exists: false, passkey: false };
let busy = false;
const message = new TextEncoder().encode('The same random database key was recovered.');
const encoded = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)));
const decoded = string => Uint8Array.from(atob(string), c => c.charCodeAt(0));

async function proof(session, create = false) {
  try {
    const key = await crypto.subtle.importKey('raw', session.keyProvider(id, 'open'), 'AES-GCM', false, ['encrypt', 'decrypt']);
    if (create) {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(id) }, key, message);
      localStorage.setItem(proofName, JSON.stringify({ iv: encoded(iv), ciphertext: encoded(ciphertext) }));
    }
    const stored = JSON.parse(localStorage.getItem(proofName));
    if (!stored) throw new Error('The initial encrypted test message is missing');
    const plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: decoded(stored.iv), additionalData: new TextEncoder().encode(id) }, key, decoded(stored.ciphertext)));
    if (new TextDecoder().decode(plain) !== new TextDecoder().decode(message)) throw new Error('Test message does not match');
  } finally { session.lock(); }
}
async function refresh() {
  status = await vault.status();
  element('state').textContent = !status.exists ? 'No test vault yet.' : status.passkey ? 'Password and passkey are configured.' : 'Password is configured. You can add a passkey.';
  element('create-form').hidden = status.exists;
  element('unlock-form').hidden = !status.exists;
  element('enroll-form').hidden = !status.exists || status.passkey;
  element('passkey-state').textContent = !status.exists ? 'Create the password vault first.' : status.passkey
    ? 'A passkey is linked. Press “Test passkey unlock” to request it.'
    : 'No passkey is linked yet. Enter your test password below and press “Add passkey with Proton Pass.”';
  element('change-section').hidden = !status.exists;
  for (const button of document.querySelectorAll('button')) button.disabled = busy;
  element('passkey').disabled = busy || !status.passkey;
  element('recover').disabled = busy || !status.passkey;
  element('add-passkey').disabled = busy || status.passkey;
}
async function report(action, ok, code) {
  // Explicitly omit messages, password values, credential identifiers and key metadata.
  try { await fetch('/result', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action, ok, code, browser: navigator.userAgent }) }); } catch { /* The on-page result remains available. */ }
}
async function run(action, operation) {
  if (busy) return;
  busy = true;
  try {
    await refresh();
    feedback(action === 'Passkey enrollment'
      ? 'Checking your test password, then requesting a passkey from your browser or Proton Pass…'
      : action.startsWith('Passkey') ? 'Requesting your passkey. Complete the browser or Proton Pass prompt…' : 'Checking…', 'pending');
    await operation();
    const text = action === 'Passkey enrollment'
      ? 'Passkey linked successfully. Now press “Test passkey unlock”; then reload and test it again.'
      : `${action}: passed. The correct database key was recovered and has been locked again.`;
    feedback(text, 'success');
    const item = document.createElement('li'); item.textContent = text; element('results').append(item);
    await report(action, true, 'ok');
  } catch (error) {
    // DOMException.code is numeric; only vault errors carry our string codes.
    const code = error.name === 'NotAllowedError' ? 'cancelled-or-unavailable'
      : typeof error.code === 'string' ? error.code : 'failed';
    feedback(code === 'unlock-failed'
      ? `${action} failed: incorrect password or damaged key record. Nothing was unlocked.`
      : code === 'cancelled-or-unavailable'
      ? `${action} did not complete: the prompt was cancelled, timed out, or the requested passkey was unavailable.`
      : `${action} failed: ${error.message} (${code})`, 'error');
    const item = document.createElement('li'); item.textContent = element('result').textContent; element('results').append(item);
    await report(action, false, code);
  } finally {
    for (const input of document.querySelectorAll('input[type=password]')) input.value = '';
    busy = false;
    await refresh().catch(storageFailure);
  }
}
function feedback(text, kind) {
  const result = element('result');
  result.textContent = text;
  result.dataset.kind = kind;
  result.focus({ preventScroll: true });
  result.scrollIntoView({ block: 'nearest' });
}
function storageFailure(error) {
  element('state').textContent = 'Test vault is unavailable.';
  feedback(error.message, 'error');
  for (const button of document.querySelectorAll('button')) button.disabled = true;
  element('reload').disabled = false;
}
function matched(first, second) {
  const password = element(first).value;
  if (password !== element(second).value) throw new Error('Passwords do not match');
  return password;
}
element('create-form').addEventListener('submit', event => {
  event.preventDefault();
  run('Create password vault', async () => proof(await vault.createPassword(matched('new-password', 'confirm-password')), true));
});
element('unlock-form').addEventListener('submit', event => {
  event.preventDefault();
  run('Password unlock', async () => proof(await vault.unlockPassword(element('password').value)));
});
element('enroll-form').addEventListener('submit', event => {
  event.preventDefault();
  run('Passkey enrollment', async () => {
    const password = element('enrollment-password').value;
    await proof(await vault.unlockPassword(password));
    await vault.addPasskey(password);
    // addPasskey already checks a PRF assertion; the separate unlock button tests
    // the persisted wrapper without forcing a third prompt during enrollment.
  });
});
element('passkey').addEventListener('click', () => run('Passkey unlock', async () => proof(await vault.unlockPasskey())));
element('reload').addEventListener('click', () => location.reload());
element('change-form').addEventListener('submit', event => {
  event.preventDefault();
  run('Password change', async () => {
    const password = matched('replacement', 'replacement-confirm');
    await vault.changePassword(element('password').value, password);
    await proof(await vault.unlockPassword(password));
  });
});
element('recover').addEventListener('click', () => {
  if (!element('change-form').reportValidity()) return;
  run('Passkey password recovery', async () => {
    const password = matched('replacement', 'replacement-confirm');
    await vault.resetPasswordWithPasskey(password);
    await proof(await vault.unlockPassword(password));
  });
});
await refresh().catch(storageFailure);
