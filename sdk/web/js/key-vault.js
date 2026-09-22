/** Local database-key wrapping. This is not a server authentication protocol. */
const DOMAIN = 'spp/database-key-wrap/v1';
const ITERATIONS = 600_000;
const encoder = new TextEncoder();
const random = size => crypto.getRandomValues(new Uint8Array(size));

export class KeyVaultError extends Error {
  constructor(code, message) { super(message); this.name = 'KeyVaultError'; this.code = code; }
}
const fail = (code, message) => { throw new KeyVaultError(code, message); };
const requireValue = (condition, message) => { if (!condition) fail('invalid-record', message); };

function encode(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes))).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}
function decode(value, min, max = min) {
  requireValue(typeof value === 'string' && value.length <= Math.ceil(max * 4 / 3) && /^[A-Za-z0-9_-]+$/.test(value), 'Invalid encoded key metadata');
  let bytes;
  try { bytes = Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0)); }
  catch { fail('invalid-record', 'Invalid encoded key metadata'); }
  requireValue(bytes.length >= min && bytes.length <= max && encode(bytes) === value, 'Invalid key metadata length');
  return bytes;
}
function fields(value, names) {
  requireValue(value && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).sort().join(',') === [...names].sort().join(','), 'Unsupported key metadata');
}
function validate(record, databaseId) {
  fields(record, ['version', 'databaseId', 'vaultId', 'revision', 'password', 'passkey', ...(Object.prototype.hasOwnProperty.call(record ?? {}, 'wallet') ? ['wallet'] : [])]);
  requireValue(record.version === 1 && record.databaseId === databaseId &&
    Number.isSafeInteger(record.revision) && record.revision >= 1, 'Invalid key vault identity or version');
  decode(record.vaultId, 16);
  fields(record.password, ['salt', 'iterations', 'iv', 'ciphertext']);
  decode(record.password.salt, 32);
  requireValue(Number.isSafeInteger(record.password.iterations) && record.password.iterations >= ITERATIONS && record.password.iterations <= 2_000_000, 'Unsupported password work factor');
  for (const slot of [record.password, record.passkey, record.wallet].filter(Boolean)) {
    decode(slot.iv, 12); decode(slot.ciphertext, 48);
  }
  if (record.wallet !== undefined && record.wallet !== null) {
    fields(record.wallet, ['address', 'origin', 'salt', 'iv', 'ciphertext']);
    walletPublicKey(record.wallet.address);
    secureOrigin(record.wallet.origin);
    decode(record.wallet.salt, 32);
  }
  if (record.passkey !== null) {
    fields(record.passkey, ['credentialId', 'prfSalt', 'origin', 'rpId', 'iv', 'ciphertext']);
    decode(record.passkey.credentialId, 1, 1024); decode(record.passkey.prfSalt, 32);
    requireValue(typeof record.passkey.origin === 'string' && record.passkey.origin.length <= 2048 &&
      typeof record.passkey.rpId === 'string' && record.passkey.rpId.length <= 253, 'Invalid passkey origin');
  }
  return record;
}
function passwordBytes(password, creating = false) {
  if (typeof password !== 'string' || password.length > 1024 || !password.length ||
      (creating && [...password].length < 15)) {
    fail('invalid-password', creating ? 'Use a password with 15–1024 characters' : 'Password is required');
  }
  // Preserve exactly what the user entered; do not trim or normalize passwords.
  return encoder.encode(password);
}
async function passwordKey(password, slot, creating = false) {
  const bytes = passwordBytes(password, creating);
  try {
    const material = await crypto.subtle.importKey('raw', bytes, 'PBKDF2', false, ['deriveKey']);
    return await crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: decode(slot.salt, 32), iterations: slot.iterations }, material,
      { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  } finally { bytes.fill(0); }
}
function associatedData(record, method, slot) {
  const metadata = method === 'password' ? [slot.salt, slot.iterations] : method === 'wallet'
    ? [slot.address, slot.origin, slot.salt] : [slot.credentialId, slot.prfSalt, slot.origin, slot.rpId];
  return encoder.encode(JSON.stringify([DOMAIN, record.version, record.databaseId, record.vaultId, method, ...metadata]));
}

function secureOrigin(origin) {
  let url;
  try { url = new URL(origin); } catch { fail('wrong-origin', 'Wallet unlock requires HTTPS or localhost'); }
  if (url.origin !== origin || origin.length > 2048 || (url.protocol !== 'https:' && !(url.protocol === 'http:' && url.hostname === 'localhost'))) {
    fail('wrong-origin', 'Wallet unlock requires HTTPS or localhost');
  }
  return origin;
}
function walletPublicKey(address) {
  requireValue(typeof address === 'string' && /^G[A-Z2-7]{55}$/.test(address), 'Expected a Stellar Ed25519 account address');
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, value = 0;
  const bytes = [];
  for (const char of address) {
    value = (value << 5) | alphabet.indexOf(char); bits += 5;
    if (bits >= 8) { bits -= 8; bytes.push((value >>> bits) & 255); }
  }
  let crc = 0;
  for (const byte of bytes.slice(0, 33)) {
    crc ^= byte << 8;
    for (let i = 0; i < 8; i++) crc = ((crc << 1) ^ ((crc & 0x8000) ? 0x1021 : 0)) & 65535;
  }
  requireValue(bytes[0] === 48 && bytes[33] === (crc & 255) && bytes[34] === (crc >>> 8), 'Invalid Stellar account checksum');
  return Uint8Array.from(bytes.slice(1, 33));
}
function walletSignature(value) {
  if (typeof value !== 'string') fail('invalid-signature', 'Wallet returned no message signature');
  if (/^[0-9a-fA-F]{128}$/.test(value)) return Uint8Array.from(value.match(/../g), byte => parseInt(byte, 16));
  if (!/^[A-Za-z0-9+/]{86}==$/.test(value)) fail('invalid-signature', 'Invalid wallet signature encoding');
  const bytes = Uint8Array.from(atob(value), char => char.charCodeAt(0));
  if (btoa(String.fromCharCode(...bytes)) !== value) fail('invalid-signature', 'Noncanonical wallet signature');
  return bytes;
}
async function wrap(record, method, slot, wrappingKey, dataKey) {
  const iv = random(12);
  return { ...slot, iv: encode(iv), ciphertext: encode(await crypto.subtle.encrypt({ name: 'AES-GCM', iv,
    additionalData: associatedData(record, method, slot), tagLength: 128 }, wrappingKey, dataKey)) };
}
async function unwrap(record, method, wrappingKey) {
  const slot = record[method];
  try {
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: decode(slot.iv, 12),
      additionalData: associatedData(record, method, slot), tagLength: 128 }, wrappingKey, decode(slot.ciphertext, 48)));
  } catch {
    if (method === 'wallet') fail('wallet-unlock-failed', 'Wallet signature could not unlock this database; use your recovery password');
    fail('unlock-failed', 'Cannot unlock: incorrect password/passkey or damaged key metadata');
  }
}

/** IndexedDB stores encrypted envelopes only. Writes resolve after transaction commit. */
export class IndexedDbKeyStore {
  constructor(name = 'spp-database-key-vault') { this.name = name; }
  async transaction(mode, operation) {
    const db = await new Promise((resolve, reject) => {
      let blocked = false;
      const request = indexedDB.open(this.name, 1);
      request.onupgradeneeded = () => request.result.createObjectStore('keys');
      request.onsuccess = () => { if (blocked) request.result.close(); else resolve(request.result); };
      request.onerror = () => reject(request.error);
      request.onblocked = () => { blocked = true; reject(new KeyVaultError('storage-blocked', 'Close other pages before opening the key vault')); };
    });
    try {
      return await new Promise((resolve, reject) => {
        const transaction = db.transaction('keys', mode, { durability: 'strict' });
        let result;
        let failure;
        transaction.oncomplete = () => resolve(result);
        transaction.onabort = () => reject(failure ?? transaction.error ?? new Error('Key storage transaction aborted'));
        transaction.onerror = () => {}; // Abort handler reports the final outcome.
        operation(transaction.objectStore('keys'), value => { result = value; }, error => {
          failure = error; transaction.abort();
        });
      });
    } finally { db.close(); }
  }
  read(id) {
    return this.transaction('readonly', (store, result) => {
      const request = store.get(id);
      request.onsuccess = () => result(request.result ?? null);
    });
  }
  write(id, next, expected) {
    return this.transaction('readwrite', (store, _result, abort) => {
      const request = store.get(id);
      request.onsuccess = () => {
        const current = request.result ?? null;
        // Compare the complete previous envelope, not just a caller-controlled revision.
        if (JSON.stringify(current) !== JSON.stringify(expected)) {
          abort(new KeyVaultError('conflict', 'Key vault changed in another page; unlock again before retrying'));
          return;
        }
        store.put(next, id);
      };
    });
  }
}

/** Holds the raw data key only while unlocked. Close SQLite BEFORE calling lock(). */
class KeySession {
  #key;
  constructor(databaseId, key) {
    this.#key = new Uint8Array(key);
    this.keyProvider = (id, purpose) => {
      if (!this.#key) fail('locked', 'Database key is locked');
      if (id !== databaseId || !['create', 'open'].includes(purpose)) fail('wrong-database', 'Database key requested for a different database');
      return this.#key;
    };
  }
  lock() { this.#key?.fill(0); this.#key = null; }
}

/**
 * Password recovery remains available when a passkey is added. Clearing browser
 * site data can delete these wrapped keys. Password changes do not revoke old
 * copies/backups of the envelope or an already-unlocked SQLite connection.
 * JS strings and browser-managed CryptoKeys cannot be reliably zeroized.
 */
export class DatabaseKeyVault {
  constructor({ databaseId = 'spp.encrypted.db', store = new IndexedDbKeyStore(),
    credentials = globalThis.navigator?.credentials, origin = globalThis.location?.origin } = {}) {
    if (typeof databaseId !== 'string' || !databaseId.length || databaseId.length > 256) throw new TypeError('Invalid databaseId');
    this.databaseId = databaseId;
    this.store = store;
    this.credentials = credentials;
    this.origin = origin;
  }
  async record() {
    const record = await this.store.read(this.databaseId);
    if (!record) fail('missing-key', 'No wrapped database key exists; restore key metadata instead of generating a replacement');
    return validate(record, this.databaseId);
  }
  async status() {
    const record = await this.store.read(this.databaseId);
    if (!record) return { exists: false, passkey: false };
    validate(record, this.databaseId);
    return { exists: true, passkey: record.passkey !== null, wallet: !!record.wallet,
      walletAddress: record.wallet?.address, revision: record.revision };
  }
  async save(previous, changes) {
    const next = { ...previous, ...changes, revision: previous.revision + 1 };
    validate(next, this.databaseId);
    await this.store.write(this.databaseId, next, previous);
  }
  async createPassword(password) {
    passwordBytes(password, true).fill(0);
    if (await this.store.read(this.databaseId)) fail('already-exists', 'A wrapped database key already exists');
    const key = random(32);
    try {
      const record = { version: 1, databaseId: this.databaseId, vaultId: encode(random(16)), revision: 1, password: null, passkey: null };
      const slot = { salt: encode(random(32)), iterations: ITERATIONS };
      record.password = await wrap(record, 'password', slot, await passwordKey(password, slot, true), key);
      validate(record, this.databaseId);
      await this.store.write(this.databaseId, record, null);
      return new KeySession(this.databaseId, key);
    } finally { key.fill(0); }
  }
  async unlockPassword(password) {
    const record = await this.record();
    const key = await unwrap(record, 'password', await passwordKey(password, record.password));
    try { return new KeySession(this.databaseId, key); } finally { key.fill(0); }
  }
  async changePassword(oldPassword, newPassword) {
    passwordBytes(newPassword, true).fill(0);
    const record = await this.record();
    const key = await unwrap(record, 'password', await passwordKey(oldPassword, record.password));
    try { await this.replacePassword(record, key, newPassword); } finally { key.fill(0); }
  }
  async replacePassword(record, key, password) {
    const slot = { salt: encode(random(32)), iterations: ITERATIONS };
    const wrapped = await wrap(record, 'password', slot, await passwordKey(password, slot, true), key);
    await this.save(record, { password: wrapped });
  }
  async walletKey(record, slot, signer) {
    if (secureOrigin(this.origin) !== slot.origin) fail('wrong-origin', 'Wallet unlock belongs to a different site; use your password');
    if (!signer?.getPublicKey || !signer?.signMessage) fail('wallet-unavailable', 'Wallet message signing is unavailable');
    if (await signer.getPublicKey() !== slot.address) fail('wrong-wallet', 'Select the wallet account enrolled for this database');
    const message = ['Stellar Private Payments — unlock local encrypted database',
      'This signature unlocks local storage. It does not authorize a transaction.',
      `Domain: ${DOMAIN}/wallet-signature`, `Origin: ${slot.origin}`, `Account: ${slot.address}`,
      `Database: ${record.databaseId}`, `Vault: ${record.vaultId}`, `Salt: ${slot.salt}`].join('\n');
    const response = await signer.signMessage(message, { address: slot.address });
    if (response?.signerAddress !== slot.address) fail('wrong-wallet', 'Wallet signed with a different account');
    const signature = walletSignature(response.signedMessage);
    try {
      const publicKey = await crypto.subtle.importKey('raw', walletPublicKey(slot.address), 'Ed25519', false, ['verify']);
      const hash = await crypto.subtle.digest('SHA-256', encoder.encode(`Stellar Signed Message:\n${message}`));
      if (!await crypto.subtle.verify('Ed25519', publicKey, signature, hash)) fail('invalid-signature', 'Wallet signature verification failed');
      const material = await crypto.subtle.importKey('raw', signature, 'HKDF', false, ['deriveKey']);
      return await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: decode(slot.salt, 32),
        info: associatedData(record, 'wallet', slot) }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    } finally { signature.fill(0); }
  }
  async addWallet(password, signer) {
    const record = await this.record();
    if (record.wallet) fail('already-exists', 'A wallet is already enrolled');
    const key = await unwrap(record, 'password', await passwordKey(password, record.password));
    try {
      const origin = secureOrigin(this.origin);
      if (!signer?.getPublicKey) fail('wallet-unavailable', 'Wallet message signing is unavailable');
      const address = await signer.getPublicKey();
      walletPublicKey(address);
      const slot = { address, origin, salt: encode(random(32)) };
      const wrapped = await wrap(record, 'wallet', slot, await this.walletKey(record, slot, signer), key);
      // A second real signing request must reproduce the key before persistence.
      const verified = await unwrap({ ...record, wallet: wrapped }, 'wallet', await this.walletKey(record, wrapped, signer));
      try {
        if (!key.every((byte, i) => byte === verified[i])) fail('invalid-signature', 'Wallet cannot reproduce the storage wrapping key');
      } finally { verified.fill(0); }
      await this.save(record, { wallet: wrapped });
    } finally { key.fill(0); }
  }
  async unlockWallet(signer) {
    const record = await this.record();
    if (!record.wallet) fail('missing-wallet', 'No wallet is enrolled for this database');
    const key = await unwrap(record, 'wallet', await this.walletKey(record, record.wallet, signer));
    try { return new KeySession(this.databaseId, key); } finally { key.fill(0); }
  }
  async removeWallet(password) {
    const record = await this.record();
    const key = await unwrap(record, 'password', await passwordKey(password, record.password));
    try { await this.save(record, { wallet: null }); } finally { key.fill(0); }
  }
  passkeyContext() {
    if (!this.credentials?.create || !this.credentials?.get) fail('passkey-unavailable', 'This browser does not provide WebAuthn');
    let url;
    try { url = new URL(this.origin); } catch { fail('passkey-unavailable', 'Passkeys require a secure browser origin'); }
    if (url.origin !== this.origin || (url.protocol !== 'https:' && !(url.protocol === 'http:' && url.hostname === 'localhost'))) {
      fail('passkey-unavailable', 'Passkeys require HTTPS or localhost');
    }
    return { origin: url.origin, rpId: url.hostname };
  }
  checkCredential(credential, challenge, type, context, expectedId) {
    if (!credential || credential.type !== 'public-key') fail('passkey-cancelled', 'No passkey was selected');
    const id = encode(credential.rawId);
    decode(id, 1, 1024);
    if (expectedId && id !== expectedId) fail('wrong-passkey', 'A different passkey was returned');
    let data;
    try { data = JSON.parse(new TextDecoder().decode(credential.response.clientDataJSON)); }
    catch { fail('invalid-passkey', 'Invalid WebAuthn response'); }
    if (data.type !== type || data.challenge !== encode(challenge) || data.origin !== context.origin || data.crossOrigin === true) {
      fail('invalid-passkey', 'WebAuthn origin or challenge does not match');
    }
    return id;
  }
  async passkeyKey(record, slot) {
    const context = this.passkeyContext();
    if (context.origin !== slot.origin || context.rpId !== slot.rpId) fail('wrong-origin', 'Passkey belongs to a different origin');
    const challenge = random(32);
    const credential = await this.credentials.get({ publicKey: { challenge, rpId: slot.rpId,
      allowCredentials: [{ type: 'public-key', id: decode(slot.credentialId, 1, 1024) }],
      userVerification: 'required', timeout: 60_000, extensions: { prf: { eval: { first: decode(slot.prfSalt, 32) } } } } });
    this.checkCredential(credential, challenge, 'webauthn.get', context, slot.credentialId);
    const auth = new Uint8Array(credential.response.authenticatorData);
    const rpHash = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(slot.rpId)));
    if (auth.length < 37 || (auth[32] & 5) !== 5 || !rpHash.every((byte, i) => byte === auth[i])) {
      fail('invalid-passkey', 'Passkey user verification or relying-party binding is missing');
    }
    const output = credential.getClientExtensionResults()?.prf?.results?.first;
    if (Object.prototype.toString.call(output) !== '[object ArrayBuffer]' && !ArrayBuffer.isView(output)) fail('prf-unavailable', 'This passkey provider does not support PRF encryption; use your password');
    const raw = ArrayBuffer.isView(output) ? new Uint8Array(output.buffer, output.byteOffset, output.byteLength) : new Uint8Array(output);
    if (raw.length !== 32) fail('prf-unavailable', 'Invalid passkey PRF output');
    try {
      const material = await crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveKey']);
      return await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: decode(record.vaultId, 16),
        info: encoder.encode(`${DOMAIN}/webauthn-prf/${record.databaseId}`) }, material,
      { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    } finally { raw.fill(0); }
  }
  async addPasskey(password) {
    const context = this.passkeyContext();
    const record = await this.record();
    if (record.passkey) fail('already-exists', 'A passkey is already enrolled');
    const key = await unwrap(record, 'password', await passwordKey(password, record.password));
    try {
      const challenge = random(32);
      const salt = random(32);
      const credential = await this.credentials.create({ publicKey: {
        challenge, rp: { name: 'Stellar Private Payments local storage', id: context.rpId },
        user: { id: decode(record.vaultId, 16), name: `database-${record.vaultId}`, displayName: 'Local encrypted database' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
        attestation: 'none', timeout: 60_000, extensions: { prf: { eval: { first: salt } } },
      } });
      const credentialId = this.checkCredential(credential, challenge, 'webauthn.create', context);
      // Creation support alone is not enough: require a successful assertion
      // with PRF before persisting the second wrapper. Never use the signature.
      if (credential.getClientExtensionResults()?.prf?.enabled === false) fail('prf-unavailable', 'This passkey provider does not support PRF encryption; use your password');
      const slot = { ...context, credentialId, prfSalt: encode(salt) };
      const wrapped = await wrap(record, 'passkey', slot, await this.passkeyKey(record, slot), key);
      await this.save(record, { passkey: wrapped });
    } finally { key.fill(0); }
  }
  async unlockPasskey() {
    const record = await this.record();
    if (!record.passkey) fail('missing-passkey', 'No passkey is enrolled for this database');
    const key = await unwrap(record, 'passkey', await this.passkeyKey(record, record.passkey));
    try { return new KeySession(this.databaseId, key); } finally { key.fill(0); }
  }
  async resetPasswordWithPasskey(password) {
    passwordBytes(password, true).fill(0);
    const record = await this.record();
    if (!record.passkey) fail('missing-passkey', 'No passkey is enrolled for this database');
    const key = await unwrap(record, 'passkey', await this.passkeyKey(record, record.passkey));
    try { await this.replacePassword(record, key, password); } finally { key.fill(0); }
  }
  async removePasskey(password) {
    const record = await this.record();
    const key = await unwrap(record, 'password', await passwordKey(password, record.password));
    try { await this.save(record, { passkey: null }); } finally { key.fill(0); }
  }
}
