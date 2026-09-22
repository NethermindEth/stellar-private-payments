// Test-only credential provider. This does NOT prove browser/authenticator support.
export class MemoryKeyStore {
  value = null;
  writes = 0;
  failWrites = false;
  async read() { return structuredClone(this.value); }
  async write(_id, next, expected) {
    if (this.failWrites) throw new Error('simulated storage failure');
    if (JSON.stringify(expected) !== JSON.stringify(this.value)) throw new Error('conflict');
    this.value = structuredClone(next);
    this.writes++;
  }
}
const encode = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes))).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
export function fakeCredentials(origin = 'https://vault.test') {
  const id = crypto.getRandomValues(new Uint8Array(32));
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const state = { fault: null, creates: 0, gets: 0 };
  function client(publicKey, type) {
    return new TextEncoder().encode(JSON.stringify({ type, origin: state.fault === 'origin' ? 'https://wrong.test' : origin,
      challenge: state.fault === 'challenge' ? 'wrong' : encode(publicKey.challenge), crossOrigin: state.fault === 'cross-origin' })).buffer;
  }
  const credentials = {
    async create({ publicKey }) {
      state.creates++;
      if (state.fault === 'cancel-create') throw new DOMException('User cancelled', 'NotAllowedError');
      return { type: 'public-key', rawId: id.buffer.slice(0), response: { clientDataJSON: client(publicKey, 'webauthn.create') },
        getClientExtensionResults: () => ({ prf: { enabled: state.fault !== 'unsupported-create' } }) };
    },
    async get({ publicKey }) {
      state.gets++;
      if (state.fault === 'cancel-get') throw new DOMException('User cancelled', 'NotAllowedError');
      const hmac = await crypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      const result = await crypto.subtle.sign('HMAC', hmac, publicKey.extensions.prf.eval.first);
      if (state.fault === 'different-secret') new Uint8Array(result)[0] ^= 1;
      const auth = new Uint8Array(37);
      auth.set(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(publicKey.rpId))));
      auth[32] = state.fault === 'no-uv' ? 1 : 5;
      if (state.fault === 'rp-hash') auth[0] ^= 1;
      return { type: 'public-key', rawId: state.fault === 'credential' ? new Uint8Array(32).buffer : id.buffer.slice(0),
        response: { clientDataJSON: client(publicKey, 'webauthn.get'), authenticatorData: auth.buffer, signature: crypto.getRandomValues(new Uint8Array(64)).buffer },
        getClientExtensionResults: () => state.fault === 'unsupported-get' ? {} : { prf: { results: { first: result } } } };
    },
  };
  return { state, credentials };
}

// Synthetic Ed25519 wallet for protocol and browser tests only.
export async function createWalletSigner(material) {
  const keys = material ? {
    privateKey: await crypto.subtle.importKey('jwk', material.privateKey, 'Ed25519', true, ['sign']),
    publicKey: await crypto.subtle.importKey('jwk', material.publicKey, 'Ed25519', true, ['verify']),
  } : await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', keys.publicKey));
  const payload = Uint8Array.from([48, ...raw]);
  let crc = 0;
  for (const byte of payload) {
    crc ^= byte << 8;
    for (let i = 0; i < 8; i++) crc = ((crc << 1) ^ (crc & 0x8000 ? 0x1021 : 0)) & 65535;
  }
  const data = [...payload, crc & 255, crc >>> 8];
  let value = 0, bits = 0, address = '';
  for (const byte of data) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { bits -= 5; address += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'[(value >>> bits) & 31]; }
  }
  const state = { calls: [], fault: null };
  const signer = {
    getPublicKey: async () => state.fault === 'account' ? 'wrong-account' : address,
    signMessage: async (message, options) => {
      state.calls.push({ message, options });
      if (state.fault === 'cancel') throw new DOMException('Wallet request cancelled', 'NotAllowedError');
      const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('Stellar Signed Message:\n' + message));
      const signature = new Uint8Array(await crypto.subtle.sign('Ed25519', keys.privateKey, hash));
      if (state.fault === 'signature') signature[0] ^= 1;
      return { signerAddress: state.fault === 'reported-account' ? 'wrong-account' : address,
        signedMessage: state.fault === 'hex' ? Array.from(signature, b => b.toString(16).padStart(2, '0')).join('') : btoa(String.fromCharCode(...signature)) };
    },
  };
  return { signer, state, address, material: {
    privateKey: await crypto.subtle.exportKey('jwk', keys.privateKey),
    publicKey: await crypto.subtle.exportKey('jwk', keys.publicKey),
  } };
}
