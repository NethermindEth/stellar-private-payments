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
