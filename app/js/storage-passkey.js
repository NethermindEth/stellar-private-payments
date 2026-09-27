// Local key wrapping with WebAuthn PRF. Assertion signatures are never used
// as encryption material: only the authenticator's secret PRF output is.
const DOMAIN = 'spp/database-key-wrap/v1/webauthn-prf';
const encoder = new TextEncoder();
const random = size => crypto.getRandomValues(new Uint8Array(size));
const hex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
const encode = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
const unsupported = () => new Error('This passkey provider does not support encrypted storage. Try another provider or continue with your password.');

function decodeId(value) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,1366}$/.test(value)) {
        throw new Error('Invalid passkey credential. Use your password.');
    }
    const bytes = Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0));
    if (bytes.length > 1024 || encode(bytes) !== value) throw new Error('Invalid passkey credential. Use your password.');
    return bytes;
}

function siteContext(origin, credentials) {
    const url = new URL(origin);
    if (url.origin !== origin || (url.protocol !== 'https:' &&
        !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)))) {
        throw new Error('Passkey unlocking requires HTTPS or localhost.');
    }
    if (!credentials?.create || !credentials?.get) throw new Error('Passkeys are unavailable in this browser. Use your password.');
    return { origin, rpId: url.hostname };
}

function checkCredential(credential, challenge, type, context, expectedId) {
    if (!credential || credential.type !== 'public-key') throw new Error('No passkey was selected. Try again or use your password.');
    const id = encode(credential.rawId);
    decodeId(id);
    if (credential.id !== id || (expectedId && id !== expectedId)) throw new Error('A different passkey was returned. Use the enrolled passkey or your password.');
    const data = JSON.parse(new TextDecoder().decode(credential.response.clientDataJSON));
    if (data.type !== type || data.challenge !== encode(challenge) ||
        data.origin !== context.origin || data.crossOrigin === true) {
        throw new Error('Passkey origin or challenge does not match. Use your password.');
    }
    return id;
}

async function requestCredential(credentials, method, options) {
    try { return await credentials[method](options); }
    catch (error) {
        if (['NotAllowedError', 'AbortError', 'TimeoutError'].includes(error?.name)) {
            throw new Error('Passkey request was cancelled or unavailable. Try again or use your password.');
        }
        throw error;
    }
}

async function passkeySecret(context, credentials, origin) {
    const site = siteContext(origin, credentials);
    if (context?.version !== 1 || context.origin !== site.origin || context.rpId !== site.rpId ||
        typeof context.salt !== 'string' || !/^[a-f0-9]{64}$/.test(context.salt)) {
        throw new Error('Passkey enrollment does not match this site. Use your password.');
    }
    const salt = Uint8Array.from(context.salt.match(/../g), byte => parseInt(byte, 16));
    const challenge = random(32);
    const credential = await requestCredential(credentials, 'get', { publicKey: {
        challenge, rpId: context.rpId,
        allowCredentials: [{ type: 'public-key', id: decodeId(context.credentialId) }],
        userVerification: 'required', timeout: 60_000,
        extensions: { prf: { eval: { first: salt } } },
    } });
    checkCredential(credential, challenge, 'webauthn.get', context, context.credentialId);
    const auth = new Uint8Array(credential.response.authenticatorData);
    const rpHash = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(context.rpId)));
    if (auth.length < 37 || (auth[32] & 5) !== 5 || !rpHash.every((byte, i) => auth[i] === byte)) {
        throw new Error('Passkey user verification or site binding is missing. Use your password.');
    }
    const output = credential.getClientExtensionResults()?.prf?.results?.first;
    if (Object.prototype.toString.call(output) !== '[object ArrayBuffer]' && !ArrayBuffer.isView(output)) throw unsupported();
    const raw = ArrayBuffer.isView(output)
        ? new Uint8Array(output.buffer, output.byteOffset, output.byteLength) : new Uint8Array(output);
    try {
        if (raw.length !== 32) throw unsupported();
        const material = await crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveBits']);
        const derived = new Uint8Array(await crypto.subtle.deriveBits({
            name: 'HKDF', hash: 'SHA-256', salt,
            info: encoder.encode(JSON.stringify([DOMAIN, context.version, 'spp.encrypted.db',
                context.origin, context.rpId, context.credentialId, context.salt])),
        }, material, 256));
        try { return hex(derived); } finally { derived.fill(0); }
    } finally { raw.fill(0); }
}

/** Persist access only after creation and a successful user-verified PRF assertion. */
export async function enrollPasskey(storage, password, credentials = navigator.credentials, origin = location.origin) {
    const site = siteContext(origin, credentials);
    const challenge = random(32);
    const userId = random(32);
    const credential = await requestCredential(credentials, 'create', { publicKey: {
        challenge, rp: { name: 'Stellar Private Payments local storage', id: site.rpId },
        user: { id: userId, name: `local-data-${encode(userId)}`, displayName: 'Local encrypted database' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
        attestation: 'none', timeout: 60_000, extensions: { prf: {} },
    } });
    const credentialId = checkCredential(credential, challenge, 'webauthn.create', site);
    if (credential.getClientExtensionResults()?.prf?.enabled !== true) throw unsupported();
    const context = { version: 1, ...site, credentialId, salt: hex(random(32)) };
    let secret;
    let repeated;
    try {
        secret = await passkeySecret(context, credentials, origin);
        repeated = await passkeySecret(context, credentials, origin);
        if (secret !== repeated) throw new Error('This passkey could not reproduce its encryption secret. Try another provider or use your password.');
        await storage.enrollPasskey(password, context, secret);
    } finally { secret = repeated = undefined; }
}

export async function unlockPasskey(storage, credentials = navigator.credentials, origin = location.origin) {
    const context = await storage.passkeyContext();
    if (!context) throw new Error('Passkey unlocking is not enabled. Use your password.');
    let secret;
    try {
        secret = await passkeySecret(context, credentials, origin);
        await storage.unlockPasskey(context, secret);
    } finally { secret = undefined; }
}
