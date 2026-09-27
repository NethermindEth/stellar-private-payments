import { StrKey } from '@stellar/stellar-sdk';

const DOMAIN = 'spp/database-key-wrap/v1/wallet-signature';
const encoder = new TextEncoder();
const hex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');

function validateContext(context, origin) {
    if (context?.version !== 1 || context.origin !== origin ||
        typeof context.salt !== 'string' || !/^[a-f0-9]{64}$/.test(context.salt)) {
        throw new Error('Freighter enrollment does not match this site. Use your password.');
    }
    const url = new URL(origin);
    if (url.origin !== origin || (url.protocol !== 'https:' &&
        !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)))) {
        throw new Error('Freighter unlocking requires HTTPS or localhost.');
    }
    return StrKey.decodeEd25519PublicKey(context.address);
}

function signatureBytes(value) {
    if (typeof value === 'string' && /^[a-f0-9]{128}$/i.test(value)) {
        return Uint8Array.from(value.match(/../g), byte => parseInt(byte, 16));
    }
    if (typeof value !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(value)) {
        throw new Error('Freighter returned an invalid message signature.');
    }
    const bytes = Uint8Array.from(atob(value), char => char.charCodeAt(0));
    if (btoa(String.fromCharCode(...bytes)) !== value) {
        throw new Error('Freighter returned an invalid message signature.');
    }
    return bytes;
}

async function walletSecret(context, signer, origin) {
    const publicKey = validateContext(context, origin);
    if (await signer.getPublicKey() !== context.address) {
        throw new Error(`Select the enrolled Freighter account (${context.address}), or use your password.`);
    }
    const message = [
        'Stellar Private Payments — unlock local encrypted database',
        'This signature unlocks local storage. It does not authorize a transaction.',
        `Domain: ${DOMAIN}`, `Origin: ${context.origin}`, `Account: ${context.address}`,
        'Database: spp.encrypted.db', `Salt: ${context.salt}`,
    ].join('\n');
    const response = await signer.signMessage(message, { address: context.address });
    if (response?.signerAddress !== context.address) {
        throw new Error('Freighter signed with a different account. Use the enrolled account or your password.');
    }
    const signature = signatureBytes(response.signedMessage);
    try {
        // SEP-0053: Ed25519 over SHA-256(prefix + message).
        const key = await crypto.subtle.importKey('raw', publicKey, 'Ed25519', false, ['verify']);
        const digest = await crypto.subtle.digest('SHA-256', encoder.encode(`Stellar Signed Message:\n${message}`));
        if (!await crypto.subtle.verify('Ed25519', key, signature, digest)) {
            throw new Error('Freighter signature verification failed. Use your password.');
        }
        const material = await crypto.subtle.importKey('raw', signature, 'HKDF', false, ['deriveBits']);
        const derived = new Uint8Array(await crypto.subtle.deriveBits({
            name: 'HKDF', hash: 'SHA-256',
            salt: Uint8Array.from(context.salt.match(/../g), byte => parseInt(byte, 16)),
            info: encoder.encode(message),
        }, material, 256));
        try { return hex(derived); } finally { derived.fill(0); }
    } finally { signature.fill(0); }
}

/** Two approvals confirm the wallet reproduces its secret before persisting it. */
export async function enrollFreighter(storage, password, signer, origin = location.origin) {
    const context = {
        version: 1, address: await signer.getPublicKey(), origin,
        salt: hex(crypto.getRandomValues(new Uint8Array(32))),
    };
    let secret;
    let repeated;
    try {
        secret = await walletSecret(context, signer, origin);
        repeated = await walletSecret(context, signer, origin);
        if (secret !== repeated) throw new Error('Freighter could not reproduce the unlock signature. Use your password.');
        await storage.enrollWallet(password, context, secret);
    } finally {
        // JS strings cannot be reliably zeroized; never persist or log these.
        secret = repeated = undefined;
    }
}

export async function unlockFreighter(storage, signer, origin = location.origin) {
    const context = await storage.walletContext();
    if (!context) throw new Error('Freighter unlocking is not enabled. Use your password.');
    let secret;
    try {
        secret = await walletSecret(context, signer, origin);
        await storage.unlockWallet(context, secret);
    } finally { secret = undefined; }
}
