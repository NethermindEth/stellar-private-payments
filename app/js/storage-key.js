/** Wallet-wrapped database key. Only the public context and encrypted envelope persist. */
const RECORD_KEY = 'poolstellar_encrypted_storage_v1';
const encoder = new TextEncoder();
const encode = bytes => btoa(String.fromCharCode(...bytes));
const decode = value => Uint8Array.from(atob(value), char => char.charCodeAt(0));

export async function openWalletStorage({ locks = globalThis.navigator?.locks, ...options }) {
    if (typeof locks?.request !== 'function') {
        throw new Error('This browser cannot safely unlock local storage because Web Locks are unavailable. Use a browser with Web Locks support.');
    }
    // Serialize the record read, enrollment and database open across tabs. The
    // OPFS lock alone is too late: enrollment saves its envelope before opening.
    return locks.request(RECORD_KEY, { mode: 'exclusive' }, () => openLockedWalletStorage(options));
}

async function openLockedWalletStorage({ storage, getAddress, signMessage, verifySignature, confirmAccount,
    records = localStorage, origin = location.origin, crypto = globalThis.crypto }) {
    let record = JSON.parse(records.getItem(RECORD_KEY) || 'null');
    const fresh = !record;
    if (fresh) {
        record = { version: 1, address: await getAddress(), origin,
            salt: encode(crypto.getRandomValues(new Uint8Array(32))), pending: true };
    }
    if (record?.version !== 1 || record.origin !== origin || typeof record.address !== 'string' || !record.address ||
        typeof record.salt !== 'string' || decode(record.salt).length !== 32 ||
        (!fresh && (typeof record.iv !== 'string' || decode(record.iv).length !== 12 ||
        typeof record.envelope !== 'string' || decode(record.envelope).length !== 48))) {
        throw new Error('Invalid storage key metadata. Restore the original metadata to unlock storage.');
    }
    if (confirmAccount) {
        for (;;) {
            const confirmed = await confirmAccount({ address: record.address, fresh });
            if (!fresh) break;
            if (typeof confirmed === 'string' && confirmed) record.address = confirmed;
            // The user may switch accounts while the confirmation is visible.
            // Confirm the updated account before binding any persistent data.
            const selected = await getAddress();
            if (selected === record.address) break;
            if (typeof selected !== 'string' || !selected) throw new Error('Select an account in Freighter to unlock local storage.');
            record.address = selected;
        }
    }
    const message = `Stellar Private Payments storage unlock v1\nOrigin: ${origin}\nAccount: ${record.address}\nSalt: ${record.salt}`;
    const sign = async () => {
        const { signedMessage, signerAddress } = await signMessage(message, { address: record.address });
        if (signerAddress && signerAddress !== record.address) throw new Error('Storage unlock signed with a different account.');
        const signature = decode(signedMessage);
        try {
            if (signature.length !== 64 || !await verifySignature(record.address, message, signature)) {
                throw new Error('Invalid wallet signature for storage unlock.');
            }
            return signature;
        } catch (error) {
            signature.fill(0);
            throw error;
        }
    };
    const signature = await sign();
    let key;
    try {
        if (fresh) {
            const repeated = await sign();
            const stable = repeated.every((byte, i) => byte === signature[i]);
            repeated.fill(0);
            if (!stable) throw new Error('Wallet signatures must be reproducible to unlock storage.');
        }
        const material = await crypto.subtle.importKey('raw', signature, 'HKDF', false, ['deriveKey']);
        const wrappingKey = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256',
            salt: decode(record.salt), info: encoder.encode('spp.browser.storage-key-wrap.v1') },
            material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
        const aad = encoder.encode(message);
        if (fresh) {
            key = crypto.getRandomValues(new Uint8Array(32));
            const iv = crypto.getRandomValues(new Uint8Array(12));
            record.iv = encode(iv);
            record.envelope = encode(new Uint8Array(await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv, additionalData: aad }, wrappingKey, key)));
            // Save before creating the DB so interrupted creation never loses its key.
            records.setItem(RECORD_KEY, JSON.stringify(record));
        } else {
            key = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM',
                iv: decode(record.iv), additionalData: aad }, wrappingKey, decode(record.envelope)));
        }
        if (key.length !== 32) throw new Error('Invalid database key envelope.');
        const open = createNew => storage.open({ keyProvider: async () => key, createNew });
        let handle;
        try {
            handle = await open(record.pending === true);
        } catch (error) {
            // A crash after DB creation can leave only the envelope marked pending.
            if (!record.pending || !String(error).includes('database create/open purpose does not match existing file')) throw error;
            handle = await open(false);
        }
        record.pending = false;
        records.setItem(RECORD_KEY, JSON.stringify(record));
        return handle;
    } finally {
        signature.fill(0);
        key?.fill(0);
    }
}
