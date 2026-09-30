/** Password-wrapped database key. Only KDF parameters and a sealed key persist. */
const RECORD_KEY = 'poolstellar_encrypted_storage_v1';
const ITERATIONS = 600_000;
const encoder = new TextEncoder();
const encode = bytes => btoa(String.fromCharCode(...bytes));
const decode = value => Uint8Array.from(atob(value), char => char.charCodeAt(0));

export async function openPasswordStorage({ storage, requestPassword,
    records = localStorage, origin = location.origin, crypto = globalThis.crypto }) {
    let record = JSON.parse(records.getItem(RECORD_KEY) || 'null');
    const fresh = !record;
    if (fresh) {
        record = { version: 2, kdf: 'PBKDF2-SHA-256', iterations: ITERATIONS, origin,
            salt: encode(crypto.getRandomValues(new Uint8Array(32))), pending: true };
    }
    // Older unlock formats are never overwritten or silently replaced.
    if (record.version !== 2 || record.kdf !== 'PBKDF2-SHA-256' ||
        record.iterations !== ITERATIONS || record.origin !== origin ||
        typeof record.salt !== 'string' || decode(record.salt).length !== 32 ||
        (!fresh && (typeof record.iv !== 'string' || decode(record.iv).length !== 12 ||
        typeof record.envelope !== 'string' || decode(record.envelope).length !== 48))) {
        throw new Error('Unsupported or damaged storage key record. Existing data has been preserved. Restore a matching backup or use a separate browser profile.');
    }
    const aad = encoder.encode(JSON.stringify([record.version, record.kdf, record.iterations, record.origin, record.salt]));
    let key;
    let error = '';
    try {
        while (!key) {
            let password = await requestPassword({ creating: fresh, error });
            if (typeof password !== 'string' || !password.length) throw new Error('Storage password must not be empty.');
            const bytes = encoder.encode(password);
            password = undefined;
            let wrappingKey;
            try {
                const material = await crypto.subtle.importKey('raw', bytes, 'PBKDF2', false, ['deriveKey']);
                wrappingKey = await crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256',
                    salt: decode(record.salt), iterations: record.iterations },
                    material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
            } finally { bytes.fill(0); }
            if (fresh) {
                key = crypto.getRandomValues(new Uint8Array(32));
                const iv = crypto.getRandomValues(new Uint8Array(12));
                record.iv = encode(iv);
                record.envelope = encode(new Uint8Array(await crypto.subtle.encrypt(
                    { name: 'AES-GCM', iv, additionalData: aad }, wrappingKey, key)));
                // Save before creating the DB so interruption cannot lose its key.
                records.setItem(RECORD_KEY, JSON.stringify(record));
            } else {
                try {
                    key = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM',
                        iv: decode(record.iv), additionalData: aad }, wrappingKey, decode(record.envelope)));
                } catch (failure) {
                    if (failure.name !== 'OperationError') throw failure;
                    error = 'Incorrect storage password or damaged key record. Try again.';
                }
            }
        }
        if (key.length !== 32) throw new Error('Invalid database key envelope.');
        const open = createNew => storage.open({ keyProvider: async () => key, createNew });
        let handle;
        try {
            handle = await open(record.pending === true);
        } catch (failure) {
            // A crash after DB creation can leave the envelope marked pending.
            if (!record.pending || !String(failure).includes('database create/open purpose does not match existing file')) throw failure;
            handle = await open(false);
        }
        if (record.pending) {
            record.pending = false;
            records.setItem(RECORD_KEY, JSON.stringify(record));
        }
        return handle;
    } finally { key?.fill(0); }
}
