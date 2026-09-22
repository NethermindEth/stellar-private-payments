// Versioned complete backup. The payload is already SQLite3MC ciphertext;
// an outer AEAD binds those bytes to the wrapped-key metadata as one archive.
const encoder = new TextEncoder();
const MAGIC = encoder.encode('SPPBACK1');
const DOMAIN = encoder.encode('spp/database-backup/container/v1');

export function readBackup(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 32 || !MAGIC.every((b, i) => b === bytes[i])) throw new Error('Not a supported complete database backup.');
    const size = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(8);
    if (size > 16384 || size < 2 || bytes.length < 12 + size + 16) throw new Error('Invalid database backup header.');
    const header = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(12, 12 + size)));
    if (!header || Object.keys(header).sort().join(',') !== 'iv,record' || !Array.isArray(header.iv) ||
        header.iv.length !== 12 || !header.iv.every(b => Number.isInteger(b) && b >= 0 && b <= 255)) throw new Error('Invalid database backup metadata.');
    return { record: header.record, iv: Uint8Array.from(header.iv), aad: bytes.subarray(0, 12 + size), payload: bytes.subarray(12 + size) };
}

async function archiveKey(provider) {
    const bytes = provider('spp.encrypted.db', 'open');
    const material = await crypto.subtle.importKey('raw', bytes, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: DOMAIN, info: encoder.encode('encrypted-snapshot-and-key-envelope') },
        material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

export async function createBackup(record, snapshot, provider) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const header = encoder.encode(JSON.stringify({ record, iv: [...iv] }));
    if (header.length > 16384) throw new Error('Key metadata is too large.');
    const aad = new Uint8Array(12 + header.length);
    aad.set(MAGIC); new DataView(aad.buffer).setUint32(8, header.length); aad.set(header, 12);
    const payload = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, await archiveKey(provider), snapshot);
    const bytes = new Uint8Array(aad.length + payload.byteLength);
    bytes.set(aad); bytes.set(new Uint8Array(payload), aad.length);
    return bytes;
}

export async function decryptBackup(bytes, provider) {
    const { iv, aad, payload } = readBackup(bytes);
    try {
        return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, await archiveKey(provider), payload));
    } catch { throw new Error('Complete backup authentication failed. The file is damaged or does not match its key.'); }
}
