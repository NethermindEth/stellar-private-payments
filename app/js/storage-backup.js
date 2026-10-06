/** Encrypted OPFS backups. Import validates an isolated copy before committing its pointer. */
export const STORAGE_RECORD_KEY = 'poolstellar_turso_encrypted_storage_v1';
export const DEFAULT_DIRECTORY = 'spp-turso-encrypted-v1';
const PREFIX = `${DEFAULT_DIRECTORY}-`;
const LIMIT = 256 * 1024 * 1024;
const FORMAT = 'spp-turso-encrypted-storage-backup';
export const validDirectory = value => value === DEFAULT_DIRECTORY ||
    (typeof value === 'string' && new RegExp(`^spp-turso-encrypted-v1-[0-9a-f-]{36}$`).test(value));
const encode = bytes => {
    let text = '';
    for (let i = 0; i < bytes.length; i += 8192) text += String.fromCharCode(...bytes.subarray(i, i + 8192));
    return btoa(text);
};

export async function hasEncryptedStorage(root) {
    for await (const [name, handle] of root.entries()) {
        if (handle.kind === 'directory' && validDirectory(name)) {
            for await (const _entry of handle.entries()) return true;
        }
    }
    return false;
}

/** A writable lease conflicts with another worker's sync access handle. */
export async function acquireStorageLease(root) {
    const leases = [];
    const release = async () => {
        for (const stream of leases.splice(0)) await stream.abort();
    };
    try {
        for await (const [name, handle] of root.entries()) {
            if (handle.kind !== 'directory' || !validDirectory(name)) continue;
            let file;
            try { file = await handle.getFileHandle('spp.db'); }
            catch (error) { if (error.name === 'NotFoundError') continue; throw error; }
            leases.push(await file.createWritable({ keepExistingData: true, mode: 'exclusive' }));
        }
        return release;
    } catch (cause) {
        await release();
        throw new Error('Close other app tabs before backing up, importing, or resetting local storage.', { cause });
    }
}

export function parseBackup(text, origin = location.origin) {
    if (text.length > LIMIT * 1.5) throw new Error('Backup is too large (maximum 256 MiB of stored files).');
    let backup;
    try { backup = JSON.parse(text); } catch { throw new Error('This is not a valid storage backup.'); }
    if (backup?.format !== FORMAT || backup.version !== 1 || backup.record?.origin !== origin ||
        backup.record?.pending !== false || !Array.isArray(backup.files) || !backup.files.length || backup.files.length > 4096) {
        throw new Error('Invalid storage backup, or this backup belongs to a different app origin.');
    }
    const names = new Set();
    let size = 0;
    const files = backup.files.map(file => {
        if (typeof file?.path !== 'string' || file.path.length > 512 || names.has(file.path) ||
            file.path.split('/').some(part => !part || part === '.' || part === '..' || !/^[a-zA-Z0-9_.-]+$/.test(part)) ||
            typeof file.data !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(file.data)) {
            throw new Error('Invalid file in storage backup.');
        }
        names.add(file.path);
        size += file.data.length * 3 / 4;
        if (size > LIMIT) throw new Error('Backup is too large (maximum 256 MiB of stored files).');
        return { path: file.path, bytes: Uint8Array.from(atob(file.data), char => char.charCodeAt(0)) };
    });
    return { record: backup.record, files };
}

export async function exportStorageBackup({ root, records = localStorage }) {
    const record = JSON.parse(records.getItem(STORAGE_RECORD_KEY) || 'null');
    const directory = record?.directory ?? DEFAULT_DIRECTORY;
    if (!record || record.pending !== false || !validDirectory(directory)) throw new Error('Unlock local storage before exporting a backup.');
    const files = [];
    let size = 0;
    async function collect(handle, prefix = '') {
        for await (const [name, entry] of handle.entries()) {
            const path = `${prefix}${name}`;
            if (entry.kind === 'directory') await collect(entry, `${path}/`);
            else {
                const file = await entry.getFile();
                size += file.size;
                if (size > LIMIT || files.length >= 4096) throw new Error('Backup is too large (maximum 256 MiB of stored files).');
                files.push({ path, data: encode(new Uint8Array(await file.arrayBuffer())) });
            }
        }
    }
    await collect(await root.getDirectoryHandle(directory));
    return JSON.stringify({ format: FORMAT, version: 1, record, files });
}

export async function importStorageBackup({ backup, root, validate, records = localStorage, crypto = globalThis.crypto }) {
    const directory = `${PREFIX}${crypto.randomUUID()}`;
    const staged = await root.getDirectoryHandle(directory, { create: true });
    let committed = false;
    try {
        for (const file of backup.files) {
            const parts = file.path.split('/');
            const name = parts.pop();
            let parent = staged;
            for (const part of parts) parent = await parent.getDirectoryHandle(part, { create: true });
            const handle = await parent.getFileHandle(name, { create: true });
            const writer = await handle.createWritable();
            try { await writer.write(file.bytes); await writer.close(); }
            catch (error) { await writer.abort().catch(() => {}); throw error; }
        }
        const record = { ...backup.record, directory, pending: false };
        await validate(record);
        // The envelope and directory move together in one localStorage write.
        // Never remove the previous database before this commit succeeds.
        records.setItem(STORAGE_RECORD_KEY, JSON.stringify(record));
        committed = true;
    } finally {
        if (!committed) await root.removeEntry(directory, { recursive: true }).catch(() => {});
    }
}

export async function resetStorage({ root, records = localStorage }) {
    const directories = [];
    for await (const [name, handle] of root.entries()) {
        if (handle.kind === 'directory' && validDirectory(name)) directories.push(name);
    }
    for (const name of directories) await root.removeEntry(name, { recursive: true });
    records.removeItem(STORAGE_RECORD_KEY);
    // Remove any associations awaiting migration as part of the confirmed reset.
    const legacy = [];
    for (let i = 0; i < records.length; i++) {
        const name = records.key(i);
        if (name?.startsWith('poolstellar_signers:')) legacy.push(name);
    }
    for (const name of legacy) records.removeItem(name);
}
