// Called only from a dedicated worker. The exclusive main-file handle is the
// lock for the entire database (including its WAL).
export async function openFiles(directory, createNew) {
    const root = await navigator.storage.getDirectory();
    const dir = await root.getDirectoryHandle(directory, { create: createNew });
    const files = [];
    try {
        const main = await dir.getFileHandle('spp.db', { create: createNew });
        files.push(await main.createSyncAccessHandle());
        const exists = files[0].getSize() > 0;
        if (exists && createNew) {
            throw new Error('database create/open purpose does not match existing file');
        }
        // Reject plaintext here; Turso authenticates encrypted pages when opening.
        if (exists) {
            const header = new Uint8Array(5);
            files[0].read(header, { at: 0 });
            if (new TextDecoder().decode(header) !== 'Turso') {
                throw new Error('unencrypted or unsupported database; existing data has been preserved');
            }
        }
        const wal = await dir.getFileHandle('spp.db-wal', { create: true });
        files.push(await wal.createSyncAccessHandle());
        if (!exists && files[1].getSize() > 0) {
            throw new Error('empty database has recovery files; existing data has been preserved');
        }
        return files;
    } catch (error) {
        closeFiles(files);
        throw error;
    }
}

export function closeFiles(files) {
    for (const file of [...files].reverse()) {
        try { file.close(); } catch { /* Already closed during teardown. */ }
    }
}

export function readFile(files, slot, buffer, offset) {
    buffer.fill(0);
    return files[slot].read(buffer, { at: offset });
}
export function writeFile(files, slot, buffer, offset) {
    return files[slot].write(buffer, { at: offset });
}
export function syncFile(files, slot) { files[slot].flush(); }
export function truncateFile(files, slot, size) { files[slot].truncate(size); }
export function sizeFile(files, slot) { return files[slot].getSize(); }
export function monotonicMillis() { return performance.now(); }
