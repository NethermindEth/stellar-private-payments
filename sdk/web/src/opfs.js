// Called only from a dedicated worker. The exclusive main-file handle is the
// lock for the entire database (including its WAL and initialization marker).
export async function openFiles(directory) {
    const root = await navigator.storage.getDirectory();
    const dir = await root.getDirectoryHandle(directory, { create: true });
    const files = [];
    try {
        for (const name of ['spp.db', 'spp.db-wal', 'initialized']) {
            const file = await dir.getFileHandle(name, { create: true });
            files.push(await file.createSyncAccessHandle());
        }
        return files;
    } catch (error) {
        closeFiles(files);
        throw error;
    }
}

export function closeFiles(files) {
    // Release the main-file lock last.
    for (const file of [...files].reverse()) {
        try { file.close(); } catch { /* Already closed during teardown. */ }
    }
}

export function isInitialized(files) {
    const marker = new Uint8Array(1);
    return files[2].getSize() === 1 && files[2].read(marker, { at: 0 }) === 1 && marker[0] === 1;
}

export function initializeFiles(files) {
    // No writes are accepted until initialization is marked complete.
    // Retry an interrupted first initialization from an empty database.
    files[0].truncate(0);
    files[1].truncate(0);
    files[0].flush();
    files[1].flush();
}

export function markReady(files) {
    files[0].flush();
    files[1].flush();
    if (files[2].write(new Uint8Array([1]), { at: 0 }) !== 1) throw new Error('ShortWrite');
    files[2].truncate(1);
    files[2].flush();
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
