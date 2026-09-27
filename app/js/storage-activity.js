// Explicit guards for foreground work that must finish before inactivity lock.
let pending = 0;
let completedAt = 0;
export function storageActivityPending() { return pending > 0; }
export function lastStorageActivity() { return completedAt; }
export function beginStorageActivity() {
    pending++;
    let released = false;
    return () => {
        if (released) return;
        released = true;
        pending--;
        completedAt = Date.now();
    };
}
export async function withStorageActivity(operation) {
    const release = beginStorageActivity();
    try { return await operation(); } finally { release(); }
}
