// A timed-out RPC does not cancel work in the worker. Observe its state before
// retrying rather than submitting a second create/unlock against an open DB.
export async function settledStorageStatus(storage, { timeoutMs = 120_000 } = {}) {
    const deadline = performance.now() + timeoutMs;
    for (;;) {
        const remaining = deadline - performance.now();
        const timeout = () => Object.assign(new Error('Local storage is still opening. Reload the page before trying again.'), { code: 'storage-opening-timeout' });
        if (remaining <= 0) throw timeout();
        let timer;
        let status;
        try {
            status = await Promise.race([
                storage.status(),
                new Promise((_, reject) => { timer = setTimeout(() => reject(timeout()), remaining); }),
            ]);
        } finally { clearTimeout(timer); }
        if (status !== 'opening') return status;
        await new Promise(resolve => setTimeout(resolve, Math.min(250, Math.max(0, deadline - performance.now()))));
    }
}
const isOpen = status => ['unlocked', 'password-recovery-required'].includes(status);
export async function openStorage(storage, operation) {
    if (isOpen(await settledStorageStatus(storage))) return;
    try { await operation(); }
    catch (error) {
        // Preserve the original failure if status is unavailable. A stuck open
        // gets actionable reload guidance instead of an indefinite spinner.
        let status;
        try { status = await settledStorageStatus(storage); }
        catch (statusError) {
            if (statusError?.code === 'storage-opening-timeout') throw statusError;
        }
        if (!isOpen(status)) throw error;
    }
}
