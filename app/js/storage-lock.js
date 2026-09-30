/** Reload even when a worker cannot acknowledge close; navigation drops its keys. */
export function closeAndReload(storage, { timeoutMs = 3_000, reload = () => window.location.reload() } = {}) {
    return new Promise(resolve => {
        let finished = false;
        const finish = () => {
            if (finished) return;
            finished = true;
            clearTimeout(timer);
            try { reload(); } finally { resolve(); }
        };
        const timer = setTimeout(finish, timeoutMs);
        Promise.resolve().then(() => storage?.close()).then(finish, finish);
    });
}
