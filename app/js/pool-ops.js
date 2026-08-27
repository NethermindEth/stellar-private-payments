/**
 * In-flight pool-operation tracking, extracted from app/js/ui/pool.js.
 *
 * Kept in its own module so it can be unit-tested directly: pool.js imports
 * '../wasm-facade.js' at module scope, so the whole file fails to load
 * under plain `node --test` even though this counter has no dependency of
 * its own on the wasm package. The counter looks directly testable because
 * it has no wasm-touching code -- true of the code, false of the file it
 * previously lived in.
 *
 * A signed-and-building op doesn't re-read wallet state, so it isn't
 * affected by a mid-flight account/network change, but tearing the client
 * down while one is still running would break its OpHistory write.
 * navigation.js's watcher waits for this to drain before disconnecting,
 * rather than severing state out from under it.
 */

let inFlightOps = 0;

export function beginPoolOp() {
    inFlightOps += 1;
}

export function endPoolOp() {
    inFlightOps = Math.max(0, inFlightOps - 1);
}

export function hasInFlightPoolOps() {
    return inFlightOps > 0;
}

export function waitForPoolOpsToDrain({ timeoutMs = 15000, intervalMs = 100 } = {}) {
    if (!hasInFlightPoolOps()) return Promise.resolve(true);
    return new Promise((resolve) => {
        const start = Date.now();
        const check = () => {
            if (!hasInFlightPoolOps()) {
                resolve(true);
            } else if (Date.now() - start >= timeoutMs) {
                resolve(false);
            } else {
                setTimeout(check, intervalMs);
            }
        };
        check();
    });
}
