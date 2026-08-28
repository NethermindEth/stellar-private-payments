// Guards for the account-session cache in wasm-facade.js, which imports the
// wasm package and so cannot be loaded by plain `node --test`. These have no
// imports and are unit-tested directly.

export function requireNoteOwner(userAddress) {
    if (typeof userAddress === 'string' && userAddress.length > 0) return userAddress;
    throw new Error(
        'openAccount requires userAddress: refusing to open a session for whichever account the wallet has active',
    );
}

export function sessionMatchesCache(cached, requested) {
    return (
        isUsableAddress(cached.userAddress) &&
        isUsableAddress(cached.signerAddress) &&
        cached.userAddress === requested.userAddress &&
        cached.signerAddress === requested.signerAddress
    );
}

function isUsableAddress(value) {
    return typeof value === 'string' && value.length > 0;
}

export function openPairKey(userAddress, signerAddress) {
    if (!isUsableAddress(userAddress) || !isUsableAddress(signerAddress)) return null;
    return `${userAddress} ${signerAddress}`;
}

/** Shares one in-flight open among concurrent callers of the same pair. */
export function createInFlightOpenRegistry() {
    const inFlight = new Map();
    return {
        share(key, openFn) {
            if (key !== null) {
                const existing = inFlight.get(key);
                if (existing) return existing;
            }
            const promise = Promise.resolve().then(openFn);
            if (key === null) return promise;
            inFlight.set(key, promise);
            const forget = () => {
                if (inFlight.get(key) === promise) inFlight.delete(key);
            };
            promise.then(forget, forget);
            return promise;
        },
        clear() {
            inFlight.clear();
        },
    };
}

/** Supersession tokens so an abandoned openAccount call can't overwrite a newer session. */
export function createSessionGeneration() {
    let current = 0;
    return {
        begin() {
            current += 1;
            return current;
        },
        invalidate() {
            current += 1;
        },
        isCurrent(token) {
            return token === current;
        },
    };
}
