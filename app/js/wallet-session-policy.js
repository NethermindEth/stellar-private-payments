// Network and account-change rules shared by index.html and admin.html.
// No imports, so this can be unit-tested without a bundler.

export const UNREADABLE_WALLET_MESSAGE =
    'Freighter is no longer reporting the active account. Reconnect to continue.';

export const WRONG_NETWORK_MESSAGE = 'This app supports Stellar testnet only.';

export const NO_RPC_MESSAGE =
    'Freighter did not report a Soroban RPC URL for the active network. Check the network settings in Freighter.';

/**
 * Validate the wallet's reported network, or throw.
 *
 * There is no default RPC endpoint on purpose: falling back to a testnet URL
 * would give a wallet on another network a working testnet client, and the
 * page would then read one chain while the user signs for another.
 *
 * @param {{network?: string, networkPassphrase?: string, sorobanRpcUrl?: string}} details
 * @returns {{network: string|null, networkPassphrase: string|null, sorobanRpcUrl: string}}
 */
export function requireTestnetNetwork(details) {
    const sorobanRpcUrl = (details?.sorobanRpcUrl || '').trim();
    if (!sorobanRpcUrl) {
        throw new Error(NO_RPC_MESSAGE);
    }
    // Substring match, not a passphrase check: tightening it would lock out
    // local quickstart setups.
    if (!sorobanRpcUrl.toLowerCase().includes('testnet')) {
        throw new Error(WRONG_NETWORK_MESSAGE);
    }
    return {
        network: details?.network ?? null,
        networkPassphrase: details?.networkPassphrase ?? null,
        sorobanRpcUrl,
    };
}

// At the watcher's 2s interval this is ~6s of not knowing which account is
// active. One poll would end healthy sessions whenever Freighter's service
// worker drops a single round trip.
export const UNREADABLE_POLL_LIMIT = 3;

/**
 * Compare a watcher notification against the session's current context.
 *
 * `unreadable` means the watcher answered but could not name the active
 * account, which is not the same as "nothing changed". It is keyed on the
 * missing address rather than on `info.error` because Freighter's
 * WatchWalletChanges.fetchInfo lacks a `return` after its error callback: a
 * failed poll fires twice, the second time with `address: undefined` and no
 * error field.
 *
 * Absent network fields never count as a change — Freighter omits what it has
 * not observed yet.
 *
 * @param {{address?: string, network?: string, networkPassphrase?: string, error?: unknown}|null|undefined} info
 * @param {{address?: string|null, network?: string|null, networkPassphrase?: string|null}|null|undefined} current
 * @returns {{unreadable: boolean, networkChanged: boolean, addressChanged: boolean, changed: boolean}}
 */
export function classifyWalletChange(info, current) {
    if (!info) {
        return { unreadable: false, networkChanged: false, addressChanged: false, changed: false };
    }
    if (info.error || !info.address) {
        return { unreadable: true, networkChanged: false, addressChanged: false, changed: false };
    }
    const networkChanged =
        (!!info.network && info.network !== current?.network) ||
        (!!info.networkPassphrase && info.networkPassphrase !== current?.networkPassphrase);
    const addressChanged = info.address !== current?.address;
    return { unreadable: false, networkChanged, addressChanged, changed: networkChanged || addressChanged };
}

/**
 * Wraps {@link classifyWalletChange} with a count of consecutive unreadable
 * polls. Any readable poll resets it.
 *
 * @param {{unreadableLimit?: number}} [options]
 */
export function createWalletSessionMonitor({ unreadableLimit = UNREADABLE_POLL_LIMIT } = {}) {
    let unreadableStreak = 0;
    return {
        observe(info, current) {
            const classified = classifyWalletChange(info, current);
            if (!classified.unreadable) {
                unreadableStreak = 0;
                return { ...classified, unreadableStreak: 0, sessionUnverifiable: false };
            }
            unreadableStreak += 1;
            return {
                ...classified,
                unreadableStreak,
                sessionUnverifiable: unreadableStreak >= unreadableLimit,
            };
        },
        reset() {
            unreadableStreak = 0;
        },
    };
}
