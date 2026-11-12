/**
 * What the app asks of the user before its data views open.
 *
 * - `welcome`: no local store and no wallet; a first visit.
 * - `returning`: a store exists but no wallet is connected.
 * - `connecting`: the wallet is connecting and storage is not open yet.
 * - `locked`: the wallet is connected but encrypted storage is locked.
 * - `ready`: storage is open.
 *
 * Plaintext storage opens without a signature, so it never reaches `locked`.
 * Pure, so every combination can be tested without a browser.
 */

export const ACCESS_STATES = ['welcome', 'returning', 'connecting', 'locked', 'ready'];

const SIGNATURE_NOTE = 'You’ll sign a message, not a transaction. It’s free and keeps your data encrypted on this device.';
const PLAINTEXT_NOTE = 'Your private keys and history are stored unencrypted in this browser. Anyone with access to this device can read them.';

const COPY = {
    encrypted: {
        connectLabel: { welcome: 'Connect Freighter', returning: 'Connect & unlock', ready: 'Connect Freighter' },
        cards: {
            welcome: {
                title: 'Send and hold tokens privately',
                body: 'Deposit tokens into a privacy pool, then transfer and withdraw without linking your accounts. Proofs are generated in your browser.',
                note: SIGNATURE_NOTE,
            },
            returning: {
                title: 'Welcome back',
                body: 'Connect Freighter to unlock your private balance and history on this device.',
                note: SIGNATURE_NOTE,
            },
            connecting: {
                title: 'Connecting',
                body: 'Approve each request in Freighter to continue.',
                note: '',
            },
            locked: {
                title: 'Your private account is locked',
                body: 'Unlock to see your private balance and history, or to make a payment. You can still verify disclosures while it’s locked.',
                note: SIGNATURE_NOTE,
            },
        },
    },
    plaintext: {
        connectLabel: { welcome: 'Connect Freighter', returning: 'Connect Freighter', ready: 'Connect Freighter' },
        cards: {
            welcome: {
                title: 'Send and hold tokens privately',
                body: 'Deposit tokens into a privacy pool, then transfer and withdraw without linking your accounts. Proofs are generated in your browser.',
                note: PLAINTEXT_NOTE,
            },
            returning: {
                title: 'Welcome back',
                body: 'Connect Freighter to open your private balance and history in this browser.',
                note: PLAINTEXT_NOTE,
            },
            connecting: {
                title: 'Connecting',
                body: 'Approve each request in Freighter to continue.',
                note: '',
            },
        },
    },
};

// Matches the nav, so the card reads as that tab's empty state.
const VIEW_LABELS = {
    dashboard: 'Overview',
    'move-funds': 'Move Funds',
    advanced: 'Advanced',
    disclosure: 'Disclosure',
};

function stateOf({ mode, storeExists, walletState, unlocked }) {
    if (unlocked) return 'ready';
    if (walletState === 'connecting') return 'connecting';
    // `ready` without open storage only happens mid-lock, before the reload.
    if (walletState === 'locked' || walletState === 'ready') return mode === 'encrypted' ? 'locked' : 'connecting';
    return storeExists ? 'returning' : 'welcome';
}

/**
 * @param {{
 *   mode: 'encrypted' | 'plaintext',
 *   storeExists: boolean,
 *   walletState?: string,
 *   walletConnected: boolean,
 *   unlocked: boolean,
 *   storageState?: string,
 *   view?: string,
 * }} input
 */
export function describeAccess({ mode, storeExists, walletState, walletConnected, unlocked, storageState, view }) {
    const copy = COPY[mode];
    if (!copy) throw new Error(`Unknown storage mode: ${mode}`);
    const state = stateOf({ mode, storeExists, walletState, unlocked });
    const connecting = walletState === 'connecting';
    const unlocking = storageState === 'unlocking' || storageState === 'locking';
    const busy = connecting || unlocking;

    let action = 'connect';
    if (busy || (state === 'ready' && walletConnected)) action = 'none';
    else if (state === 'locked') action = 'unlock';

    let label = '';
    if (connecting) label = 'Connecting…';
    else if (unlocking) label = storageState === 'locking' ? 'Locking…' : 'Unlocking…';
    else if (action === 'unlock') label = 'Unlock';
    else if (action === 'connect') label = copy.connectLabel[state];

    const card = state === 'ready' ? null : copy.cards[state];
    // Verifying a disclosure needs no account, so the card leaves the
    // Disclosure tab alone until the user starts connecting.
    const cardVisible = !!card && !(view === 'disclosure' && (state === 'welcome' || state === 'returning'));

    return {
        state,
        action,
        label,
        busy,
        showLock: mode === 'encrypted' && state === 'ready',
        showViews: state === 'ready',
        card,
        cardVisible,
        viewLabel: VIEW_LABELS[view] ?? null,
    };
}
