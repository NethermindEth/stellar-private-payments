import { StellarWalletsKit } from '@creit.tech/stellar-wallets-kit/sdk';
import { FreighterModule, FREIGHTER_ID } from '@creit.tech/stellar-wallets-kit/modules/freighter';
import { HanaModule, HANA_ID } from '@creit.tech/stellar-wallets-kit/modules/hana';
import { xBullModule, XBULL_ID } from '@creit.tech/stellar-wallets-kit/modules/xbull';
import { AlbedoModule, ALBEDO_ID } from '@creit.tech/stellar-wallets-kit/modules/albedo';
import { Networks, SwkAppDarkTheme } from '@creit.tech/stellar-wallets-kit/types';

import { getHandle } from './wasm-facade.js';

const WALLET_STORAGE_KEY = 'poolstellar-selected-wallet';

const SOROBAN_RPC_BY_PASSPHRASE = {
    [Networks.TESTNET]: 'https://soroban-testnet.stellar.org',
    [Networks.PUBLIC]: 'https://soroban.stellar.org',
    [Networks.FUTURENET]: 'https://rpc-futurenet.stellar.org',
};

/**
 * Wallets bundled for this app. Freighter and Hana support signTransaction,
 * signAuthEntry, and signMessage. xBull and Albedo are included for broader
 * coverage but cannot complete all flows (see WALLET_CAPABILITIES).
 */
const APP_WALLET_MODULES = [
    new FreighterModule(),
    new HanaModule(),
    new xBullModule(),
    new AlbedoModule(),
];

/** @type {Record<string, { signTransaction: boolean, signAuthEntry: boolean, signMessage: boolean }>} */
export const WALLET_CAPABILITIES = {
    [FREIGHTER_ID]: { signTransaction: true, signAuthEntry: true, signMessage: true },
    [HANA_ID]: { signTransaction: true, signAuthEntry: true, signMessage: true },
    [XBULL_ID]: { signTransaction: true, signAuthEntry: false, signMessage: true },
    [ALBEDO_ID]: { signTransaction: true, signAuthEntry: false, signMessage: false },
};

const APP_THEME = {
    ...SwkAppDarkTheme,
    primary: '#f59e0b',
    'primary-foreground': '#0a0a0a',
    background: '#171717',
    'background-secondary': '#0a0a0a',
    'font-family': 'Outfit, sans-serif',
};

let kitReady = false;

function readSavedWalletId() {
    try {
        const saved = localStorage.getItem(WALLET_STORAGE_KEY);
        return APP_WALLET_MODULES.some((mod) => mod.productId === saved) ? saved : FREIGHTER_ID;
    } catch {
        return FREIGHTER_ID;
    }
}

function persistWalletId(id) {
    try {
        localStorage.setItem(WALLET_STORAGE_KEY, id);
    } catch {
        // best-effort
    }
}

function ensureKitInitialized() {
    if (kitReady) return;
    StellarWalletsKit.init({
        modules: APP_WALLET_MODULES,
        network: Networks.TESTNET,
        selectedWalletId: readSavedWalletId(),
        theme: APP_THEME,
        authModal: {
            showInstallLabel: true,
            hideUnsupportedWallets: true,
        },
    });
    kitReady = true;
}

function getActiveWalletId() {
    ensureKitInitialized();
    return StellarWalletsKit.selectedModule.productId;
}

function assertWalletCapabilities(walletId = getActiveWalletId()) {
    const caps = WALLET_CAPABILITIES[walletId];
    if (!caps?.signMessage || !caps?.signAuthEntry) {
        const name = StellarWalletsKit.selectedModule.productName;
        throw new Error(
            `${name} does not support all signing methods required by this app. ` +
            'Please connect with Freighter or Hana Wallet.',
        );
    }
}

/**
 * Normalize wallet errors to a consistent shape.
 *
 * @param {unknown} error
 * @param {string} fallbackMessage
 * @returns {Error}
 */
function normalizeWalletError(error, fallbackMessage = 'Wallet error') {
    const message = error?.message || fallbackMessage;
    const lower = String(message).toLowerCase();
    const err = new Error(message);
    const userRejected =
        error?.code === -1 ||
        /reject|declin|denied|cancel|closed the modal/.test(lower);
    err.code = userRejected ? 'USER_REJECTED' : 'WALLET_ERROR';
    err.cause = error;
    return err;
}

async function ensureWalletReady() {
    ensureKitInitialized();
    try {
        await StellarWalletsKit.getAddress();
    } catch {
        throw new Error('No wallet connected. Please connect your wallet first.');
    }
}

function resolveSorobanRpcUrl(networkPassphrase) {
    return SOROBAN_RPC_BY_PASSPHRASE[networkPassphrase] || '';
}

/**
 * Open the wallet picker modal and return the connected public key.
 * @param {{silent?: boolean}} [opts]
 * @returns {Promise<string>}
 */
export async function connectWallet(opts = {}) {
    const { silent = false } = opts;
    ensureKitInitialized();

    try {
        try {
            const { address } = await StellarWalletsKit.getAddress();
            if (address) {
                assertWalletCapabilities();
                return address;
            }
        } catch {
            // No active session in kit memory.
        }

        if (silent) {
            const { address } = await StellarWalletsKit.fetchAddress();
            if (!address) {
                throw new Error('No public key returned');
            }
            persistWalletId(getActiveWalletId());
            assertWalletCapabilities();
            return address;
        }

        const { address } = await StellarWalletsKit.authModal();
        if (!address) {
            throw new Error('No public key returned');
        }
        persistWalletId(getActiveWalletId());
        assertWalletCapabilities();
        return address;
    } catch (e) {
        throw normalizeWalletError(e, 'Wallet connection failed');
    }
}

/**
 * Fetch the currently active public key without opening the picker.
 * @returns {Promise<string>}
 */
export async function getWalletAddress() {
    await ensureWalletReady();
    const { address } = await StellarWalletsKit.getAddress();
    if (!address) {
        throw new Error('No public key returned');
    }
    return address;
}

/**
 * Watch the connected wallet for address/network changes.
 * @param {{intervalMs?: number, onChange: function}} opts
 * @returns {function} stop watcher
 */
export function startWalletWatcher(opts) {
    const { intervalMs = 3000, onChange } = opts || {};
    let lastAddress = null;
    let lastNetwork = null;
    let lastPassphrase = null;

    const tick = async () => {
        try {
            await ensureWalletReady();
            const { address } = await StellarWalletsKit.getAddress();

            let network = 'TESTNET';
            let networkPassphrase = Networks.TESTNET;
            try {
                const details = await StellarWalletsKit.getNetwork();
                network = details.network || network;
                networkPassphrase = details.networkPassphrase || networkPassphrase;
            } catch {
                // Wallets like Hana do not expose getNetwork; app is testnet-only.
            }

            if (
                address !== lastAddress ||
                network !== lastNetwork ||
                networkPassphrase !== lastPassphrase
            ) {
                lastAddress = address;
                lastNetwork = network;
                lastPassphrase = networkPassphrase;
                onChange?.({ address, network, networkPassphrase });
            }
        } catch (e) {
            onChange?.({ error: e });
        }
    };

    const timer = setInterval(() => {
        void tick();
    }, intervalMs);
    void tick();

    return () => clearInterval(timer);
}

/**
 * Fetch current network details from the connected wallet.
 *
 * @returns {Promise<{network: string, networkUrl: string, networkPassphrase: string, sorobanRpcUrl?: string}>}
 */
export async function getWalletNetwork() {
    await ensureWalletReady();

    let network = 'TESTNET';
    let networkPassphrase = Networks.TESTNET;
    let networkUrl = '';

    try {
        const details = await StellarWalletsKit.getNetwork();
        network = details.network || network;
        networkPassphrase = details.networkPassphrase || networkPassphrase;
    } catch {
        // Fall back to the kit's configured network for wallets without getNetwork.
    }

    return {
        network,
        networkUrl,
        networkPassphrase,
        sorobanRpcUrl: resolveSorobanRpcUrl(networkPassphrase),
    };
}

/**
 * @param {string} transactionXdr
 * @param {Object} opts
 * @param {string} [opts.networkPassphrase]
 * @param {string} [opts.address]
 * @returns {Promise<{signedTxXdr: string, signerAddress: string}>}
 */
export async function signWalletTransaction(transactionXdr, opts = {}) {
    await ensureWalletReady();
    assertWalletCapabilities();

    try {
        const { signedTxXdr, signerAddress } = await StellarWalletsKit.signTransaction(
            transactionXdr,
            opts,
        );
        if (!signedTxXdr) {
            throw new Error('Transaction signature was not returned');
        }
        return { signedTxXdr, signerAddress };
    } catch (e) {
        throw normalizeWalletError(e, 'Transaction signature failed');
    }
}

/**
 * @param {string} entryXdr
 * @param {Object} opts
 * @param {string} [opts.networkPassphrase]
 * @param {string} [opts.address]
 * @returns {Promise<{signedAuthEntry: string | null, signerAddress: string}>}
 */
export async function signWalletAuthEntry(entryXdr, opts = {}) {
    await ensureWalletReady();
    assertWalletCapabilities();

    try {
        const { signedAuthEntry, signerAddress } = await StellarWalletsKit.signAuthEntry(
            entryXdr,
            opts,
        );
        if (!signedAuthEntry) {
            throw new Error('Auth entry signature was not returned');
        }
        return { signedAuthEntry, signerAddress };
    } catch (e) {
        throw normalizeWalletError(e, 'Auth entry signature failed');
    }
}

/**
 * @param {string} message
 * @param {Object} [opts]
 * @param {string} [opts.address]
 * @param {string} [opts.networkPassphrase]
 * @param {boolean} [opts.skipEnsureReady]
 * @returns {Promise<{signedMessage: string | null, signerAddress: string}>}
 */
export async function signWalletMessage(message, opts = {}) {
    const { skipEnsureReady = false, ...signOpts } = opts || {};
    if (!skipEnsureReady) {
        await ensureWalletReady();
    }
    assertWalletCapabilities();

    console.log('[Wallet] Requesting message signature for:', message.substring(0, 30) + '...');
    try {
        const { signedMessage, signerAddress } = await StellarWalletsKit.signMessage(
            message,
            signOpts,
        );
        console.log('[Wallet] signMessage result:', {
            hasSignedMessage: !!signedMessage,
        });
        if (!signedMessage) {
            throw new Error('No signature returned. User may have rejected the request.');
        }
        return { signedMessage, signerAddress };
    } catch (e) {
        throw normalizeWalletError(e, 'Message signature failed');
    }
}

/**
 * Derives spending and encryption keys from a single wallet signature.
 *
 * @param {string} account
 * @param {Object} options
 * @param {function} options.onStatus
 * @param {Object} [options.signOptions]
 * @param {boolean} [options.skipCacheCheck]
 */
export async function deriveKeysFromWallet(
    account,
    { onStatus, signOptions = {}, skipCacheCheck = false }
) {
    const client = getHandle().webClient;
    let data = null;
    let aspSecret = null;
    if (!skipCacheCheck) {
        data = await client.getUserKeys(account);
        aspSecret = await client.getASPSecret(account);
        if (data && aspSecret?.membershipBlinding) {
            onStatus?.('Loaded privacy keys and ASP secret from local storage');
            return {
                pubKey: data.noteKeypair.public,
                encryptionKeypair: {
                    publicKey: data.encryptionKeypair.public,
                },
                aspSecret: aspSecret.membershipBlinding,
            };
        }
    }

    onStatus?.('Signature: derive privacy keys and ASP secret (does not move funds)...');

    let derivationResult;
    try {
        derivationResult = await signWalletMessage(client.keyDerivationMessage(), {
            ...signOptions,
            skipEnsureReady: true,
        });
    } catch (e) {
        if (e.code === 'USER_REJECTED') {
            throw new Error('Please approve the message signature to derive your privacy keys and ASP secret');
        }
        throw e;
    }

    if (!derivationResult?.signedMessage) {
        throw new Error('Key derivation signature rejected');
    }

    const signatureBytes = Uint8Array.from(atob(derivationResult.signedMessage), c => c.charCodeAt(0));
    await client.deriveAndSaveUserKeys(account, signatureBytes);

    data = await client.getUserKeys(account);
    aspSecret = await client.getASPSecret(account);
    if (!data || !aspSecret?.membershipBlinding) {
        throw new Error('Derived privacy keys or ASP secret are unavailable');
    }

    return {
        pubKey: data.noteKeypair.public,
        encryptionKeypair: {
            publicKey: data.encryptionKeypair.public,
        },
        aspSecret: aspSecret.membershipBlinding,
    };
}

/**
 * Disconnect the active wallet session.
 * @returns {Promise<void>}
 */
export async function disconnectWallet() {
    ensureKitInitialized();
    await StellarWalletsKit.disconnect();
}
