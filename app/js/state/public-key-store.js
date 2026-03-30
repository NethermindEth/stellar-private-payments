/**
 * Public Key Store - manages registered public keys for the address book.
 * Syncs from Pool contract events (PublicKeyEvent).
 *
 * Stores two key types per user:
 * - encryptionKey: X25519 key for encrypting note data (amount, blinding)
 * - noteKey: BN254 key for creating commitments in the ZK circuit
 *
 * @module state/public-key-store
 */

import { get as wasm } from './wasm.js';
import { bytesToHex, normalizeHex } from './utils.js';
import { fieldToHex } from '../bridge.js';
import { getContractEvents, getDeployedContracts, getLatestLedger } from '../stellar.js';

/**
 * @typedef {Object} PublicKeyRecord
 * @property {string} address - Stellar address (owner)
 * @property {string} encryptionKey - X25519 encryption public key (hex, 32 bytes)
 * @property {string} noteKey - BN254 note public key (hex, 32 bytes)
 * @property {string} [publicKey] - Legacy field, alias for encryptionKey (deprecated)
 * @property {number} ledger - Ledger when registered
 * @property {string} [registeredAt] - ISO timestamp (if known)
 */

let eventListeners = [];

/**
 * Initializes the public key store.
 * @returns {Promise<void>}
 */
export async function init() {
    console.log('[PublicKeyStore] Initialized');
}

/**
 * Processes a PublicKeyEvent from the Pool contract.
 * @param {Object} event - Parsed event
 * @param {string} event.owner - Stellar address
 * @param {string|Uint8Array} [event.encryption_key] - X25519 encryption key
 * @param {string|Uint8Array} [event.note_key] - BN254 note key
 * @param {string|Uint8Array} [event.key] - Legacy public key field
 * @param {number} ledger - Ledger sequence
 * @returns {Promise<void>}
 */
export async function processPublicKeyEvent(event, ledger) {
    const address = event.owner;

    let encryptionKey, noteKey;

    if (event.encryption_key && event.note_key) {
        encryptionKey = typeof event.encryption_key === 'string'
            ? normalizeHex(event.encryption_key)
            : bytesToHex(event.encryption_key);
        noteKey = typeof event.note_key === 'string'
            ? normalizeHex(event.note_key)
            : fieldToHex(event.note_key);
    } else if (event.key) {
        const legacyKey = typeof event.key === 'string'
            ? normalizeHex(event.key)
            : bytesToHex(event.key);
        encryptionKey = legacyKey;
        noteKey = legacyKey;
        console.warn('[PublicKeyStore] Processing legacy single-key format');
    } else {
        console.error('[PublicKeyStore] Invalid event format - no keys found');
        return;
    }

    const registeredAt = new Date().toISOString();
    try {
        wasm().store_public_key(address, encryptionKey, noteKey, ledger, registeredAt);
    } catch (e) {
        console.error(`[PublicKeyStore] Failed to store keys for ${address.slice(0, 8)}...:`, e);
        return;
    }

    console.log(`[PublicKeyStore] Stored keys for ${address.slice(0, 8)}...`);
    emit('publicKeyRegistered', { address, encryptionKey, noteKey, ledger });
}

/**
 * Processes a batch of Pool events for public key registrations.
 * @param {Array} events - Parsed events with topic and value
 * @returns {Promise<{registrations: number}>}
 */
export async function processEvents(events) {
    let registrations = 0;

    for (const event of events) {
        const eventType = event.topic?.[0];

        if (eventType === 'PublicKeyEvent' || eventType === 'public_key_event') {
            const owner = event.value?.owner || event.topic?.[1];
            const encryptionKey = event.value?.encryption_key;
            const noteKey = event.value?.note_key;
            const legacyKey = event.value?.key;

            if (owner && (encryptionKey || legacyKey)) {
                await processPublicKeyEvent({
                    owner,
                    encryption_key: encryptionKey,
                    note_key: noteKey,
                    key: legacyKey,
                }, event.ledger);
                registrations++;
            }
        }
    }

    return { registrations };
}

/**
 * Gets a public key record by Stellar address.
 * @param {string} address - Stellar address
 * @returns {Promise<PublicKeyRecord|null>}
 */
export async function getByAddress(address) {
    try {
        return JSON.parse(wasm().get_public_key_by_address(address));
    } catch (e) {
        console.error('[PublicKeyStore] Failed to get by address:', e);
        return null;
    }
}

/**
 * Searches for public keys, querying on-chain if not found locally.
 * @param {string} address - Stellar address to search
 * @returns {Promise<{found: boolean, record?: PublicKeyRecord, source: 'local'|'onchain'|'none'}>}
 */
export async function searchByAddress(address) {
    // Check local first
    const localRecord = await getByAddress(address);
    if (localRecord) {
        return { found: true, record: localRecord, source: 'local' };
    }

    // Query on-chain
    try {
        const contracts = getDeployedContracts();
        if (!contracts?.pool) {
            console.warn('[PublicKeyStore] Pool contract not configured');
            return { found: false, source: 'none' };
        }

        const latestLedger = await getLatestLedger();
        const startLedger = Math.max(1, latestLedger - 200000);

        const result = await getContractEvents(contracts.pool, {
            startLedger,
            limit: 100,
        });

        if (!result.success) {
            console.warn('[PublicKeyStore] Failed to fetch events:', result.error);
            return { found: false, source: 'none' };
        }

        for (const event of result.events) {
            const eventType = event.topic?.[0];
            if (eventType === 'PublicKeyEvent' || eventType === 'public_key_event') {
                const owner = event.value?.owner || event.topic?.[1];
                if (owner === address) {
                    const rawEncKey = event.value?.encryption_key;
                    const rawNoteKey = event.value?.note_key;
                    const rawLegacyKey = event.value?.key;

                    let encryptionKey, noteKey;
                    if (rawEncKey && rawNoteKey) {
                        encryptionKey = typeof rawEncKey === 'string'
                            ? normalizeHex(rawEncKey)
                            : bytesToHex(rawEncKey);
                        noteKey = typeof rawNoteKey === 'string'
                            ? normalizeHex(rawNoteKey)
                            : bytesToHex(rawNoteKey);
                    } else if (rawLegacyKey) {
                        const legacyKey = typeof rawLegacyKey === 'string'
                            ? normalizeHex(rawLegacyKey)
                            : bytesToHex(rawLegacyKey);
                        encryptionKey = legacyKey;
                        noteKey = legacyKey;
                    } else {
                        continue;
                    }

                    const record = {
                        address,
                        encryptionKey,
                        noteKey,
                        publicKey: encryptionKey,
                        ledger: event.ledger,
                    };

                    // Cache locally
                    wasm().store_public_key(
                        address, encryptionKey, noteKey,
                        event.ledger, new Date().toISOString()
                    );

                    return { found: true, record, source: 'onchain' };
                }
            }
        }

        return { found: false, source: 'none' };
    } catch (error) {
        console.error('[PublicKeyStore] On-chain search failed:', error);
        return { found: false, source: 'none' };
    }
}

/**
 * Gets recent public key registrations ordered by ledger (descending).
 * @param {number} [limit=20]
 * @returns {Promise<PublicKeyRecord[]>}
 */
export async function getRecentRegistrations(limit = 20) {
    try {
        const all = JSON.parse(wasm().get_all_public_keys());
        all.sort((a, b) => b.ledger - a.ledger);
        return all.slice(0, limit);
    } catch (e) {
        console.error('[PublicKeyStore] Failed to get recent registrations:', e);
        return [];
    }
}

/**
 * Gets the total count of registered public keys.
 * @returns {Promise<number>}
 */
export async function getCount() {
    return wasm().get_public_key_count();
}

/**
 * Clears all public key data.
 * @returns {Promise<void>}
 */
export async function clear() {
    wasm().clear_public_keys();
    console.log('[PublicKeyStore] Cleared all data');
}

/**
 * Adds an event listener.
 * @param {string} event
 * @param {function} handler
 */
export function on(event, handler) {
    eventListeners.push({ event, handler });
}

/**
 * Removes an event listener.
 * @param {string} event
 * @param {function} handler
 */
export function off(event, handler) {
    eventListeners = eventListeners.filter(
        l => !(l.event === event && l.handler === handler)
    );
}

function emit(event, data) {
    for (const listener of eventListeners) {
        if (listener.event === event) {
            try {
                listener.handler(data);
            } catch (e) {
                console.error(`[PublicKeyStore] Event handler error (${event}):`, e);
            }
        }
    }
}
