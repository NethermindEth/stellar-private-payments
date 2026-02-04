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

import * as db from './db.js';
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
 * Handles both new format (encryption_key + note_key) and legacy format (key only).
 * 
 * @param {Object} event - Parsed event
 * @param {string} event.owner - Stellar address
 * @param {string|Uint8Array} [event.encryption_key] - X25519 encryption key (new format)
 * @param {string|Uint8Array} [event.note_key] - BN254 note key (new format)
 * @param {string|Uint8Array} [event.key] - Legacy public key field
 * @param {number} ledger - Ledger sequence
 * @returns {Promise<void>}
 */
export async function processPublicKeyEvent(event, ledger) {
    const address = event.owner;
    
    // Handle both new format (encryption_key + note_key) and legacy format (key)
    let encryptionKey, noteKey;
    
    if (event.encryption_key && event.note_key) {
        // New format with both keys
        // X25519 encryption keys are raw bytes - use bytesToHex (no reversal)
        encryptionKey = typeof event.encryption_key === 'string' 
            ? normalizeHex(event.encryption_key) 
            : bytesToHex(event.encryption_key);
        // BN254 note keys are field elements - use fieldToHex (LE→BE) so hexToField works correctly
        noteKey = typeof event.note_key === 'string' 
            ? normalizeHex(event.note_key) 
            : fieldToHex(event.note_key);
    } else if (event.key) {
        // Legacy format - use same key for both (backward compatibility)
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
    
    const record = {
        address,
        encryptionKey,
        noteKey,
        publicKey: encryptionKey, // Legacy alias
        ledger,
        registeredAt: new Date().toISOString(),
    };
    
    await db.put('registered_public_keys', record);
    
    console.log(`[PublicKeyStore] Stored keys for ${address.slice(0, 8)}...`);
    
    emit('publicKeyRegistered', { address, encryptionKey, noteKey, ledger });
}

/**
 * Processes a batch of Pool events for public key registrations.
 * Handles both new format (encryption_key + note_key) and legacy format (key).
 * 
 * @param {Array} events - Parsed events with topic and value
 * @returns {Promise<{registrations: number}>}
 */
export async function processEvents(events) {
    let registrations = 0;
    
    for (const event of events) {
        const eventType = event.topic?.[0];
        
        // Match various event name formats (Soroban converts struct names to snake_case)
        if (eventType === 'PublicKeyEvent' || eventType === 'public_key_event') {
            const owner = event.value?.owner || event.topic?.[1];
            
            // Try new format first (encryption_key + note_key)
            const encryptionKey = event.value?.encryption_key;
            const noteKey = event.value?.note_key;
            // Fallback to legacy format (key)
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
    return await db.get('registered_public_keys', address) || null;
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
        // Search within retention window (roughly 17 days worth)
        const startLedger = Math.max(1, latestLedger - 200000);
        
        const result = await getContractEvents(contracts.pool, {
            startLedger,
            limit: 100,
        });
        
        if (!result.success) {
            console.warn('[PublicKeyStore] Failed to fetch events:', result.error);
            return { found: false, source: 'none' };
        }
        
        // Look for PublicKeyEvent matching the address
        for (const event of result.events) {
            const eventType = event.topic?.[0];
            if (eventType === 'PublicKeyEvent' || eventType === 'public_key_event') {
                const owner = event.value?.owner || event.topic?.[1];
                if (owner === address) {
                    // Try new format first (encryption_key + note_key)
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
                        publicKey: encryptionKey, // Legacy alias
                        ledger: event.ledger,
                    };
                    
                    // Cache locally
                    await db.put('registered_public_keys', {
                        ...record,
                        registeredAt: new Date().toISOString(),
                    });
                    
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
 * @param {number} [limit=20] - Maximum records to return
 * @returns {Promise<PublicKeyRecord[]>}
 */
export async function getRecentRegistrations(limit = 20) {
    const all = await db.getAll('registered_public_keys');
    // Sort by ledger descending (most recent first)
    all.sort((a, b) => b.ledger - a.ledger);
    return all.slice(0, limit);
}

/**
 * Gets the total count of registered public keys.
 * @returns {Promise<number>}
 */
export async function getCount() {
    return db.count('registered_public_keys');
}

/**
 * Clears all public key data.
 * @returns {Promise<void>}
 */
export async function clear() {
    await db.clear('registered_public_keys');
    console.log('[PublicKeyStore] Cleared all data');
}

/**
 * Adds an event listener.
 * @param {string} event - Event name ('publicKeyRegistered')
 * @param {function} handler - Event handler
 */
export function on(event, handler) {
    eventListeners.push({ event, handler });
}

/**
 * Removes an event listener.
 * @param {string} event - Event name
 * @param {function} handler - Event handler
 */
export function off(event, handler) {
    eventListeners = eventListeners.filter(
        l => !(l.event === event && l.handler === handler)
    );
}

/**
 * Emits an event to all listeners.
 * @param {string} event - Event name
 * @param {any} data - Event data
 */
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
