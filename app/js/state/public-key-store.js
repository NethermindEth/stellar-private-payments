/**
 * Public Key Store - manages registered public keys for the address book.
 * Syncs from Pool contract events (PublicKeyEvent).
 * 
 * @module state/public-key-store
 */

import * as db from './db.js';
import { bytesToHex, normalizeHex } from './utils.js';
import { getContractEvents, getDeployedContracts, getLatestLedger } from '../stellar.js';

/**
 * @typedef {Object} PublicKeyRecord
 * @property {string} address - Stellar address (owner)
 * @property {string} publicKey - Registered public key (hex)
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
 * @param {Object} event - Parsed event with owner and key
 * @param {string} event.owner - Stellar address
 * @param {string|Uint8Array} event.key - Public key
 * @param {number} ledger - Ledger sequence
 * @returns {Promise<void>}
 */
export async function processPublicKeyEvent(event, ledger) {
    const address = event.owner;
    const publicKey = typeof event.key === 'string' 
        ? normalizeHex(event.key) 
        : bytesToHex(event.key);
    
    const record = {
        address,
        publicKey,
        ledger,
        registeredAt: new Date().toISOString(),
    };
    
    await db.put('registered_public_keys', record);
    
    console.log(`[PublicKeyStore] Stored public key for ${address.slice(0, 8)}...`);
    
    emit('publicKeyRegistered', { address, publicKey, ledger });
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
        
        // Match various event name formats (Soroban converts struct names to snake_case)
        if (eventType === 'PublicKeyEvent' || eventType === 'public_key_event') {
            const owner = event.value?.owner || event.topic?.[1];
            const key = event.value?.key;
            
            if (owner && key) {
                await processPublicKeyEvent({ owner, key }, event.ledger);
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
 * Searches for a public key, querying on-chain if not found locally.
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
                    const key = event.value?.key;
                    const publicKey = typeof key === 'string' 
                        ? normalizeHex(key) 
                        : bytesToHex(key);
                    
                    const record = {
                        address,
                        publicKey,
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
