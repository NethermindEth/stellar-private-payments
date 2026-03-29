/**
 * WASM State Bridge loader.
 * Lazily imports and initializes the Rust StateManager WASM module.
 * All persistent storage and Merkle tree operations go through here.
 * @module state/wasm
 */

import initStateWasm, { StateManager } from './wasm-state/state.js';

let stateManager = null;
let initPromise = null;

/**
 * Initializes the WASM state module and opens the database.
 * Safe to call multiple times — returns the same instance.
 * @returns {Promise<StateManager>}
 */
export async function init() {
    if (stateManager) return stateManager;
    if (initPromise) return initPromise;

    initPromise = (async () => {
        console.log('[WASM] Initializing state module...');
        await initStateWasm();
        stateManager = new StateManager();
        console.log('[WASM] State module initialized');
        return stateManager;
    })();

    return initPromise;
}

/**
 * Gets the initialized StateManager instance.
 * @returns {StateManager}
 * @throws {Error} If not yet initialized
 */
export function get() {
    if (!stateManager) {
        throw new Error('WASM state module not initialized — call init() first');
    }
    return stateManager;
}

/**
 * Checks if the WASM state module is initialized.
 * @returns {boolean}
 */
export function isReady() {
    return stateManager !== null;
}
