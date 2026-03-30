/**
 * Pool Store - manages local pool state including merkle tree, nullifiers, and commitments.
 * Syncs from Pool contract events (NewCommitment, NewNullifier).
 *
 * Storage and Merkle tree operations are delegated to the Rust WASM StateManager.
 *
 * @module state/pool-store
 */

import { get as wasm } from './wasm.js';
import {
    bytesToHex,
    normalizeU256ToHex,
    normalizeHex,
    TREE_DEPTH,
} from './utils.js';

// Alias for backwards compatibility
const POOL_TREE_DEPTH = TREE_DEPTH;

/**
 * @typedef {Object} PoolLeaf
 * @property {number} index - Leaf index in merkle tree
 * @property {string} commitment - Commitment hash
 * @property {number} ledger - Ledger when added
 */

/**
 * @typedef {Object} PoolNullifier
 * @property {string} nullifier - Nullifier hash
 * @property {number} ledger - Ledger when spent
 */

/**
 * @typedef {Object} PoolEncryptedOutput
 * @property {string} commitment - Commitment hash
 * @property {number} index - Leaf index
 * @property {string} encryptedOutput - Encrypted output data
 * @property {number} ledger - Ledger when created
 */

/**
 * Initializes the pool store.
 * Tree is already built by the WASM StateManager constructor.
 * @returns {Promise<void>}
 */
export async function init() {
    // No-op: WASM StateManager rebuilds the tree on construction.
    const leafCount = wasm().get_pool_leaf_count();
    console.log(`[PoolStore] Initialized with ${leafCount} leaves (WASM)`);
}

/**
 * Rebuilds the merkle tree from the database.
 * @returns {Promise<number>} Number of leaves in the rebuilt tree
 */
export async function rebuildTree() {
    const count = wasm().rebuild_pool_tree();
    console.log(`[PoolStore] Rebuilt tree with ${count} leaves`);
    return count;
}

/**
 * Processes a NewCommitment event from the Pool contract.
 * @param {Object} event - Parsed event
 * @param {string} event.commitment - Commitment U256 value
 * @param {number} event.index - Leaf index
 * @param {string} event.encryptedOutput - Encrypted output bytes
 * @param {number} ledger - Ledger sequence
 * @returns {Promise<void>}
 */
export async function processNewCommitment(event, ledger) {
    const commitment = normalizeU256ToHex(event.commitment);
    const index = typeof event.index === 'bigint' ? Number(event.index) : Number(event.index);
    const encryptedOutput = event.encryptedOutput;

    const encHex = typeof encryptedOutput === 'string'
        ? encryptedOutput
        : bytesToHex(encryptedOutput);

    wasm().process_new_commitment(commitment, index, encHex, ledger);
}

/**
 * Processes a NewNullifier event from the Pool contract.
 * @param {Object} event - Parsed event
 * @param {string} event.nullifier - Nullifier U256 value
 * @param {number} ledger - Ledger sequence
 * @returns {Promise<void>}
 */
export async function processNewNullifier(event, ledger) {
    const nullifier = normalizeU256ToHex(event.nullifier);
    wasm().process_new_nullifier(nullifier, ledger);
}

/**
 * Processes a batch of Pool events.
 * @param {Array} events - Parsed events with topic and value
 * @param {number} ledger - Ledger sequence
 * @returns {Promise<{commitments: number, nullifiers: number}>}
 */
export async function processEvents(events, ledger) {
    let commitments = 0;
    let nullifiers = 0;

    for (const event of events) {
        const eventType = event.topic?.[0];

        if (eventType === 'NewCommitmentEvent' || eventType === 'new_commitment_event' || eventType === 'new_commitment') {
            const commitment = event.topic?.[1];
            const index = event.value?.index;
            const encryptedOutput = event.value?.encrypted_output;

            await processNewCommitment({
                commitment,
                index,
                encryptedOutput,
            }, event.ledger || ledger);
            commitments++;
        } else if (eventType === 'NewNullifierEvent' || eventType === 'new_nullifier_event' || eventType === 'new_nullifier') {
            const nullifier = event.topic?.[1];
            await processNewNullifier({
                nullifier,
            }, event.ledger || ledger);
            nullifiers++;
        }
    }

    return { commitments, nullifiers };
}

/**
 * Gets the current merkle root as LE bytes.
 * @returns {Uint8Array|null}
 */
export function getRoot() {
    return new Uint8Array(wasm().get_pool_root());
}

/**
 * Gets a merkle proof for a leaf at the given index.
 * @param {number} leafIndex - Index of the leaf
 * @returns {Object|null} Merkle proof with path_elements, path_indices, root
 */
export async function getMerkleProof(leafIndex) {
    try {
        const maxIndex = wasm().get_pool_next_index();
        console.log(`[PoolStore] getMerkleProof: tree has ${maxIndex} leaves, requesting index ${leafIndex}`);

        if (leafIndex >= maxIndex) {
            console.error(`[PoolStore] Leaf index ${leafIndex} out of range (max: ${maxIndex - 1})`);
            return null;
        }

        const proof = wasm().get_pool_merkle_proof(leafIndex);

        const rootBytesLE = new Uint8Array(wasm().get_pool_root());
        const rootBytesBE = Uint8Array.from(rootBytesLE).reverse();
        console.log(`[PoolStore] Built proof for index ${leafIndex}`);
        console.log(`[PoolStore] Tree root (BE): ${bytesToHex(rootBytesBE)}`);

        return proof;
    } catch (e) {
        console.error('[PoolStore] Failed to get merkle proof:', e);
        return null;
    }
}

/**
 * Checks if a nullifier has been spent.
 * @param {string|Uint8Array} nullifier - Nullifier to check
 * @returns {Promise<boolean>}
 */
export async function isNullifierSpent(nullifier) {
    const hex = typeof nullifier === 'string' ? normalizeHex(nullifier) : bytesToHex(nullifier);
    return wasm().is_nullifier_spent(hex);
}

/**
 * Gets all encrypted outputs for potential note detection.
 * @param {number} [fromLedger] - Only get outputs from this ledger onwards
 * @returns {Promise<PoolEncryptedOutput[]>}
 */
export async function getEncryptedOutputs(fromLedger) {
    const json = wasm().get_encrypted_outputs(fromLedger ?? null);
    return JSON.parse(json);
}

/**
 * Gets the total number of leaves in the pool.
 * @returns {Promise<number>}
 */
export async function getLeafCount() {
    return wasm().get_pool_leaf_count();
}

/**
 * Gets the next leaf index (same as leaf count).
 * @returns {number}
 */
export function getNextIndex() {
    return wasm().get_pool_next_index();
}

/**
 * Clears all pool data (for resync).
 * @returns {Promise<void>}
 */
export async function clear() {
    wasm().clear_pool();
    console.log('[PoolStore] Cleared all data');
}

export { POOL_TREE_DEPTH };
