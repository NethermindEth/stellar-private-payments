/**
 * ASP Membership Store - manages local merkle tree for ASP membership proofs.
 * Syncs from ASP Membership contract events (LeafAdded).
 *
 * Storage and Merkle tree operations are delegated to the Rust WASM StateManager.
 *
 * @module state/asp-membership-store
 */

import { get as wasm } from './wasm.js';
import {
    bytesToHex,
    normalizeU256ToHex,
    TREE_DEPTH,
} from './utils.js';

// Alias for backwards compatibility
const ASP_MEMBERSHIP_TREE_DEPTH = TREE_DEPTH;

/**
 * @typedef {Object} ASPMembershipLeaf
 * @property {number} index - Leaf index in merkle tree
 * @property {string} leaf - Leaf hash
 * @property {string} root - Root after insertion
 * @property {number} ledger - Ledger when added
 */

/**
 * Initializes the ASP membership store.
 * Tree is already built by the WASM StateManager constructor.
 * @returns {Promise<void>}
 */
export async function init() {
    try {
        const leafCount = wasm().get_asp_membership_leaf_count();
        console.log(`[ASPMembershipStore] Initialized with ${leafCount} leaves (WASM)`);
    } catch (e) {
        console.error('[ASPMembershipStore] Failed to read leaf count during init:', e);
    }
}

/**
 * Processes a LeafAdded event from the ASP Membership contract.
 * @param {Object} event - Parsed event
 * @param {string} event.leaf - Leaf U256 value
 * @param {number} event.index - Leaf index
 * @param {string} event.root - New root after insertion
 * @param {number} ledger - Ledger sequence
 * @returns {Promise<void>}
 */
export async function processLeafAdded(event, ledger) {
    const leaf = normalizeU256ToHex(event.leaf);
    const index = Number(event.index);
    const root = normalizeU256ToHex(event.root);

    try {
        wasm().process_asp_leaf_added(leaf, index, root, ledger);
    } catch (e) {
        console.error(`[ASPMembershipStore] Failed to process leaf at index ${index}:`, e);
        throw e;
    }
    console.log(`[ASPMembershipStore] Stored leaf at index ${index}`);
}

/**
 * Processes a batch of ASP Membership events.
 * @param {Array} events - Parsed events with topic and value
 * @param {number} ledger - Default ledger if not in event
 * @returns {Promise<number>} Number of leaves processed
 */
export async function processEvents(events, ledger) {
    let count = 0;

    if (events.length === 0) {
        console.log('[ASPMembershipStore] No events to process');
        return count;
    }

    console.log(`[ASPMembershipStore] Processing ${events.length} events...`);

    // Filter and sort LeafAdded events by index
    const leafEvents = events
        .filter(e => {
            const topic = e.topic?.[0];
            return topic === 'LeafAdded' ||
                   topic === 'leaf_added' ||
                   (typeof topic === 'string' && topic.includes('LeafAdded'));
        })
        .map(e => ({
            leaf: e.value?.leaf,
            index: Number(e.value?.index),
            root: e.value?.root,
            ledger: e.ledger || ledger,
        }))
        .sort((a, b) => a.index - b.index);

    if (leafEvents.length === 0 && events.length > 0) {
        console.log('[ASPMembershipStore] No LeafAdded events found in batch. Event types seen:',
            [...new Set(events.map(e => JSON.stringify(e.topic)))].join(', '));
        return count;
    }

    // Get current tree state to skip already-processed events
    const nextIdx = wasm().get_asp_membership_next_index();

    for (const event of leafEvents) {
        // Skip events we've already processed
        if (event.index < nextIdx) {
            console.log(`[ASPMembershipStore] Skipping already-processed leaf at index ${event.index}`);
            continue;
        }

        console.log('[ASPMembershipStore] Processing LeafAdded:', event);
        await processLeafAdded(event, event.ledger);
        count++;
    }

    return count;
}

/**
 * Gets the current merkle root as LE bytes.
 * @returns {Uint8Array|null}
 */
export function getRoot() {
    return new Uint8Array(wasm().get_asp_membership_root());
}

/**
 * Gets a merkle proof for a leaf at the given index.
 * @param {number} leafIndex - Index of the leaf
 * @returns {Object|null} Merkle proof with path_elements, path_indices, root
 */
export function getMerkleProof(leafIndex) {
    try {
        if (!Number.isInteger(leafIndex) || leafIndex < 0) {
            console.error(`[ASPMembershipStore] Invalid leaf index: ${leafIndex}`);
            return null;
        }
        const maxIndex = wasm().get_asp_membership_next_index();
        if (leafIndex >= maxIndex) {
            console.error(`[ASPMembershipStore] Leaf index ${leafIndex} out of range (max: ${maxIndex - 1})`);
            return null;
        }

        return wasm().get_asp_membership_proof(leafIndex);
    } catch (e) {
        console.error('[ASPMembershipStore] Failed to get merkle proof:', e);
        return null;
    }
}

/**
 * Gets the total number of leaves.
 * @returns {Promise<number>}
 */
export async function getLeafCount() {
    return wasm().get_asp_membership_leaf_count();
}

/**
 * Gets the next leaf index.
 * @returns {number}
 */
export function getNextIndex() {
    return wasm().get_asp_membership_next_index();
}

/**
 * Finds a leaf by its hash value.
 * @param {string|Uint8Array} leafHash - Leaf hash to find
 * @returns {Promise<ASPMembershipLeaf|null>}
 */
export async function findLeafByHash(leafHash) {
    try {
        const hex = typeof leafHash === 'string' ? leafHash : bytesToHex(leafHash);
        const json = wasm().find_asp_membership_leaf(hex);
        return JSON.parse(json);
    } catch (e) {
        console.error('[ASPMembershipStore] Failed to find leaf by hash:', e);
        return null;
    }
}

/**
 * Clears all ASP membership data and resets the tree.
 * @returns {Promise<void>}
 */
export async function clear() {
    wasm().clear_asp_membership();
    console.log('[ASPMembershipStore] Cleared all data');
}

export { ASP_MEMBERSHIP_TREE_DEPTH };
