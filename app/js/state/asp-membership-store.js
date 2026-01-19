/**
 * ASP Membership Store - manages local merkle tree for ASP membership proofs.
 * Syncs from ASP Membership contract events (LeafAdded).
 * 
 * Init uses cursor iteration to avoid memory issues with large datasets.
 * TODO: Move to a web worker later.
 * 
 * @module state/asp-membership-store
 */

import * as db from './db.js';
import { createMerkleTree } from '../bridge.js';
import { hexToBytes, bytesToHex, normalizeU256ToHex } from './utils.js';

// Note: This should match the actual contract depth
// For now using 20 (1M leaves) to avoid memory issues
// TODO: Read actual depth from contract state
const ASP_MEMBERSHIP_TREE_DEPTH = 20; // Depth 20 = 2^20 = 1,048,576 leaves (reasonable for WASM)

let merkleTree = null;

/**
 * @typedef {Object} ASPMembershipLeaf
 * @property {number} index - Leaf index in merkle tree
 * @property {string} leaf - Leaf hash 
 * @property {string} root - Root after insertion 
 * @property {number} ledger - Ledger when added
 */

/**
 * Initializes the ASP membership store and merkle tree.
 * Uses cursor-based iteration to avoid loading the entire table into memory.
 * @returns {Promise<void>}
 */
export async function init() {
    merkleTree = createMerkleTree(ASP_MEMBERSHIP_TREE_DEPTH);
    
    // Use cursor to iterate leaves in index order without loading all into memory
    let leafCount = 0;
    let expectedIndex = 0;
    
    await db.iterate('asp_membership_leaves', (leaf) => {
        if (leaf.index !== expectedIndex) {
            console.error(`[ASPMembershipStore] Gap in leaf indices: expected ${expectedIndex}, got ${leaf.index}`);
            throw new Error('[ASPMembershipStore] Gap in leaf indices, aborting init');
        }
        
        const leafBytes = hexToBytes(leaf.leaf);
        merkleTree.insert(leafBytes);
        leafCount++;
        expectedIndex = leaf.index + 1;
    }, { direction: 'next' });
    
    console.log(`[ASPMembershipStore] Initialized with ${leafCount} leaves`);
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
    
    // Store leaf
    await db.put('asp_membership_leaves', {
        index,
        leaf,
        root,
        ledger,
    });
    
    // Update merkle tree
    if (merkleTree) {
        // Enforce ordering
        if (index !== merkleTree.next_index()) {
            throw new Error(`Out-of-order insertion: expected ${merkleTree.next_index()}, got ${index}`);
        }
        
        const leafBytes = hexToBytes(leaf);
        merkleTree.insert(leafBytes);
        // Check we get the same root after insertion
        const computedRoot = bytesToHex(merkleTree.root());
        if (computedRoot !== root) {
            console.error(`[ASPMembershipStore] Root mismatch after insert at index ${index}`);
            console.error(`  Expected: ${root}`);
            console.error(`  Computed: ${computedRoot}`);
            throw new Error('[ASPMembershipStore] Root mismatch after insert. Corrupted state. Aborting');
        }
    }
}

/**
 * Processes a batch of ASP Membership events.
 * @param {Array} events - Parsed events with topic and value
 * @param {number} ledger - Default ledger if not in event
 * @returns {Promise<number>} Number of leaves processed
 */
export async function processEvents(events, ledger) {
    let count = 0;
    
    for (const event of events) {
        const eventType = event.topic?.[0];
        
        // Event topic is ["LeafAdded"] with value containing leaf, index, root
        if (eventType === 'LeafAdded' || eventType === 'leaf_added') {
            await processLeafAdded({
                leaf: event.value?.leaf,
                index: event.value?.index,
                root: event.value?.root,
            }, event.ledger || ledger);
            count++;
        }
    }
    
    return count;
}

/**
 * Gets the current merkle root.
 * @returns {Uint8Array|null}
 */
export function getRoot() {
    if (!merkleTree) return null;
    return merkleTree.root();
}

/**
 * Gets a merkle proof for a leaf at the given index.
 * @param {number} leafIndex - Index of the leaf
 * @returns {Object|null} Merkle proof with siblings and path indices
 */
export function getMerkleProof(leafIndex) {
    if (!merkleTree) return null;
    try {
        return merkleTree.proof(leafIndex);
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
    return db.count('asp_membership_leaves');
}

/**
 * Gets the next leaf index.
 * @returns {number}
 */
export function getNextIndex() {
    if (!merkleTree) return 0;
    return merkleTree.next_index();
}

/**
 * Finds a leaf by its hash value.
 * @param {string|Uint8Array} leafHash - Leaf hash to find
 * @returns {Promise<ASPMembershipLeaf|null>}
 */
export async function findLeafByHash(leafHash) {
    const hex = typeof leafHash === 'string' ? leafHash : bytesToHex(leafHash);
    const result = await db.getByIndex('asp_membership_leaves', 'by_leaf', hex);
    return result || null;
}

/**
 * Clears all ASP membership data if we want to force a re-sync
 * @returns {Promise<void>}
 */
export async function clear() {
    await db.clear('asp_membership_leaves');
    merkleTree = createMerkleTree(ASP_MEMBERSHIP_TREE_DEPTH);
    console.log('[ASPMembershipStore] Cleared all data');
}

export { ASP_MEMBERSHIP_TREE_DEPTH };
