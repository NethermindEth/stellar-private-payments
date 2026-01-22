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
import { createMerkleTreeWithZeroLeaf } from '../bridge.js';
import { hexToBytes, bytesToHex, normalizeU256ToHex } from './utils.js';

/**
 * Converts hex string to bytes for Merkle tree insertion.
 * 
 * The Rust Merkle tree uses from_le_bytes_mod_order (LE).
 * Soroban stores U256 as BE and converts via BigUint::from_bytes_be.
 * Reversing BE to LE ensures the same numeric value.
 * 
 * @param {string} hex - Hex string (BE representation)
 * @returns {Uint8Array} LE bytes for Rust tree
 */
function hexToBytesForTree(hex) {
    const beBytes = hexToBytes(hex);
    return beBytes.reverse();
}

// ASP Membership tree depth - must match the contract deployment
// The current testnet deployment uses depth 5 (32 leaves max)
const ASP_MEMBERSHIP_TREE_DEPTH = 5;

// Zero leaf value used by the contract: poseidon2("XLM") - must match contract's get_zeroes()[0]
const ZERO_LEAF_HEX = '0x25302288db99350344974183ce310d63b53abb9ef0f8575753eed36e0118f9ce';

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
    // Initialize tree with contract's zero leaf value (poseidon2("XLM"))
    const zeroLeaf = hexToBytesForTree(ZERO_LEAF_HEX);
    merkleTree = createMerkleTreeWithZeroLeaf(ASP_MEMBERSHIP_TREE_DEPTH, zeroLeaf);
    
    // Use cursor to iterate leaves in index order without loading all into memory
    let leafCount = 0;
    let expectedIndex = 0;
    
    await db.iterate('asp_membership_leaves', (leaf) => {
        if (leaf.index !== expectedIndex) {
            console.error(`[ASPMembershipStore] Gap in leaf indices: expected ${expectedIndex}, got ${leaf.index}`);
            throw new Error('[ASPMembershipStore] Gap in leaf indices, aborting init');
        }
        
        const leafBytes = hexToBytesForTree(leaf.leaf);
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
        const nextIdx = Number(merkleTree.next_index);
        if (index !== nextIdx) {
            throw new Error(`Out-of-order insertion: expected ${nextIdx}, got ${index}`);
        }
        
        const leafBytes = hexToBytesForTree(leaf);
        merkleTree.insert(leafBytes);
        
        // Verify root matches contract
        // Tree returns LE bytes, contract root is BE hex - reverse for comparison
        const rootBytesLE = merkleTree.root();
        const rootBytesBE = Uint8Array.from(rootBytesLE).reverse();
        const computedRoot = bytesToHex(rootBytesBE);
        if (computedRoot !== root) {
            console.error(`[ASPMembershipStore] Root mismatch at index ${index}`);
            console.error(`  Contract: ${root}`);
            console.error(`  Local:    ${computedRoot}`);
        }
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
    
    for (const event of events) {
        const eventType = event.topic?.[0];
        console.log('[ASPMembershipStore] Event topic:', eventType, 'full topics:', event.topic);
        
        // Event topic is ["LeafAdded"] with value containing leaf, index, root
        if (eventType === 'LeafAdded' || eventType === 'leaf_added') {
            console.log('[ASPMembershipStore] Processing LeafAdded:', {
                leaf: event.value?.leaf,
                index: event.value?.index,
                root: event.value?.root,
            });
            await processLeafAdded({
                leaf: event.value?.leaf,
                index: event.value?.index,
                root: event.value?.root,
            }, event.ledger || ledger);
            count++;
        } else {
            console.log('[ASPMembershipStore] Skipped event with topic:', eventType);
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
 * Uses the live tree which is initialized with the correct zero leaf value.
 * @param {number} leafIndex - Index of the leaf
 * @returns {Object|null} Merkle proof with path_elements, path_indices, root
 */
export function getMerkleProof(leafIndex) {
    try {
        if (!merkleTree) {
            console.warn('[ASPMembershipStore] Merkle tree not initialized');
            return null;
        }
        
        const maxIndex = Number(merkleTree.next_index);
        console.log(`[ASPMembershipStore] getMerkleProof: tree has ${maxIndex} leaves, requesting index ${leafIndex}`);
        
        if (leafIndex >= maxIndex) {
            console.error(`[ASPMembershipStore] Leaf index ${leafIndex} out of range (max: ${maxIndex - 1})`);
            return null;
        }
        
        const proof = merkleTree.get_proof(leafIndex);
        
        console.log(`[ASPMembershipStore] Built proof for index ${leafIndex}`);
        console.log(`[ASPMembershipStore] Tree root: ${bytesToHex(merkleTree.root())}`);
        
        return proof;
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
    return merkleTree.next_index;
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
    const zeroLeaf = hexToBytesForTree(ZERO_LEAF_HEX);
    merkleTree = createMerkleTreeWithZeroLeaf(ASP_MEMBERSHIP_TREE_DEPTH, zeroLeaf);
    console.log('[ASPMembershipStore] Cleared all data');
}

export { ASP_MEMBERSHIP_TREE_DEPTH };
