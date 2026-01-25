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
import { 
    bytesToHex,
    hexToBytes,
    normalizeU256ToHex, 
    hexToBytesForTree,
    ZERO_LEAF_HEX,
    TREE_DEPTH,
} from './utils.js';

// Alias for backwards compatibility
const ASP_MEMBERSHIP_TREE_DEPTH = TREE_DEPTH;

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
    console.log(`[ASPMembershipStore] Initializing with ZERO_LEAF_HEX: ${ZERO_LEAF_HEX}`);
    const zeroLeafLE = hexToBytesForTree(ZERO_LEAF_HEX);
    
    merkleTree = createMerkleTreeWithZeroLeaf(ASP_MEMBERSHIP_TREE_DEPTH, zeroLeafLE);
    
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
    
    // Debug: log the raw event values
    console.log(`[ASPMembershipStore] processLeafAdded raw:`, {
        leafBigint: typeof event.leaf === 'bigint' ? event.leaf.toString(16) : event.leaf,
        rootBigint: typeof event.root === 'bigint' ? event.root.toString(16) : event.root,
        leafNormalized: leaf,
        rootNormalized: root,
    });
    
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
        console.log(`[ASPMembershipStore] Inserting leaf bytes (LE for tree):`, bytesToHex(leafBytes));
        
        merkleTree.insert(leafBytes);
        
        // Verify root matches contract
        // Tree returns LE bytes, contract root is BE hex
        const rootBytesLE = merkleTree.root();
        console.log(`[ASPMembershipStore] Tree root bytes (LE):`, bytesToHex(rootBytesLE));
        
        // Try both BE and LE comparison
        const rootBytesBE = Uint8Array.from(rootBytesLE).reverse();
        const computedRootBE = bytesToHex(rootBytesBE);
        const computedRootLE = bytesToHex(rootBytesLE);
        
        console.log(`[ASPMembershipStore] Root comparison at index ${index}:`);
        console.log(`  Contract (expected): ${root}`);
        console.log(`  Local (as BE):       ${computedRootBE}`);
        console.log(`  Local (as LE):       ${computedRootLE}`);
        
        if (computedRootBE !== root && computedRootLE !== root) {
            console.error(`[ASPMembershipStore] Root mismatch! Neither endianness matches.`);
        } else if (computedRootLE === root) {
            console.log(`[ASPMembershipStore] Root matches with LE interpretation`);
        } else {
            console.log(`[ASPMembershipStore] Root matches with BE interpretation`);
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
    
    if (events.length === 0) {
        console.log('[ASPMembershipStore] No events to process');
        return count;
    }
    
    console.log(`[ASPMembershipStore] Processing ${events.length} events...`);
    
    // Debug: log all event topics to see what we're getting
    console.log('[ASPMembershipStore] Event topics received:', 
        events.map(e => ({ topic: e.topic, topicType: typeof e.topic?.[0], value: e.value })));
    
    // Filter and sort LeafAdded events by index
    // Topic might be 'LeafAdded', 'leaf_added', or contain it as a substring
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
    const nextIdx = merkleTree ? Number(merkleTree.next_index) : 0;
    
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
