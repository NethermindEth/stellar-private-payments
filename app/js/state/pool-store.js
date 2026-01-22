/**
 * Pool Store - manages local pool state including merkle tree, nullifiers, and commitments.
 * Syncs from Pool contract events (NewCommitment, NewNullifier).
 * 
 * Init uses cursor iteration to avoid memory issues with large datasets.
 * TODO: Move this to web worker later.
 * 
 * @module state/pool-store
 */

import * as db from './db.js';
import { createMerkleTreeWithZeroLeaf } from '../bridge.js';
import { hexToBytes, bytesToHex, normalizeU256ToHex, normalizeHex } from './utils.js';

/**
 * Converts hex string to bytes for Merkle tree insertion.
 * 
 * The Rust Merkle tree uses zkhash which interprets bytes via from_le_bytes_mod_order (LE).
 * The Soroban contract stores U256 as BE and converts to Scalar via BigUint::from_bytes_be.
 * 
 * To get matching numeric values:
 * - Contract: U256 (BE bytes) → BigUint::from_bytes_be → Scalar
 * - Our code: Hex → BE bytes → reverse to LE → from_le_bytes_mod_order → Scalar
 * 
 * By reversing BE to LE before calling from_le_bytes_mod_order, we get the same
 * numeric value as the contract.
 * 
 * @param {string} hex - Hex string (BE representation of U256)
 * @returns {Uint8Array} LE bytes for Rust tree insertion
 */
function hexToBytesForTree(hex) {
    const beBytes = hexToBytes(hex);
    // Reverse BE to LE for Rust's from_le_bytes_mod_order
    return beBytes.reverse();
}

// Pool tree depth - must match the circuit and contract deployment
// The current testnet deployment uses depth 5 (32 leaves max)
const POOL_TREE_DEPTH = 5;

// Zero leaf value used by the contract: poseidon2("XLM") - must match contract's get_zeroes()[0]
const ZERO_LEAF_HEX = '0x25302288db99350344974183ce310d63b53abb9ef0f8575753eed36e0118f9ce';

let merkleTree = null;

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
 * Initializes the pool store and merkle tree.
 * Uses cursor-based iteration to avoid loading entire table into memory.
 * @returns {Promise<void>}
 */
export async function init() {
    await rebuildTree();
}

/**
 * Rebuilds the merkle tree from the database.
 * Call this after sync to ensure tree is up-to-date with stored leaves.
 * @returns {Promise<number>} Number of leaves in the rebuilt tree
 */
export async function rebuildTree() {
    // Initialize tree with contract's zero leaf value (poseidon2("XLM"))
    const zeroLeaf = hexToBytesForTree(ZERO_LEAF_HEX);
    merkleTree = createMerkleTreeWithZeroLeaf(POOL_TREE_DEPTH, zeroLeaf);
    
    // Use cursor to iterate leaves in index order without loading all into memory
    let leafCount = 0;
    let expectedIndex = 0;
    
    await db.iterate('pool_leaves', (leaf) => {
        // Verify sequential ordering (merkle tree requires ordered insertion)
        if (leaf.index !== expectedIndex) {
            console.warn(`[PoolStore] Gap in leaf indices: expected ${expectedIndex}, got ${leaf.index}`);
        }
        
        const commitmentBytes = hexToBytesForTree(leaf.commitment);
        merkleTree.insert(commitmentBytes);
        leafCount++;
        expectedIndex = leaf.index + 1;
    }, { direction: 'next' }); // 'next' ensures ascending order by keyPath (index)
    
    return leafCount;
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
    // Ensure index is a Number (events may have BigInt or Number)
    const index = typeof event.index === 'bigint' ? Number(event.index) : Number(event.index);
    const encryptedOutput = event.encryptedOutput;
    
    // Store leaf
    await db.put('pool_leaves', {
        index,
        commitment,
        ledger,
    });
    
    // Store encrypted output for note detection
    await db.put('pool_encrypted_outputs', {
        commitment,
        index,
        encryptedOutput: typeof encryptedOutput === 'string' 
            ? encryptedOutput 
            : bytesToHex(encryptedOutput),
        ledger,
    });
    
    // Update merkle tree
    if (merkleTree) {
        const commitmentBytes = hexToBytesForTree(commitment);
        merkleTree.insert(commitmentBytes);
    }
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
    
    await db.put('pool_nullifiers', {
        nullifier,
        ledger,
    });
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
        
        // Match various event name formats (Soroban converts struct names to snake_case symbols)
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
export async function getMerkleProof(leafIndex) {
    try {
        if (!merkleTree) {
            console.warn('[PoolStore] Merkle tree not initialized');
            return null;
        }
        
        const maxIndex = Number(merkleTree.next_index);
        console.log(`[PoolStore] getMerkleProof: tree has ${maxIndex} leaves, requesting index ${leafIndex}`);
        
        if (leafIndex >= maxIndex) {
            console.error(`[PoolStore] Leaf index ${leafIndex} out of range (max: ${maxIndex - 1})`);
            return null;
        }
        
        const proof = merkleTree.get_proof(leafIndex);
        
        // Tree returns LE bytes, convert to BE hex for logging
        const rootBytesLE = merkleTree.root();
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
    const result = await db.get('pool_nullifiers', hex);
    return result !== undefined;
}

/**
 * Gets all encrypted outputs for potential note detection.
 * @param {number} [fromLedger] - Only get outputs from this ledger onwards
 * @returns {Promise<PoolEncryptedOutput[]>}
 */
export async function getEncryptedOutputs(fromLedger) {
    const outputs = await db.getAll('pool_encrypted_outputs');
    
    if (fromLedger === undefined) {
        return outputs;
    }
    
    return outputs.filter(o => o.ledger >= fromLedger);
}

/**
 * Gets the total number of leaves in the pool.
 * @returns {Promise<number>}
 */
export async function getLeafCount() {
    return db.count('pool_leaves');
}

/**
 * Gets the next leaf index (same as leaf count).
 * @returns {number}
 */
export function getNextIndex() {
    if (!merkleTree) return 0;
    return merkleTree.next_index;
}

/**
 * Clears all pool data (for resync).
 * @returns {Promise<void>}
 */
export async function clear() {
    await db.clear('pool_leaves');
    await db.clear('pool_nullifiers');
    await db.clear('pool_encrypted_outputs');
    const zeroLeaf = hexToBytesForTree(ZERO_LEAF_HEX);
    merkleTree = createMerkleTreeWithZeroLeaf(POOL_TREE_DEPTH, zeroLeaf);
    console.log('[PoolStore] Cleared all data');
}

export { POOL_TREE_DEPTH };
