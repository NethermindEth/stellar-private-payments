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
import { createMerkleTree } from '../bridge.js';
import { hexToBytes, bytesToHex, normalizeU256ToHex, normalizeHex, reverseBytes } from './utils.js';

const POOL_TREE_DEPTH = 20;

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
    merkleTree = createMerkleTree(POOL_TREE_DEPTH);

    // Use cursor to iterate leaves in index order without loading all into memory
    let leafCount = 0;
    let expectedIndex = 0;

    await db.iterate('pool_leaves', (leaf) => {
        // Verify sequential ordering (merkle tree requires ordered insertion)
        if (leaf.index !== expectedIndex) {
            console.warn(`[PoolStore] Gap in leaf indices: expected ${expectedIndex}, got ${leaf.index}`);
        }

        const commitmentBytes = hexToBytes(leaf.commitment);
        // Reverse bytes: DB has BE hex (from Soroban), but Merkle Tree (Arkworks) needs LE bytes
        merkleTree.insert(reverseBytes(commitmentBytes));
        leafCount++;
        expectedIndex = leaf.index + 1;
    }, { direction: 'next' }); // 'next' ensures ascending order by keyPath (index)

    console.log(`[PoolStore] Initialized with ${leafCount} leaves`);
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
    const index = event.index;
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
        const commitmentBytes = hexToBytes(commitment);
        // Reverse bytes: Event sends BE hex, Merkle Tree needs LE bytes
        merkleTree.insert(reverseBytes(commitmentBytes));
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

        if (eventType === 'NewCommitmentEvent' || eventType === 'new_commitment') {
            await processNewCommitment({
                commitment: event.value?.commitment || event.topic?.[1],
                index: event.value?.index,
                encryptedOutput: event.value?.encrypted_output || event.value?.encryptedOutput,
            }, event.ledger || ledger);
            commitments++;
        } else if (eventType === 'NewNullifierEvent' || eventType === 'new_nullifier') {
            await processNewNullifier({
                nullifier: event.value?.nullifier || event.topic?.[1],
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
 * @param {number} leafIndex - Index of the leaf
 * @returns {Object|null} Merkle proof with siblings and path indices
 */
export function getMerkleProof(leafIndex) {
    if (!merkleTree) return null;
    try {
        return merkleTree.proof(leafIndex);
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
    return merkleTree.next_index();
}

/**
 * Clears all pool data (for resync).
 * @returns {Promise<void>}
 */
export async function clear() {
    await db.clear('pool_leaves');
    await db.clear('pool_nullifiers');
    await db.clear('pool_encrypted_outputs');
    merkleTree = createMerkleTree(POOL_TREE_DEPTH);
    console.log('[PoolStore] Cleared all data');
}

export { POOL_TREE_DEPTH };
