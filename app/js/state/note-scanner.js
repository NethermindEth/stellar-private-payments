/**
 * Note Scanner - discovers notes addressed to the user by scanning encrypted outputs.
 * 
 * When someone sends a private transfer:
 * 1. They encrypt (amount, blinding) with the recipient's X25519 encryption public key
 * 2. The encrypted output is emitted as an event on-chain
 * 3. The recipient scans all outputs, trying to decrypt each one
 * 4. Successful decryption means the note is addressed to them
 * 5. They verify the commitment matches and save the note
 * 
 * This module uses the deterministic keys from notes-store.js:
 * - Encryption keypair: For decrypting note data
 * - Note identity keypair: For verifying commitments and deriving nullifiers
 * 
 * @module state/note-scanner
 */

import * as db from './db.js';
import * as notesStore from './notes-store.js';
import * as poolStore from './pool-store.js';
import { 
    computeCommitment, 
    computeNullifier, 
    computeSignature,
    decryptNoteData,
    bigintToLittleEndian,
} from '../bridge.js';
import { hexToBytes, bytesToHex, normalizeHex } from './utils.js';

/**
 * @typedef {Object} ScanResult
 * @property {number} scanned - Total outputs scanned
 * @property {number} found - Notes found belonging to user
 * @property {Array<Object>} notes - Discovered notes
 * @property {number} alreadyKnown - Notes already in store
 */

/**
 * @typedef {Object} DecryptedNote
 * @property {bigint} amount - Note amount
 * @property {Uint8Array} blinding - Blinding factor (32 bytes)
 * @property {Uint8Array} [recipientPubKey] - Recipient public key if included
 */

/**
 * Scanning state for tracking progress.
 */
let lastScannedLedger = 0;
let scanListeners = [];

/**
 * Tries to decrypt an encrypted output using the user's X25519 encryption private key.
 * 
 * The encryption private key is derived deterministically from a Freighter signature,
 * so this will work on any device where the user has their wallet.
 * 
 * Encryption scheme: X25519-XSalsa20-Poly1305. Format: [ephemeralPubKey (32)] [nonce (24)] [ciphertext (40) + tag (16)]
 * 
 * @param {string|Uint8Array} encryptedOutput - Encrypted output data from on-chain event
 * @returns {Promise<DecryptedNote|null>} Decrypted note data or null if not addressed to us
 */
export async function tryDecryptNote(encryptedOutput) {
    try {
        const encrypted = typeof encryptedOutput === 'string' 
            ? hexToBytes(encryptedOutput) 
            : encryptedOutput;
        
        // Minimum size: ephemeral_pubkey (32) + nonce (24) + ciphertext (40) + tag (16) = 112
        if (encrypted.length < 112) {
            return null;
        }
        
        // Get user's encryption keypair
        const encKeypair = await notesStore.getUserEncryptionKeypair();
        if (!encKeypair) {
            console.warn('[NoteScanner] No encryption keypair available - user must sign message');
            return null;
        }
        
        // Attempt decryption
        const decrypted = decryptNoteData(encKeypair.privateKey, encrypted);
        
        return decrypted; // { amount, blinding }
    } catch (e) {
        // Decryption failed - this output is not addressed to us
        return null;
    }
}

/**
 * Verifies that a decrypted note matches the on-chain commitment.
 * 
 * The commitment is: Poseidon2(amount, notePublicKey, blinding, domain=0x01)
 * 
 * We use our note public key to verify that this commitment was indeed addressed to us.
 * 
 * @param {DecryptedNote} decrypted - Decrypted note data { amount, blinding }
 * @param {Uint8Array} notePublicKey - User's note public key
 * @param {string} expectedCommitment - On-chain commitment hash
 * @returns {boolean} True if commitment matches
 */
export function verifyNoteCommitment(decrypted, notePublicKey, expectedCommitment) {
    try {
        // Compute commitment: Poseidon2(amount, publicKey, blinding, domain=0x01)
        const amountBytes = bigintToLittleEndian(decrypted.amount, 8);
        const computed = computeCommitment(amountBytes, notePublicKey, decrypted.blinding);
        const computedHex = bytesToHex(computed);
        
        return normalizeHex(computedHex) === normalizeHex(expectedCommitment);
    } catch (e) {
        console.error('[NoteScanner] Commitment verification failed:', e);
        return false;
    }
}

/**
 * Scans encrypted outputs to find notes belonging to the user.
 * 
 * This function uses the user's deterministic keypairs:
 * 1. Encryption keypair: To decrypt note data
 * 2. Note identity keypair: To verify commitments and store the note
 * 
 * @param {Object} [options] - Scan options
 * @param {number} [options.fromLedger] - Start scanning from this ledger
 * @param {boolean} [options.fullRescan] - Ignore lastScannedLedger, scan everything
 * @param {function} [options.onProgress] - Progress callback (scanned, total)
 * @returns {Promise<ScanResult>}
 */
export async function scanForNotes(options = {}) {
    const { fromLedger, fullRescan = false, onProgress } = options;
    
    // Get user's note identity keypair
    const noteKeypair = await notesStore.getUserNoteKeypair();
    if (!noteKeypair) {
        console.error('[NoteScanner] Cannot scan without note keypair');
        return { scanned: 0, found: 0, notes: [], alreadyKnown: 0 };
    }
    
    // Determine start ledger
    const startLedger = fullRescan ? 0 : (fromLedger ?? lastScannedLedger);
    
    // Get encrypted outputs from pool
    const outputs = await poolStore.getEncryptedOutputs(startLedger > 0 ? startLedger : undefined);
    
    const result = {
        scanned: 0,
        found: 0,
        notes: [],
        alreadyKnown: 0,
    };
    
    for (let i = 0; i < outputs.length; i++) {
        const output = outputs[i];
        result.scanned++;
        
        if (onProgress && i % 100 === 0) {
            onProgress(i, outputs.length);
        }
        
        // Skip if we already have this note
        const existing = await notesStore.getNoteByCommitment(output.commitment);
        if (existing) {
            result.alreadyKnown++;
            continue;
        }
        
        // Try to decrypt using our encryption private key
        const decrypted = await tryDecryptNote(output.encryptedOutput);
        if (!decrypted) {
            continue; // Not addressed to us
        }
        
        // Verify the commitment matches using our note public key
        if (!verifyNoteCommitment(decrypted, noteKeypair.publicKey, output.commitment)) {
            console.warn('[NoteScanner] Decryption succeeded but commitment mismatch - ignoring');
            continue;
        }
        
        // Save the discovered note with our note private key
        // The private key is deterministic, so we store it for convenience
        const note = await notesStore.saveNote({
            commitment: output.commitment,
            privateKey: noteKeypair.privateKey,
            blinding: decrypted.blinding,
            amount: decrypted.amount,
            leafIndex: output.index,
            ledger: output.ledger,
        });
        
        result.notes.push(note);
        result.found++;
        
        emit('noteDiscovered', note);
    }
    
    // Update last scanned ledger
    if (outputs.length > 0) {
        lastScannedLedger = Math.max(lastScannedLedger, ...outputs.map(o => o.ledger));
    }
    
    if (onProgress) {
        onProgress(outputs.length, outputs.length);
    }
    
    console.log(`[NoteScanner] Scanned ${result.scanned} outputs, found ${result.found} new notes`);
    
    return result;
}

/**
 * Checks if any user notes have been spent by matching nullifiers.
 * Call this after syncing new nullifiers from the pool.
 * 
 * The note's privateKey is stored with each note, so we don't need
 * to re-derive it from Freighter for this operation.
 * 
 * @returns {Promise<{checked: number, markedSpent: number}>}
 */
export async function checkSpentNotes() {
    const unspentNotes = await notesStore.getUnspentNotes();
    
    let markedSpent = 0;
    
    for (const note of unspentNotes) {
        try {
            // Derive nullifier for this note using its stored private key
            const nullifier = deriveNullifierForNote(
                hexToBytes(note.privateKey),
                hexToBytes(note.id), // commitment
                note.leafIndex
            );
            
            const nullifierHex = bytesToHex(nullifier);
            
            // Check if this nullifier exists on-chain
            const isSpent = await poolStore.isNullifierSpent(nullifierHex);
            
            if (isSpent) {
                // Get the ledger when it was spent
                const nullifierRecord = await db.get('pool_nullifiers', normalizeHex(nullifierHex));
                const spentLedger = nullifierRecord?.ledger || 0;
                
                await notesStore.markNoteSpent(note.id, spentLedger);
                markedSpent++;
                
                emit('noteSpent', { commitment: note.id, ledger: spentLedger });
            }
        } catch (e) {
            console.error('[NoteScanner] Error checking note spent status:', e);
        }
    }
    
    console.log(`[NoteScanner] Checked ${unspentNotes.length} notes, marked ${markedSpent} as spent`);
    
    return { checked: unspentNotes.length, markedSpent };
}

/**
 * Derives the nullifier for a note.
 * Nullifier = hash(commitment, pathIndices, signature)
 * 
 * @param {Uint8Array} privateKey - Note's private key
 * @param {Uint8Array} commitment - Note commitment
 * @param {number} leafIndex - Leaf index in merkle tree
 * @returns {Uint8Array} Nullifier hash
 */
export function deriveNullifierForNote(privateKey, commitment, leafIndex) {
    // Path indices are the binary representation of leafIndex
    // Notes are in the pool tree, which has depth 20
    const treeDepth = 20; // Match POOL_TREE_DEPTH
    const pathIndices = [];
    let idx = leafIndex;
    for (let i = 0; i < treeDepth; i++) {
        pathIndices.push(idx & 1);
        idx = idx >> 1;
    }
    
    // Compute signature = hash(privateKey, commitment, pathIndices[0])
    const signature = computeSignature(privateKey, commitment, pathIndices[0]);
    
    // Convert pathIndices to field elements for nullifier computation
    // pathIndices is encoded as a single number: sum(pathIndices[i] * 2^i)
    let pathIndicesValue = 0n;
    for (let i = 0; i < pathIndices.length; i++) {
        if (pathIndices[i]) {
            pathIndicesValue |= (1n << BigInt(i));
        }
    }
    
    const pathIndicesBytes = bigintToLittleEndian(pathIndicesValue, 32);
    
    // Nullifier = hash(commitment, pathIndices, signature)
    return computeNullifier(commitment, pathIndicesBytes, signature);
}

/**
 * Gets the last scanned ledger sequence.
 * @returns {number}
 */
export function getLastScannedLedger() {
    return lastScannedLedger;
}

/**
 * Sets the last scanned ledger (for resuming scans).
 * @param {number} ledger
 */
export function setLastScannedLedger(ledger) {
    lastScannedLedger = ledger;
}

/**
 * Adds an event listener.
 * Events: noteDiscovered, noteSpent
 * @param {string} event
 * @param {function} handler
 */
export function on(event, handler) {
    scanListeners.push({ event, handler });
}

/**
 * Removes an event listener.
 * @param {string} event
 * @param {function} handler
 */
export function off(event, handler) {
    scanListeners = scanListeners.filter(
        l => !(l.event === event && l.handler === handler)
    );
}

/**
 * Emits an event to listeners.
 * @param {string} event
 * @param {any} data
 */
function emit(event, data) {
    for (const listener of scanListeners) {
        if (listener.event === event) {
            try {
                listener.handler(data);
            } catch (e) {
                console.error(`[NoteScanner] Event handler error (${event}):`, e);
            }
        }
    }
}
