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
import * as publicKeyStore from './public-key-store.js';
import { 
    computeCommitment, 
    computeNullifier, 
    computeSignature,
    decryptNoteData,
    bigintToField,
    fieldToHex,
    hexToField,
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
 * Encryption scheme: X25519-XSalsa20-Poly1305
 * Format: [ephemeralPubKey (32)] [nonce (24)] [ciphertext (40) + tag (16)]
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
        
        // Get user's encryption keypair (derived from Freighter signature)
        const encKeypair = await notesStore.getUserEncryptionKeypair();
        if (!encKeypair) {
            console.warn('[NoteScanner] No encryption keypair available - user must sign message');
            return null;
        }
        
        // Attempt decryption
        const decrypted = decryptNoteData(encKeypair.privateKey, encrypted);
        
        return decrypted; // { amount, blinding } or null if not for us
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
 * We use our note public key (derived from Freighter signature via Poseidon2)
 * to verify that this commitment was indeed addressed to us.
 * 
 * @param {DecryptedNote} decrypted - Decrypted note data { amount, blinding }
 * @param {Uint8Array} notePublicKey - User's note public key
 * @param {string} expectedCommitment - On-chain commitment hash
 * @returns {boolean} True if commitment matches
 */
export function verifyNoteCommitment(decrypted, notePublicKey, expectedCommitment) {
    try {
        // Compute commitment: Poseidon2(amount, publicKey, blinding, domain=0x01)
        const amountBytes = bigintToField(decrypted.amount);
        
        if (amountBytes.length !== 32) {
            console.warn(`[NoteScanner] Amount bytes wrong length: ${amountBytes.length}, amount: ${decrypted.amount}`);
            return false;
        }
        if (notePublicKey.length !== 32) {
            console.warn(`[NoteScanner] Note public key wrong length: ${notePublicKey.length}`);
            return false;
        }
        if (decrypted.blinding.length !== 32) {
            console.warn(`[NoteScanner] Blinding wrong length: ${decrypted.blinding.length}`);
            return false;
        }
        
        const expectedNorm = normalizeHex(expectedCommitment).toLowerCase();
        
        // computeCommitment returns LE bytes, use fieldToHex to convert to BE hex for comparison
        const computed = computeCommitment(amountBytes, notePublicKey, decrypted.blinding);
        const computedHex = fieldToHex(computed);
        const computedNorm = normalizeHex(computedHex).toLowerCase();
        
        if (computedNorm === expectedNorm) {
            return true;
        }
        
        console.log(`[NoteScanner] Commitment mismatch:`, {
            computed: computedHex,
            expected: expectedCommitment,
        });
        return false;
    } catch (e) {
        console.error('[NoteScanner] Commitment verification failed:', e?.message || e?.toString() || e);
        return false;
    }
}

/**
 * Scans encrypted outputs to find notes belonging to the user.
 * 
 * This function uses the user's deterministic keypairs (derived from Freighter signatures):
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
    
    // Get user's note identity keypair (required for verification and storage)
    const noteKeypair = await notesStore.getUserNoteKeypair();
    if (!noteKeypair) {
        console.error('[NoteScanner] Cannot scan without note keypair');
        return { scanned: 0, found: 0, notes: [], alreadyKnown: 0 };
    }
    
    const derivedPubKeyHex = fieldToHex(noteKeypair.publicKey);
    console.log('[NoteScanner] Using note keypair:', { pubKeyHex: derivedPubKeyHex });
    
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
        
        // Skip if we already have this note (case-insensitive comparison via normalizeHex)
        // Notes created locally are saved before scanning, so they'll be found here and skipped
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
        // Skip dummy 0-value notes
        if (decrypted.amount === 0n || decrypted.amount === 0) {
            console.log('[NoteScanner] Skipping 0-value dummy note');
            continue;
        }
        
        // Verify the commitment matches using our note public key
        const isValidCommitment = verifyNoteCommitment(decrypted, noteKeypair.publicKey, output.commitment);
        if (!isValidCommitment) {
            console.warn('[NoteScanner] Decryption succeeded but commitment mismatch - ignoring');
            continue;
        }
        
        // Double-check we don't already have this note (handles potential race conditions)
        const doubleCheck = await notesStore.getNoteByCommitment(output.commitment);
        if (doubleCheck) {
            result.alreadyKnown++;
            console.log(`[NoteScanner] Note ${output.commitment.slice(0, 10)}... already exists (race condition avoided)`);
            continue;
        }
        
        // Save the discovered note with our note private key.
        // Mark as received since it wasn't in our local store before scanning.
        // Notes we created locally are saved immediately, so they won't reach here.
        const note = await notesStore.saveNote({
            commitment: output.commitment,
            privateKey: noteKeypair.privateKey,
            blinding: fieldToHex(decrypted.blinding),
            amount: decrypted.amount,
            leafIndex: output.index,
            ledger: output.ledger,
            isReceived: true,
        });
        
        result.notes.push(note);
        result.found++;
        
        console.log(`[NoteScanner] Discovered received note ${output.commitment.slice(0, 10)}... at index ${output.index}`);
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
    
    const nullifierCount = await db.count('pool_nullifiers');
    console.log(`[NoteScanner] Checking ${unspentNotes.length} unspent notes against ${nullifierCount} synced nullifiers`);
    
    let markedSpent = 0;
    let skipped = 0;
    
    for (const note of unspentNotes) {
        try {
            if (!note.privateKey || note.privateKey === '0x' || note.privateKey.length < 66) {
                console.warn(`[NoteScanner] Skipping note ${note.id?.slice(0, 10)}... - invalid privateKey`);
                skipped++;
                continue;
            }
            
            // Convert from BE hex to LE bytes (field format)
            const privateKeyBytes = hexToField(note.privateKey);
            const commitmentBytes = hexToField(note.id);
            
            if (privateKeyBytes.length !== 32 || commitmentBytes.length !== 32) {
                console.warn(`[NoteScanner] Skipping note ${note.id?.slice(0, 10)}... - invalid length`);
                skipped++;
                continue;
            }
            
            const nullifier = deriveNullifierForNote(privateKeyBytes, commitmentBytes, note.leafIndex);
            const nullifierHex = bytesToHex(nullifier);
            const isSpent = await poolStore.isNullifierSpent(nullifierHex);
            
            if (isSpent) {
                const nullifierRecord = await db.get('pool_nullifiers', normalizeHex(nullifierHex));
                const spentLedger = nullifierRecord?.ledger || 0;
                
                await notesStore.markNoteSpent(note.id, spentLedger);
                markedSpent++;
                
                console.log(`[NoteScanner] Note ${note.id.slice(0, 10)}... marked as spent`);
                emit('noteSpent', { commitment: note.id, ledger: spentLedger });
            }
        } catch (e) {
            console.error('[NoteScanner] Error checking note spent status:', e?.message || e?.toString() || e);
        }
    }
    
    console.log(`[NoteScanner] Checked ${unspentNotes.length} notes: ${markedSpent} marked spent, ${skipped} skipped`);
    
    return { checked: unspentNotes.length, markedSpent };
}

/**
 * Derives the nullifier for a note.
 * Nullifier = hash(commitment, pathIndices, signature)
 * 
 * The path indices are encoded as a single field element: sum(bit[i] * 2^i)
 * where bit[i] = (leafIndex >> i) & 1
 * 
 * @param {Uint8Array} privateKey - Note's private key
 * @param {Uint8Array} commitment - Note commitment
 * @param {number} leafIndex - Leaf index in merkle tree
 * @returns {Uint8Array} Nullifier hash
 */
export function deriveNullifierForNote(privateKey, commitment, leafIndex) {
    // Path indices is the leaf index itself (it encodes the path through the tree)
    // Convert to 32-byte field element
    const pathIndicesBytes = bigintToField(BigInt(leafIndex));
    
    // Compute signature = hash(privateKey, commitment, pathIndices)
    const signature = computeSignature(privateKey, commitment, pathIndicesBytes);
    
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
