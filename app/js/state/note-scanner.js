/**
 * Note Scanner - discovers notes addressed to the user by scanning encrypted outputs.
 *
 * @module state/note-scanner
 */

import { get as wasm } from './wasm.js';
import * as notesStore from './notes-store.js';
import { hexToBytes } from './utils.js';

/**
 * @typedef {Object} ScanResult
 * @property {number} scanned - Total outputs scanned
 * @property {number} found - Notes found belonging to user
 * @property {Array<Object>} notes - Discovered notes
 * @property {number} alreadyKnown - Notes already in store
 */

let lastScannedLedger = 0;
let scanListeners = [];

/**
 * Scans encrypted outputs to find notes belonging to the user.
 *
 * Uses the user's deterministic keypairs (derived from Freighter):
 * 1. Encryption keypair (X25519): To decrypt note data
 * 2. Note identity keypair (BN254): To verify commitments
 *
 * @param {Object} [options] - Scan options
 * @param {number} [options.fromLedger] - Start scanning from this ledger
 * @param {boolean} [options.fullRescan] - Scan everything from the start
 * @param {function} [options.onProgress] - Progress callback (scanned, total)
 * @returns {Promise<ScanResult>}
 */
export async function scanForNotes(options = {}) {
    const { fromLedger, fullRescan = false, onProgress } = options;

    // Get user's keypairs (derived from Freighter signatures, cached in memory)
    const encKeypair = await notesStore.getUserEncryptionKeypair();
    if (!encKeypair) {
        console.error('[NoteScanner] Cannot scan without encryption keypair');
        return { scanned: 0, found: 0, notes: [], alreadyKnown: 0 };
    }

    const noteKeypair = await notesStore.getUserNoteKeypair();
    if (!noteKeypair) {
        console.error('[NoteScanner] Cannot scan without note keypair');
        return { scanned: 0, found: 0, notes: [], alreadyKnown: 0 };
    }

    const owner = notesStore.getCurrentOwner() || '';
    const createdAt = new Date().toISOString();
    const startLedger = fullRescan ? null : (fromLedger ?? (lastScannedLedger > 0 ? lastScannedLedger : null));

    let result;
    try {
        const resultJson = wasm().scan_for_notes(
            encKeypair.privateKey,
            noteKeypair.privateKey,
            noteKeypair.publicKey,
            owner,
            createdAt,
            startLedger ?? undefined,
        );
        result = JSON.parse(resultJson);
    } catch (e) {
        console.error('[NoteScanner] WASM scan failed:', e);
        return { scanned: 0, found: 0, notes: [], alreadyKnown: 0 };
    }
    console.log(`[NoteScanner] Scanned ${result.scanned} outputs, found ${result.found} new notes`);

    // Emit events for discovered notes (fetch newly saved notes if any were found)
    const notes = [];
    if (result.found > 0) {
        // Retrieve newly saved notes to emit events
        const allNotes = JSON.parse(wasm().get_notes_by_owner(owner));
        const recentNotes = allNotes
            .filter(n => n.isReceived)
            .sort((a, b) => (b.createdAtLedger || 0) - (a.createdAtLedger || 0))
            .slice(0, result.found);

        for (const note of recentNotes) {
            notes.push(note);
            emit('noteDiscovered', note);
        }
    }

    // Update last scanned ledger based on current pool state
    const poolNextIndex = wasm().get_pool_next_index();
    if (poolNextIndex > 0) {
        // Use the current time as approximate last scanned marker
        lastScannedLedger = startLedger || lastScannedLedger;
    }

    if (onProgress) {
        onProgress(result.scanned, result.scanned);
    }

    return {
        scanned: result.scanned,
        found: result.found,
        notes,
        alreadyKnown: result.alreadyKnown,
    };
}

/**
 * Checks if any user notes have been spent and updates their status.
 * @returns {Promise<{checked: number, markedSpent: number}>}
 */
export async function checkSpentNotes() {
    const owner = notesStore.getCurrentOwner() || '';

    let result;
    try {
        const resultJson = wasm().check_spent_notes(owner);
        result = JSON.parse(resultJson);
    } catch (e) {
        console.error('[NoteScanner] WASM check_spent_notes failed:', e);
        return { checked: 0, markedSpent: 0 };
    }

    if (result.markedSpent > 0) {
        console.log(`[NoteScanner] ${result.markedSpent} notes marked as spent`);
        // Emit individual spent events
        // We don't have the specific commitment info from the batch check,
        // so we emit a summary event instead
        emit('noteSpent', { count: result.markedSpent });
    }

    console.log(`[NoteScanner] Checked ${result.checked} notes: ${result.markedSpent} marked spent`);
    return { checked: result.checked, markedSpent: result.markedSpent };
}

/**
 * Derives the nullifier for a note.
 * @param {Uint8Array} privateKey - Note's private key (LE bytes)
 * @param {Uint8Array} commitment - Note commitment (LE bytes)
 * @param {number} leafIndex - Leaf index in merkle tree
 * @returns {Uint8Array} Nullifier hash
 */
export function deriveNullifierForNote(privateKey, commitment, leafIndex) {
    try {
        const hexResult = wasm().derive_nullifier(privateKey, commitment, leafIndex);
        return hexToBytes(hexResult);
    } catch (e) {
        console.error('[NoteScanner] Failed to derive nullifier:', e);
        throw e;
    }
}

/**
 * Gets the last scanned ledger sequence.
 * @returns {number}
 */
export function getLastScannedLedger() {
    return lastScannedLedger;
}

/**
 * Sets the last scanned ledger.
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
