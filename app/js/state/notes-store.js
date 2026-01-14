/**
 * Notes Store - manages user notes (UTXOs) with secret management.
 * Notes contain private keys and blindings needed to spend them.
 * @module state/notes-store
 */

import * as db from './db.js';
import { toHex, normalizeHex } from './utils.js';

/**
 * @typedef {Object} UserNote
 * @property {string} id - Commitment hash 
 * @property {string} privateKey - Private key 
 * @property {string} blinding - Blinding factor
 * @property {string} amount - Amount as string (bigint)
 * @property {number} leafIndex - Index in the pool merkle tree
 * @property {string} createdAt - ISO timestamp
 * @property {number} createdAtLedger - Ledger when created
 * @property {boolean} spent - Whether the note has been spent
 * @property {number} [spentAtLedger] - Ledger when spent
 */

/**
 * Saves a new note to the store.
 * @param {Object} params - Note parameters
 * @param {string} params.commitment - Commitment hash
 * @param {Uint8Array|string} params.privateKey - Private key
 * @param {Uint8Array|string} params.blinding - Blinding factor
 * @param {bigint|string|number} params.amount - Note amount
 * @param {number} params.leafIndex - Leaf index in pool tree
 * @param {number} params.ledger - Ledger when created
 * @returns {Promise<UserNote>}
 */
export async function saveNote(params) {
    const note = {
        id: normalizeHex(params.commitment),
        privateKey: toHex(params.privateKey),
        blinding: toHex(params.blinding),
        amount: String(params.amount),
        leafIndex: params.leafIndex,
        createdAt: new Date().toISOString(),
        createdAtLedger: params.ledger,
        spent: false,
    };
    
    await db.put('user_notes', note);
    console.log(`[NotesStore] Saved note ${note.id.slice(0, 10)}... at index ${note.leafIndex}`);
    return note;
}

/**
 * Marks a note as spent.
 * @param {string} commitment - Note commitment
 * @param {number} ledger - Ledger when spent
 * @returns {Promise<boolean>} True if note was found and marked
 */
export async function markNoteSpent(commitment, ledger) {
    const id = normalizeHex(commitment);
    const note = await db.get('user_notes', id);
    
    if (!note) {
        return false;
    }
    
    note.spent = true;
    note.spentAtLedger = ledger;
    await db.put('user_notes', note);
    
    console.log(`[NotesStore] Marked note ${id.slice(0, 10)}... as spent`);
    return true;
}

/**
 * Gets all user notes.
 * @param {Object} [options] - Filter options
 * @param {boolean} [options.unspentOnly] - Only return unspent notes
 * @returns {Promise<UserNote[]>}
 */
export async function getNotes(options = {}) {
    const notes = await db.getAll('user_notes');
    
    if (options.unspentOnly) {
        return notes.filter(n => !n.spent);
    }
    
    return notes;
}

/**
 * Gets a note by commitment.
 * @param {string} commitment - Note commitment
 * @returns {Promise<UserNote|null>}
 */
export async function getNoteByCommitment(commitment) {
    const id = normalizeHex(commitment);
    return await db.get('user_notes', id) || null;
}

/**
 * Gets unspent notes for transaction inputs.
 * @returns {Promise<UserNote[]>}
 */
export async function getUnspentNotes() {
    return getNotes({ unspentOnly: true });
}

/**
 * Gets total balance of unspent notes.
 * @returns {Promise<bigint>}
 */
export async function getBalance() {
    const unspent = await getUnspentNotes();
    return unspent.reduce((sum, note) => sum + BigInt(note.amount), 0n);
}

/**
 * Exports notes to a plain JSON blob.
 * @returns {Promise<Blob>}
 */
export async function exportNotes() {
    const notes = await db.getAll('user_notes');
    const data = JSON.stringify({
        version: 1,
        exportedAt: new Date().toISOString(),
        notes,
    }, null, 2);
    
    return new Blob([data], { type: 'application/json' });
}

/**
 * Imports notes from a JSON file.
 * @param {File|Blob} file - Notes JSON file
 * @returns {Promise<number>} Number of notes imported
 */
export async function importNotes(file) {
    const text = await file.text();
    const json = JSON.parse(text);
    
    if (json.version !== 1) {
        throw new Error(`Unsupported export version: ${json.version}`);
    }
    
    // Import notes: add new ones, update spent status if import shows spent
    let imported = 0;
    for (const note of json.notes) {
        const existing = await db.get('user_notes', note.id);
        if (!existing) {
            await db.put('user_notes', note);
            imported++;
        } else if (!existing.spent && note.spent) {
            existing.spent = true;
            existing.spentAtLedger = note.spentAtLedger;
            await db.put('user_notes', existing);
        }
    }
    
    console.log(`[NotesStore] Imported ${imported} notes`);
    return imported;
}

/**
 * Deletes a note from the store.
 * @param {string} commitment - Note commitment
 * @returns {Promise<void>}
 */
export async function deleteNote(commitment) {
    const id = normalizeHex(commitment);
    await db.del('user_notes', id);
}

/**
 * Clears all notes (use with caution).
 * @returns {Promise<void>}
 */
export async function clear() {
    await db.clear('user_notes');
    console.log('[NotesStore] Cleared all notes');
}
