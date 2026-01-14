/**
 * Notes Store - manages user notes (UTXOs) with secret management.
 * Notes contain private keys and blindings needed to spend them.
 * @module state/notes-store
 */

import * as db from './db.js';
import { toHex, normalizeHex } from './utils.js';

/**
 * @typedef {Object} UserNote
 * @property {string} id - Note ID (commitment hex)
 * @property {string} privateKey - Private key (hex)
 * @property {string} blinding - Blinding factor (hex)
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
 * @param {string} params.commitment - Commitment hash (hex)
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
 * @param {string} commitment - Note commitment (hex)
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
 * @param {string} commitment - Note commitment (hex)
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
 * Exports notes to an encrypted JSON blob.
 * Uses Web Crypto API for encryption with a password-derived key.
 * @param {string} password - Encryption password
 * @returns {Promise<Blob>}
 */
export async function exportNotes(password) {
    const notes = await db.getAll('user_notes');
    const data = JSON.stringify({
        version: 1,
        exportedAt: new Date().toISOString(),
        notes,
    });
    
    // Derive key from password
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        enc.encode(password),
        'PBKDF2',
        false,
        ['deriveBits', 'deriveKey']
    );
    
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt,
            iterations: 100000,
            hash: 'SHA-256',
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt']
    );
    
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        enc.encode(data)
    );
    
    // Combine salt + iv + ciphertext
    const result = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
    result.set(salt, 0);
    result.set(iv, salt.length);
    result.set(new Uint8Array(encrypted), salt.length + iv.length);
    
    return new Blob([result], { type: 'application/octet-stream' });
}

/**
 * Imports notes from an encrypted blob.
 * @param {File|Blob} file - Encrypted notes file
 * @param {string} password - Decryption password
 * @returns {Promise<number>} Number of notes imported
 */
export async function importNotes(file, password) {
    const arrayBuffer = await file.arrayBuffer();
    const data = new Uint8Array(arrayBuffer);
    
    // Extract salt, iv, ciphertext
    const salt = data.slice(0, 16);
    const iv = data.slice(16, 28);
    const ciphertext = data.slice(28);
    
    // Derive key from password
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        enc.encode(password),
        'PBKDF2',
        false,
        ['deriveBits', 'deriveKey']
    );
    
    const key = await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt,
            iterations: 100000,
            hash: 'SHA-256',
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
    );
    
    const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        ciphertext
    );
    
    const dec = new TextDecoder();
    const json = JSON.parse(dec.decode(decrypted));
    
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
        // If existing.spent && !note.spent: keep existing spent status (no action)
    }
    
    console.log(`[NotesStore] Imported ${imported} notes`);
    return imported;
}

/**
 * Deletes a note from the store.
 * @param {string} commitment - Note commitment (hex)
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
