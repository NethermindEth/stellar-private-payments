/**
 * Notes Store - manages user notes (UTXOs) and cryptographic key management.
 *
 * This module handles two types of deterministically-derived keys:
 *
 * 1. **Encryption Keypair (X25519)**: For encrypting/decrypting note data.
 *    - Message: "Sign to access Privacy Pool [v1]"
 *    - Derived via SHA-256 from Freighter signature
 *
 * 2. **Note Identity Keypair (BN254/Poseidon2)**: For proving ownership in ZK circuits.
 *    - Message: "Privacy Pool Spending Key [v1]"
 *    - Private key derived via SHA-256 from Freighter signature
 *    - Public key derived via Poseidon2(privateKey, 0, domain=0x03)
 *
 * Both key types are recoverable using only the user's Freighter wallet.
 * Storage is delegated to the Rust WASM StateManager.
 *
 * @module state/notes-store
 */

import { get as wasm } from './wasm.js';
import { toHex, normalizeHex, bytesToHex } from './utils.js';
import { signWalletMessage } from '../wallet.js';
import {
    deriveEncryptionKeypairFromSignature,
    deriveNotePrivateKeyFromSignature,
    derivePublicKey,
} from '../bridge.js';

/**
 * @typedef {Object} UserNote
 * @property {string} id - Commitment hash
 * @property {string} owner - Stellar address that owns this note
 * @property {string} privateKey - Private key
 * @property {string} blinding - Blinding factor
 * @property {string} amount - Amount as string (bigint)
 * @property {number} leafIndex - Index in the pool merkle tree
 * @property {string} createdAt - ISO timestamp
 * @property {number} createdAtLedger - Ledger when created
 * @property {boolean} spent - Whether the note has been spent
 * @property {number} [spentAtLedger] - Ledger when spent
 * @property {boolean} [isReceived] - True if note was received via transfer
 */

// Current owner address for filtering notes
let currentOwner = null;

/**
 * Sets the current owner address for note filtering.
 * @param {string|null} address - Stellar address or null to clear
 */
export function setCurrentOwner(address) {
    const changed = currentOwner !== address;
    currentOwner = address;
    if (changed) {
        console.log(`[NotesStore] Owner changed to: ${address ? address.slice(0, 8) + '...' : 'none'}`);
    }
    return changed;
}

/**
 * Gets the current owner address.
 * @returns {string|null}
 */
export function getCurrentOwner() {
    return currentOwner;
}

/**
 * Saves a new note to the store.
 * @param {Object} params - Note parameters
 * @param {string} params.commitment - Commitment hash
 * @param {Uint8Array|string} params.privateKey - Private key
 * @param {Uint8Array|string} params.blinding - Blinding factor
 * @param {bigint|string|number} params.amount - Note amount
 * @param {number} params.leafIndex - Leaf index in pool tree
 * @param {number} params.ledger - Ledger when created
 * @param {string} [params.owner] - Stellar address (defaults to currentOwner)
 * @param {boolean} [params.isReceived=false] - True if received via transfer
 * @returns {Promise<UserNote>}
 */
export async function saveNote(params) {
    const owner = params.owner || currentOwner;
    if (!owner) {
        console.warn('[NotesStore] Saving note without owner - will not be filtered by account');
    }

    const noteJson = JSON.stringify({
        commitment: normalizeHex(params.commitment).toLowerCase(),
        owner: owner || '',
        privateKey: toHex(params.privateKey),
        blinding: toHex(params.blinding),
        amount: String(params.amount),
        leafIndex: params.leafIndex,
        ledger: params.ledger,
        createdAt: new Date().toISOString(),
        isReceived: params.isReceived || false,
    });

    let note;
    try {
        const savedJson = wasm().save_note(noteJson);
        note = JSON.parse(savedJson);
    } catch (e) {
        console.error('[NotesStore] Failed to save note:', e);
        throw e;
    }

    const noteType = note.isReceived ? 'received' : 'created';
    console.log(`[NotesStore] Saved ${noteType} note ${note.id.slice(0, 10)}... at index ${note.leafIndex} for ${owner ? owner.slice(0, 8) + '...' : 'unknown'}`);
    return note;
}

/**
 * Marks a note as spent.
 * @param {string} commitment - Note commitment
 * @param {number} ledger - Ledger when spent
 * @returns {Promise<boolean>} True if note was found and marked
 */
export async function markNoteSpent(commitment, ledger) {
    const id = normalizeHex(commitment).toLowerCase();
    try {
        const found = wasm().mark_note_spent(id, ledger);
        if (found) {
            console.log(`[NotesStore] Marked note ${id.slice(0, 10)}... as spent`);
        }
        return found;
    } catch (e) {
        console.error(`[NotesStore] Failed to mark note spent:`, e);
        return false;
    }
}

/**
 * Gets all user notes for the current owner.
 * @param {Object} [options] - Filter options
 * @param {boolean} [options.unspentOnly] - Only return unspent notes
 * @param {string} [options.owner] - Specific owner (defaults to currentOwner)
 * @param {boolean} [options.allOwners] - If true, returns notes from all owners
 * @returns {Promise<UserNote[]>}
 */
export async function getNotes(options = {}) {
    const owner = options.owner ?? currentOwner;

    if (!options.allOwners && !owner) {
        console.warn('[NotesStore] getNotes called without owner, returning empty');
        return [];
    }

    let notes;
    try {
        if (options.allOwners) {
            notes = JSON.parse(wasm().get_all_notes());
        } else {
            notes = JSON.parse(wasm().get_notes_by_owner(owner));
        }
    } catch (e) {
        console.error('[NotesStore] Failed to get notes:', e);
        return [];
    }

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
    try {
        const id = normalizeHex(commitment).toLowerCase();
        return JSON.parse(wasm().get_note_by_commitment(id));
    } catch (e) {
        console.error('[NotesStore] Failed to get note by commitment:', e);
        return null;
    }
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
    if (!currentOwner) return 0n;
    try {
        const balanceStr = wasm().get_balance(currentOwner);
        return BigInt(balanceStr);
    } catch (e) {
        console.error('[NotesStore] Failed to get balance:', e);
        return 0n;
    }
}

/**
 * Exports notes to a plain JSON blob.
 * @returns {Promise<Blob>}
 */
export async function exportNotes() {
    let notes;
    try {
        notes = JSON.parse(wasm().get_all_notes());
    } catch (e) {
        console.error('[NotesStore] Failed to export notes:', e);
        notes = [];
    }
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

    let imported = 0;
    for (const note of json.notes) {
        try {
            const existing = JSON.parse(wasm().get_note_by_commitment(note.id));
            if (!existing) {
                wasm().save_note(JSON.stringify(note));
                imported++;
            } else if (!existing.spent && note.spent) {
                wasm().mark_note_spent(note.id, note.spentAtLedger || 0);
            }
        } catch (e) {
            console.error(`[NotesStore] Failed to import note ${note.id?.slice(0, 10)}:`, e);
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
    const id = normalizeHex(commitment).toLowerCase();
    wasm().delete_note(id);
}

/**
 * Clears all notes.
 * @returns {Promise<void>}
 */
export async function clear() {
    wasm().clear_notes();
    console.log('[NotesStore] Cleared all notes');
}

// ── Key derivation (stays in JS — requires Freighter wallet) ────────

const ENCRYPTION_MESSAGE = "Sign to access Privacy Pool [v1]";
const SPENDING_KEY_MESSAGE = "Privacy Pool Spending Key [v1]";

let cachedEncryptionKeypair = null;
let cachedNoteKeypair = null;

/**
 * Get user X25519 encryption keypair, deriving from Freighter signature if needed.
 * @returns {Promise<{publicKey: Uint8Array, privateKey: Uint8Array}|null>}
 */
export async function getUserEncryptionKeypair() {
    if (cachedEncryptionKeypair) {
        return cachedEncryptionKeypair;
    }

    const signature = await requestSignature(ENCRYPTION_MESSAGE, 'encryption');
    if (!signature) {
        return null;
    }

    const keypair = deriveEncryptionKeypairFromSignature(signature);
    cachedEncryptionKeypair = keypair;

    console.log('[NotesStore] Derived encryption keypair');
    return keypair;
}

/**
 * Get encryption public key as hex string.
 * @returns {Promise<string|null>}
 */
export async function getEncryptionPublicKeyHex() {
    const keypair = await getUserEncryptionKeypair();
    if (!keypair) return null;
    return bytesToHex(keypair.publicKey);
}

/**
 * Get user note identity keypair, deriving from Freighter signature if needed.
 * @returns {Promise<{publicKey: Uint8Array, privateKey: Uint8Array}|null>}
 */
export async function getUserNoteKeypair() {
    if (cachedNoteKeypair) {
        return cachedNoteKeypair;
    }

    const signature = await requestSignature(SPENDING_KEY_MESSAGE, 'spending');
    if (!signature) {
        return null;
    }

    const privateKey = deriveNotePrivateKeyFromSignature(signature);
    const publicKey = derivePublicKey(privateKey);

    cachedNoteKeypair = { publicKey, privateKey };

    console.log('[NotesStore] Derived note identity keypair');
    return cachedNoteKeypair;
}

/**
 * Get note public key as hex string.
 * @returns {Promise<string|null>}
 */
export async function getNotePublicKeyHex() {
    const keypair = await getUserNoteKeypair();
    if (!keypair) return null;
    return bytesToHex(keypair.publicKey);
}

/**
 * Get note private key as Uint8Array.
 * @returns {Promise<Uint8Array|null>}
 */
export async function getNotePrivateKey() {
    const keypair = await getUserNoteKeypair();
    if (!keypair) return null;
    return keypair.privateKey;
}

/**
 * Clear all cached keypairs.
 */
export function clearKeypairCaches() {
    cachedEncryptionKeypair = null;
    cachedNoteKeypair = null;
    console.log('[NotesStore] Cleared keypair caches');
}

/**
 * Handle account change.
 * @param {string|null} newAddress
 * @returns {boolean} True if account actually changed
 */
export function handleAccountChange(newAddress) {
    const changed = setCurrentOwner(newAddress);
    if (changed) {
        clearKeypairCaches();
    }
    return changed;
}

/**
 * Check if user has authenticated (has cached keys).
 * @returns {boolean}
 */
export function hasAuthenticatedKeys() {
    return cachedEncryptionKeypair !== null && cachedNoteKeypair !== null;
}

/**
 * Set authenticated keys directly (used when keys are derived elsewhere).
 * @param {Object} keys
 * @param {Object} keys.encryptionKeypair
 * @param {Uint8Array} keys.notePrivateKey
 * @param {Uint8Array} keys.notePublicKey
 */
export function setAuthenticatedKeys({ encryptionKeypair, notePrivateKey, notePublicKey }) {
    if (encryptionKeypair) {
        cachedEncryptionKeypair = encryptionKeypair;
    }
    if (notePrivateKey && notePublicKey) {
        cachedNoteKeypair = { privateKey: notePrivateKey, publicKey: notePublicKey };
    }
    console.log('[NotesStore] Keys cached from external derivation');
}

/**
 * Initialize both keypairs (prompts user for two signatures).
 * @returns {Promise<boolean>}
 */
export async function initializeKeypairs() {
    const encryption = await getUserEncryptionKeypair();
    if (!encryption) return false;

    await new Promise(resolve => setTimeout(resolve, 500));

    let note = await getUserNoteKeypair();

    if (!note && encryption) {
        console.log('[NotesStore] Retrying spending key derivation after delay...');
        await new Promise(resolve => setTimeout(resolve, 1000));
        note = await getUserNoteKeypair();
    }

    if (!note) return false;
    return true;
}

/**
 * Request a signature from Freighter.
 * @param {string} message
 * @param {string} purpose
 * @returns {Promise<Uint8Array|null>}
 */
async function requestSignature(message, purpose) {
    const MAX_RETRIES = 2;
    let lastError = null;

    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
        try {
            const opts = currentOwner ? { address: currentOwner } : {};
            const result = await signWalletMessage(message, opts);

            if (!result.signedMessage) {
                console.warn(`[NotesStore] User rejected ${purpose} signature`);
                return null;
            }

            const signatureBytes = Uint8Array.from(
                atob(result.signedMessage),
                c => c.charCodeAt(0)
            );

            if (signatureBytes.length !== 64) {
                console.error(`[NotesStore] Invalid ${purpose} signature length:`, signatureBytes.length);
                return null;
            }

            return signatureBytes;
        } catch (e) {
            lastError = e;

            if (e.code === 'USER_REJECTED') {
                console.warn(`[NotesStore] User rejected ${purpose} signature request`);
                return null;
            }

            if (attempt < MAX_RETRIES) {
                console.warn(`[NotesStore] ${purpose} signature failed (attempt ${attempt + 1}), retrying...`, e.message);
                await new Promise(resolve => setTimeout(resolve, 500 * (attempt + 1)));
                continue;
            }
        }
    }

    console.error(`[NotesStore] Failed to get ${purpose} signature after retries:`, lastError);
    return null;
}
