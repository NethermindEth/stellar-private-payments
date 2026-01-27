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
 * 
 * @module state/notes-store
 */

import * as db from './db.js';
import { toHex, normalizeHex, bytesToHex, hexToBytes } from './utils.js';
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
 * @property {boolean} [isReceived] - True if note was received via transfer (vs created by user)
 * @property {boolean} [isLegacy] - True if note was created with legacy byte order (before endianness fix)
 */

// Current owner address for filtering notes
let currentOwner = null;

/**
 * Sets the current owner address for note filtering.
 * Call this when wallet connects or changes.
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
 * @param {string} [params.owner] - Stellar address that owns this note (defaults to currentOwner)
 * @param {boolean} [params.isReceived=false] - True if note was received via transfer (discovered by scanning)
 * @param {boolean} [params.isLegacy=false] - True if note was created with legacy byte order (before endianness fix)
 * @returns {Promise<UserNote>}
 */
export async function saveNote(params) {
    const owner = params.owner || currentOwner;
    if (!owner) {
        console.warn('[NotesStore] Saving note without owner - will not be filtered by account');
    }
    
    const note = {
        id: normalizeHex(params.commitment).toLowerCase(),
        owner: owner || '',
        privateKey: toHex(params.privateKey),
        blinding: toHex(params.blinding),
        amount: String(params.amount),
        leafIndex: params.leafIndex,
        createdAt: new Date().toISOString(),
        createdAtLedger: params.ledger,
        spent: false,
        isReceived: params.isReceived || false,
        isLegacy: params.isLegacy || false,
    };
    
    await db.put('user_notes', note);
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
 * Gets all user notes for the current owner.
 * @param {Object} [options] - Filter options
 * @param {boolean} [options.unspentOnly] - Only return unspent notes
 * @param {string} [options.owner] - Specific owner to filter by (defaults to currentOwner)
 * @param {boolean} [options.allOwners] - If true, returns notes from all owners
 * @returns {Promise<UserNote[]>}
 */
export async function getNotes(options = {}) {
    let notes;
    const owner = options.owner ?? currentOwner;
    
    if (options.allOwners) {
        notes = await db.getAll('user_notes');
    } else if (owner) {
        notes = await db.getAllByIndex('user_notes', 'by_owner', owner);
    } else {
        // No owner set - return empty to prevent showing other users' notes
        console.warn('[NotesStore] getNotes called without owner, returning empty');
        return [];
    }
    
    if (options.unspentOnly) {
        return notes.filter(n => !n.spent);
    }
    
    return notes;
}

/**
 * Gets a note by commitment (case-insensitive hex comparison).
 * @param {string} commitment - Note commitment
 * @returns {Promise<UserNote|null>}
 */
export async function getNoteByCommitment(commitment) {
    const id = normalizeHex(commitment).toLowerCase();
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
    const id = normalizeHex(commitment).toLowerCase();
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

// Key derivation constants.
// These MUST remain constant for backwards compatibility.

// Message signed to derive the X25519 encryption keypair
const ENCRYPTION_MESSAGE = "Sign to access Privacy Pool [v1]";

// Message signed to derive the BN254 note identity keypair
const SPENDING_KEY_MESSAGE = "Privacy Pool Spending Key [v1]";

// In-memory key caches to avoid repeated Freighter usage
let cachedEncryptionKeypair = null;
let cachedNoteKeypair = null;


/**
 * Get user X25519 encryption keypair, deriving from Freighter signature if needed.
 * 
 * This keypair is used with XSalsa20-Poly1305 to encrypt note data so that
 * only the recipient can see the amount and blinding factor.
 * 
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
 * Get encryption public key as hex string (for sharing with senders).
 * @returns {Promise<string|null>}
 */
export async function getEncryptionPublicKeyHex() {
    const keypair = await getUserEncryptionKeypair();
    if (!keypair) {
        return null;
    }
    return bytesToHex(keypair.publicKey);
}

/**
 * Get user note identity keypair, deriving from Freighter signature if needed.
 * 
 * This keypair is used inside ZK circuits:
 * - privateKey: Proves you own the note (used in nullifier derivation)
 * - publicKey: Identifies you as recipient (included in commitment)
 * 
 * The public key is derived via Poseidon2(privateKey, 0, domain=0x03).
 * 
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
    
    // Derive private key from signature
    const privateKey = deriveNotePrivateKeyFromSignature(signature);
    
    // Derive public key via Poseidon2
    const publicKey = derivePublicKey(privateKey);
    
    cachedNoteKeypair = { publicKey, privateKey };
    
    console.log('[NotesStore] Derived note identity keypair');
    return cachedNoteKeypair;
}

/**
 * Get note public key as hex string (for sharing with senders).
 * This is the key others use to send notes to you.
 * @returns {Promise<string|null>}
 */
export async function getNotePublicKeyHex() {
    const keypair = await getUserNoteKeypair();
    if (!keypair) {
        return null;
    }
    return bytesToHex(keypair.publicKey);
}

/**
 * Get note private key as Uint8Array.
 * Used when constructing ZK proofs to spend notes.
 * @returns {Promise<Uint8Array|null>}
 */
export async function getNotePrivateKey() {
    const keypair = await getUserNoteKeypair();
    if (!keypair) {
        return null;
    }
    return keypair.privateKey;
}

// Cache management
/**
 * Clear all cached keypairs (call on logout, wallet disconnect, or account change).
 */
export function clearKeypairCaches() {
    cachedEncryptionKeypair = null;
    cachedNoteKeypair = null;
    console.log('[NotesStore] Cleared keypair caches');
}

/**
 * Handle account change - clears caches and updates owner.
 * @param {string|null} newAddress - New Stellar address or null if disconnecting
 * @returns {boolean} True if the account actually changed
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
 * This allows note scanning to work after deposits/withdraws/transfers
 * without prompting for additional signatures.
 * 
 * @param {Object} keys
 * @param {Object} keys.encryptionKeypair - X25519 keypair { publicKey, secretKey }
 * @param {Uint8Array} keys.notePrivateKey - BN254 private key
 * @param {Uint8Array} keys.notePublicKey - BN254 public key
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
 * Call this during login/setup flow.
 * @returns {Promise<boolean>} True if both keypairs were derived successfully
 */
export async function initializeKeypairs() {
    const encryption = await getUserEncryptionKeypair();
    if (!encryption) {
        return false;
    }
    
    const note = await getUserNoteKeypair();
    if (!note) {
        return false;
    }
    
    return true;
}

/**
 * Request a signature from Freighter and decode it.
 * @param {string} message - Message to sign
 * @param {string} purpose - Purpose for logging
 * @returns {Promise<Uint8Array|null>} 64-byte Ed25519 signature or null
 */
async function requestSignature(message, purpose) {
    try {
        // Pass current owner address to ensure Freighter signs with the correct account.
        // This prevents race conditions after account switches where Freighter might
        // still reference a stale account context on the first signature attempt.
        const opts = currentOwner ? { address: currentOwner } : {};
        const result = await signWalletMessage(message, opts);
        
        if (!result.signedMessage) {
            console.warn(`[NotesStore] User rejected ${purpose} signature`);
            return null;
        }
        
        // Decode base64 to bytes
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
        if (e.code === 'USER_REJECTED') {
            console.warn(`[NotesStore] User rejected ${purpose} signature request`);
            return null;
        }
        console.error(`[NotesStore] Failed to get ${purpose} signature:`, e);
        return null;
    }
}