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
import { deriveStorageKey, encryptField, decryptField } from './crypto.js';

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
 * @returns {Promise<UserNote>}
 */
export async function saveNote(params) {
    const owner = params.owner || currentOwner;
    if (!owner) {
        console.warn('[NotesStore] Saving note without owner - will not be filtered by account');
    }
    
    const storageKey = await getStorageKey();
    if (!storageKey) {
        throw new Error(
            '[NotesStore] Cannot save note: encryption key not yet derived. ' +
            'Call initializeKeypairs() or perform a transaction to derive keys first.'
        );
    }

    const privateKeyHex = toHex(params.privateKey);
    const blindingHex   = toHex(params.blinding);

    const note = {
        id: normalizeHex(params.commitment).toLowerCase(),
        owner: owner || '',
        privateKey: await encryptField(privateKeyHex, storageKey),
        blinding:   await encryptField(blindingHex,   storageKey),
        encrypted:  true,
        amount: String(params.amount),
        leafIndex: params.leafIndex,
        createdAt: new Date().toISOString(),
        createdAtLedger: params.ledger,
        spent: false,
        isReceived: params.isReceived || false,
    };

    await db.put('user_notes', note);
    const noteType = note.isReceived ? 'received' : 'created';
    console.log(`[NotesStore] Saved ${noteType} note ${note.id.slice(0, 10)}... at index ${note.leafIndex} for ${owner ? owner.slice(0, 8) + '...' : 'unknown'}`);
    return await decryptNote(note, storageKey);
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

    // Update spent fields on the raw (potentially encrypted) record directly —
    // the secret fields (privateKey, blinding) are not touched, so encryption
    // state is preserved without needing to decrypt and re-encrypt.
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
        notes = notes.filter(n => !n.spent);
    }

    const storageKey = await getStorageKey();
    return Promise.all(notes.map(n => decryptNoteWithMigration(n, storageKey)));
}

/**
 * Gets a note by commitment (case-insensitive hex comparison).
 * @param {string} commitment - Note commitment
 * @returns {Promise<UserNote|null>}
 */
export async function getNoteByCommitment(commitment) {
    const id = normalizeHex(commitment).toLowerCase();
    const note = await db.get('user_notes', id) || null;
    if (!note) return null;
    const storageKey = await getStorageKey();
    return decryptNoteWithMigration(note, storageKey);
}

/**
 * Gets unspent notes for transaction inputs.
 * @returns {Promise<UserNote[]>}
 */
export async function getUnspentNotes() {
    return getNotes({ unspentOnly: true });
}

/**
 * Returns true if the current owner has any notes stored without encryption.
 * Used at wallet connect to detect whether a one-time migration is needed.
 * @returns {Promise<boolean>}
 */
export async function hasUnencryptedNotes() {
    const owner = currentOwner;
    const notes = owner
        ? await db.getAllByIndex('user_notes', 'by_owner', owner)
        : await db.getAll('user_notes');
    return notes.some(n => !n.encrypted);
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
    const storageKey = await getStorageKey();
    const rawNotes = await db.getAll('user_notes');

    const hasEncryptedNotes = rawNotes.some(n => n.encrypted);
    if (hasEncryptedNotes && !storageKey) {
        throw new Error(
            'Cannot export: encryption key not yet derived. ' +
            'Please perform a transaction first to derive your keys, then export.'
        );
    }

    // Decrypt before export so the file is portable (not tied to this user's derived key)
    const notes = await Promise.all(rawNotes.map(n => decryptNote(n, storageKey)));
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
    const storageKey = await getStorageKey();
    if (!storageKey) {
        throw new Error(
            '[NotesStore] Cannot import notes: encryption key not yet derived. ' +
            'Call initializeKeypairs() or perform a transaction to derive keys first.'
        );
    }

    let imported = 0;
    for (const note of json.notes) {
        const existing = await db.get('user_notes', note.id);
        if (!existing) {
            // Encrypt secret fields before storing. Exports are decrypted plaintext
            // (see exportNotes), so imported notes always arrive unencrypted.
            await db.put('user_notes', {
                ...note,
                privateKey: await encryptField(note.privateKey, storageKey),
                blinding:   await encryptField(note.blinding,   storageKey),
                encrypted:  true,
            });
            imported++;
        } else if (!existing.spent && note.spent) {
            // Update metadata only; preserve the existing note's encryption state.
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

// In-memory key caches to avoid repeated Freighter usage.
// Keys stay in memory only, but are scoped per account so A -> B -> A switches
// can reuse previously-derived keys without re-prompting.
const DEFAULT_CACHE_KEY = '__default__';
const accountKeyCache = new Map();

function getAccountCacheKey(owner = currentOwner) {
    return owner || DEFAULT_CACHE_KEY;
}

function getAccountCache(owner = currentOwner) {
    return accountKeyCache.get(getAccountCacheKey(owner)) || null;
}

function ensureAccountCache(owner = currentOwner) {
    const cacheKey = getAccountCacheKey(owner);
    let cache = accountKeyCache.get(cacheKey);
    if (!cache) {
        cache = {
            encryptionKeypair: null,
            noteKeypair: null,
            storageKey: null,
        };
        accountKeyCache.set(cacheKey, cache);
    }
    return cache;
}

/**
 * Get (or lazily derive) the AES-256-GCM key used to encrypt note secrets at rest.
 * Derived from the X25519 private key via HKDF — no extra Freighter prompt needed.
 * Returns null if the encryption keypair is not yet available.
 * @returns {Promise<CryptoKey|null>}
 */
async function getStorageKey() {
    const cache = getAccountCache();
    if (cache?.storageKey) return cache.storageKey;
    // Only derive from the already-cached keypair. Do NOT call getUserEncryptionKeypair()
    // here — that would trigger a Freighter signature prompt in unexpected places (e.g.
    // wallet connect, note table refresh). The storage key becomes available after the
    // first explicit key-derivation call (transaction flow or initializeKeypairs()).
    if (!cache?.encryptionKeypair) return null;
    cache.storageKey = await deriveStorageKey(cache.encryptionKeypair.privateKey);
    return cache.storageKey;
}

/**
 * Decrypt a note's encrypted fields back to plaintext hex.
 * If the note is not marked as encrypted (legacy row), it is returned unchanged.
 * If the storage key is unavailable, the note is returned as-is (degraded).
 * @param {Object} note - Raw note from IndexedDB
 * @param {CryptoKey|null} storageKey
 * @returns {Promise<Object>} Note with plaintext privateKey and blinding
 */
async function decryptNote(note, storageKey) {
    if (!note || !note.encrypted) return note;
    if (!storageKey) {
        // Return the note without the secret fields so callers never accidentally
        // receive raw ciphertext as if it were plaintext. The note remains usable
        // for display (amount, id, spent, leafIndex are all unencrypted) but cannot
        // be used for proof generation until keys are derived.
        const { privateKey, blinding, ...rest } = note;
        return { ...rest, privateKey: null, blinding: null };
    }
    return {
        ...note,
        privateKey: await decryptField(note.privateKey, storageKey),
        blinding:   await decryptField(note.blinding,   storageKey),
        encrypted:  false,
    };
}

/**
 * Decrypt a note, migrating plaintext legacy rows to encrypted storage on first access.
 * @param {Object} note - Raw note from IndexedDB
 * @param {CryptoKey|null} storageKey
 * @returns {Promise<Object>} Note with plaintext privateKey and blinding
 */
async function decryptNoteWithMigration(note, storageKey) {
    if (!note) return note;
    if (!note.encrypted && storageKey) {
        // Legacy plaintext row — encrypt in place so it's protected going forward
        const migrated = {
            ...note,
            privateKey: await encryptField(note.privateKey, storageKey),
            blinding:   await encryptField(note.blinding,   storageKey),
            encrypted:  true,
        };
        await db.put('user_notes', migrated);
        return note; // return original plaintext to caller
    }
    return decryptNote(note, storageKey);
}


/**
 * Get user X25519 encryption keypair, deriving from Freighter signature if needed.
 * 
 * This keypair is used with XSalsa20-Poly1305 to encrypt note data so that
 * only the recipient can see the amount and blinding factor.
 * 
 * @returns {Promise<{publicKey: Uint8Array, privateKey: Uint8Array}|null>}
 */
export async function getUserEncryptionKeypair() {
    const cached = getAccountCache();
    if (cached?.encryptionKeypair) {
        return cached.encryptionKeypair;
    }
    
    const signature = await requestSignature(ENCRYPTION_MESSAGE, 'encryption');
    if (!signature) {
        return null;
    }
    
    const keypair = deriveEncryptionKeypairFromSignature(signature);
    const cache = ensureAccountCache();
    cache.encryptionKeypair = keypair;
    cache.storageKey = null;
    
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
    const cached = getAccountCache();
    if (cached?.noteKeypair) {
        return cached.noteKeypair;
    }
    
    const signature = await requestSignature(SPENDING_KEY_MESSAGE, 'spending');
    if (!signature) {
        return null;
    }
    
    // Derive private key from signature
    const privateKey = deriveNotePrivateKeyFromSignature(signature);
    
    // Derive public key via Poseidon2
    const publicKey = derivePublicKey(privateKey);
    
    const keypair = { publicKey, privateKey };
    ensureAccountCache().noteKeypair = keypair;
    
    console.log('[NotesStore] Derived note identity keypair');
    return keypair;
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
 * Clear all cached keypairs for all accounts in this session.
 * Call on logout or wallet disconnect.
 */
export function clearKeypairCaches() {
    accountKeyCache.clear();
    console.log('[NotesStore] Cleared keypair caches');
}

/**
 * Handle account change.
 * - Switching between non-null accounts preserves per-account session caches.
 * - Disconnecting (null owner) clears all cached keys.
 * @param {string|null} newAddress - New Stellar address or null if disconnecting
 * @returns {boolean} True if the account actually changed
 */
export function handleAccountChange(newAddress) {
    const changed = setCurrentOwner(newAddress);
    if (changed && !newAddress) {
        clearKeypairCaches();
    }
    return changed;
}

/**
 * Check if user has authenticated (has cached keys).
 * @returns {boolean}
 */
export function hasAuthenticatedKeys() {
    const cache = getAccountCache();
    return !!(cache?.encryptionKeypair && cache?.noteKeypair);
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
 * @param {string} [keys.owner] - Owner to cache for (defaults to currentOwner)
 */
export function setAuthenticatedKeys({ encryptionKeypair, notePrivateKey, notePublicKey, owner }) {
    const cache = ensureAccountCache(owner);
    if (encryptionKeypair) {
        cache.encryptionKeypair = encryptionKeypair;
        cache.storageKey = null;
    }
    if (notePrivateKey && notePublicKey) {
        cache.noteKeypair = { privateKey: notePrivateKey, publicKey: notePublicKey };
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
    
    // Delay to let Freighter settle between signature requests.
    // Rapid successive requests can fail due to Freighter's internal state.
    await new Promise(resolve => setTimeout(resolve, 500));
    
    let note = await getUserNoteKeypair();
    
    // If encryption worked but spending failed, it's likely a timing issue.
    // Retry once more with a longer delay.
    if (!note && encryption) {
        console.log('[NotesStore] Retrying spending key derivation after delay...');
        await new Promise(resolve => setTimeout(resolve, 1000));
        note = await getUserNoteKeypair();
    }
    
    if (!note) {
        return false;
    }
    
    return true;
}

/**
 * Request a signature from Freighter and decode it.
 * Includes retry logic for transient Freighter failures.
 * @param {string} message - Message to sign
 * @param {string} purpose - Purpose for logging
 * @returns {Promise<Uint8Array|null>} 64-byte Ed25519 signature or null
 */
async function requestSignature(message, purpose) {
    const MAX_RETRIES = 2;
    let lastError = null;
    
    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
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
            lastError = e;
            
            // Actual user rejection - don't retry
            if (e.code === 'USER_REJECTED') {
                console.warn(`[NotesStore] User rejected ${purpose} signature request`);
                return null;
            }
            
            // Transient error - retry after delay
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
