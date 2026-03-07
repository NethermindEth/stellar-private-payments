/**
 * Web Crypto helpers for encrypting note secrets at rest in IndexedDB.
 *
 * An AES-256-GCM storage key is derived from the user's X25519 private key
 * via HKDF-SHA-256 with a domain-specific info string. This makes the storage
 * key cryptographically independent from the on-chain encryption key while
 * requiring no additional Freighter prompts.
 *
 * Encrypted field format: "<ivHex>:<ciphertextHex>"
 *   - IV:         12 random bytes (96-bit), hex-encoded with 0x prefix
 *   - Ciphertext: AES-GCM output (plaintext + 16-byte auth tag), hex-encoded
 *
 * @module state/crypto
 */

import { hexToBytes, bytesToHex } from './utils.js';

const STORAGE_KEY_INFO = new TextEncoder().encode('IndexedDB note encryption v1');
const EMPTY_SALT = new Uint8Array(32);

/**
 * Derive a non-exportable AES-256-GCM key from X25519 private key bytes
 * using HKDF-SHA-256. The info string domain-separates this key from the
 * on-chain X25519 usage.
 *
 * @param {Uint8Array} privateKeyBytes - 32-byte X25519 private key
 * @returns {Promise<CryptoKey>} AES-GCM key usable only for encrypt/decrypt
 */
export async function deriveStorageKey(privateKeyBytes) {
    const keyMaterial = await crypto.subtle.importKey(
        'raw', privateKeyBytes, 'HKDF', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt: EMPTY_SALT, info: STORAGE_KEY_INFO },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

/**
 * Encrypt a hex-encoded field value with AES-256-GCM.
 * A fresh 12-byte random IV is generated per call.
 *
 * @param {string} hexValue - Hex string to encrypt (with or without 0x prefix)
 * @param {CryptoKey} aesKey - AES-256-GCM key from deriveStorageKey()
 * @returns {Promise<string>} Encrypted string in "<ivHex>:<ciphertextHex>" format
 */
export async function encryptField(hexValue, aesKey) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plaintext = hexToBytes(hexValue);
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, plaintext);
    return bytesToHex(iv) + ':' + bytesToHex(new Uint8Array(ciphertext));
}

/**
 * Decrypt an AES-256-GCM encrypted field back to a hex string.
 *
 * @param {string} encryptedValue - "<ivHex>:<ciphertextHex>" from encryptField()
 * @param {CryptoKey} aesKey - AES-256-GCM key from deriveStorageKey()
 * @returns {Promise<string>} Original hex string (with 0x prefix)
 */
export async function decryptField(encryptedValue, aesKey) {
    const sep = encryptedValue.indexOf(':');
    const iv = hexToBytes(encryptedValue.slice(0, sep));
    const ct = hexToBytes(encryptedValue.slice(sep + 1));
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ct);
    return bytesToHex(new Uint8Array(plaintext));
}
