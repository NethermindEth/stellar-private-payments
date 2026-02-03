/**
 * Shared utilities for state management modules.
 * @module state/utils
 */

// Tree depths - must match circuit and contract deployments
export const TREE_DEPTH = 10;
export const SMT_DEPTH = 10;

/**
 * Converts hex string to Uint8Array.
 * @param {string} hex - Hex string (with or without 0x prefix)
 * @returns {Uint8Array}
 * @throws {TypeError} If input is not a string
 * @throws {Error} If hex string has odd length or invalid characters
 */
export function hexToBytes(hex) {
    if (typeof hex !== 'string') {
        throw new TypeError('Expected hex string');
    }
    const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
    if (cleanHex.length % 2 !== 0) {
        throw new Error('Hex string must have even length');
    }
    if (cleanHex.length > 0 && !/^[0-9a-fA-F]+$/.test(cleanHex)) {
        throw new Error('Invalid hex characters');
    }
    const bytes = new Uint8Array(cleanHex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(cleanHex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}

/**
 * Converts Uint8Array to hex string with 0x prefix.
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function bytesToHex(bytes) {
    return '0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Ensures hex string has 0x prefix.
 * @param {string} hex
 * @returns {string}
 */
export function normalizeHex(hex) {
    if (typeof hex !== 'string') return String(hex);
    return hex.startsWith('0x') ? hex : '0x' + hex;
}

/**
 * Converts value to hex string with 0x prefix.
 * @param {Uint8Array|string} value
 * @returns {string}
 */
export function toHex(value) {
    if (typeof value === 'string') {
        return normalizeHex(value);
    }
    return bytesToHex(value);
}

/**
 * Normalizes U256 value to hex string.
 * Handles string, bigint, Uint8Array, and Stellar U256 object representations.
 * @param {string|bigint|Uint8Array|object} value - U256 value
 * @returns {string}
 * @throws {Error} If value is null or undefined
 */
export function normalizeU256ToHex(value) {
    if (value === null || value === undefined) {
        throw new Error('Cannot normalize null/undefined U256 value');
    }
    if (typeof value === 'string') {
        return normalizeHex(value);
    }
    if (typeof value === 'bigint') {
        return '0x' + value.toString(16).padStart(64, '0');
    }
    if (value instanceof Uint8Array) {
        return bytesToHex(value);
    }
    if (typeof value === 'object') {
        // Handle Stellar U256 object with hi/lo parts
        if ('hi' in value && 'lo' in value) {
            const hi = BigInt(value.hi);
            const lo = BigInt(value.lo);
            const combined = (hi << 128n) | lo;
            return '0x' + combined.toString(16).padStart(64, '0');
        }
        console.warn('[utils] Unexpected U256 object format:', value);
        return String(value);
    }
    return String(value);
}

/**
 * Reverses a Uint8Array in place and returns it.
 * @param {Uint8Array} bytes
 * @returns {Uint8Array}
 */
export function reverseBytes(bytes) {
    return bytes.reverse();
}

/**
 * Converts hex string to LE bytes for Rust Merkle tree insertion.
 * 
 * The Rust Merkle tree uses from_le_bytes_mod_order (LE).
 * Soroban stores U256 as BE and converts via BigUint::from_bytes_be.
 * We reverse BE to LE to ensure the same numeric value.
 * 
 * @param {string} hex - Hex string (BE representation of U256)
 * @returns {Uint8Array} LE bytes for Rust tree insertion
 */
export function hexToBytesForTree(hex) {
    const beBytes = hexToBytes(hex);
    return beBytes.reverse();
}
