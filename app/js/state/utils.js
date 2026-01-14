/**
 * Shared utilities for state management modules.
 * @module state/utils
 */

/**
 * Converts hex string to Uint8Array.
 * @param {string} hex - Hex string (with or without 0x prefix)
 * @returns {Uint8Array}
 */
export function hexToBytes(hex) {
    const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
    const bytes = new Uint8Array(cleanHex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(cleanHex.substr(i * 2, 2), 16);
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
 * Handles string, bigint, and object representations.
 * @param {string|bigint|object} value - U256 value
 * @returns {string}
 */
export function normalizeU256ToHex(value) {
    if (typeof value === 'string') {
        return normalizeHex(value);
    }
    if (typeof value === 'bigint') {
        return '0x' + value.toString(16).padStart(64, '0');
    }
    if (typeof value === 'object' && value !== null) {
        try {
            return JSON.stringify(value);
        } catch {
            return String(value);
        }
    }
    return String(value);
}
