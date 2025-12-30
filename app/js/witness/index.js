/**
 * Witness Module (GPL-3.0)
 * 
 * This module uses Circom's witness_calculator.js which is GPL-3.0 licensed.
 * It is isolated from the rest of the application and communicates
 * ONLY via Uint8Array data exchange.
 * 
 * @license GPL-3.0
 */

import witnessBuilder from './witness_calculator.js';

let wc = null;

/**
 * Initialize the witness calculator with the circuit's WASM file
 * 
 * @param {string} wasmUrl - URL to the circuit's witness calculator WASM
 * @returns {Promise<void>}
 */
export async function initWitness(wasmUrl) {
    const response = await fetch(wasmUrl);
    if (!response.ok) {
        throw new Error(`Failed to fetch witness WASM: ${response.status} ${response.statusText}`);
    }
    const wasmBuffer = await response.arrayBuffer();
    
    // Build the witness calculator using Circom's builder
    wc = await witnessBuilder(wasmBuffer);
    
    console.log('[Witness] Calculator initialized');
    console.log(`[Witness] Circom version: ${wc.circom_version()}`);
    console.log(`[Witness] Witness size: ${wc.witnessSize} elements`);
}

/**
 * Compute witness from circuit inputs and return as Little-Endian bytes
 * 
 * Uses Circom's calculateBinWitness which returns bytes in LE format,
 * which is exactly what Arkworks expects.
 * 
 * @param {Object} inputs - Circuit inputs as { signalName: value | value[] }
 *                          Values can be BigInt, number, or string representations
 * @returns {Promise<Uint8Array>} - Witness as Little-Endian bytes (32 bytes per field element)
 */
export async function computeWitness(inputs) {
    if (!wc) {
        throw new Error('Witness calculator not initialized. Call initWitness() first.');
    }
    
    // Use calculateBinWitness which returns
    // This is the format Arkworks (ark-ff) expects
    const witnessBytes = await wc.calculateBinWitness(inputs, true);
    
    return witnessBytes;
}

/**
 * Compute witness and return as BigInt array (useful for debugging)
 * 
 * @param {Object} inputs - Circuit inputs
 * @returns {Promise<BigInt[]>} - Witness as array of BigInt field elements
 */
export async function computeWitnessArray(inputs) {
    if (!wc) {
        throw new Error('Witness calculator not initialized. Call initWitness() first.');
    }
    
    // Use calculateWitness which returns BigInt[]
    const witness = await wc.calculateWitness(inputs, true);
    return witness;
}

/**
 * Compute witness in WTNS binary format (for snarkjs compatibility)
 * 
 * @param {Object} inputs - Circuit inputs
 * @returns {Promise<Uint8Array>} - Witness in WTNS binary format
 */
export async function computeWitnessWTNS(inputs) {
    if (!wc) {
        throw new Error('Witness calculator not initialized. Call initWitness() first.');
    }
    
    const wtns = await wc.calculateWTNSBin(inputs, true);
    return wtns;
}

/**
 * Get information about the loaded circuit
 * 
 * @returns {Object} - Circuit info: { witnessSize, circomVersion, prime }
 */
export function getCircuitInfo() {
    if (!wc) {
        throw new Error('Witness calculator not initialized. Call initWitness() first.');
    }
    
    return {
        witnessSize: wc.witnessSize,
        circomVersion: wc.circom_version(),
        prime: wc.prime,
        n32: wc.n32,  // Number of 32-bit words per field element
    };
}

/**
 * Convert Little-Endian bytes back to BigInt array (for debugging)
 * 
 * @param {Uint8Array} bytes - Little-Endian witness bytes
 * @returns {BigInt[]} - Array of field elements
 */
export function bytesToWitness(bytes) {
    const FIELD_SIZE = 32;  // BN254: 8 x 32-bit words = 32 bytes
    if (bytes.length % FIELD_SIZE !== 0) {
        throw new Error(`Witness bytes length ${bytes.length} is not a multiple of ${FIELD_SIZE}`);
    }
    
    const numElements = bytes.length / FIELD_SIZE;
    const witness = new Array(numElements);
    
    // Circom uses Little-Endian byte order
    for (let i = 0; i < numElements; i++) {
        let value = 0n;
        // Little-Endian: LSB first, so we read backwards to build the BigInt
        for (let j = FIELD_SIZE - 1; j >= 0; j--) {
            value = (value << 8n) | BigInt(bytes[i * FIELD_SIZE + j]);
        }
        witness[i] = value;
    }
    
    return witness;
}

/**
 * Convert BigInt array to Little-Endian bytes (for testing)
 * 
 * @param {BigInt[]} witness - Array of field elements
 * @returns {Uint8Array} - Little-Endian bytes
 */
export function witnessToBytes(witness) {
    const FIELD_SIZE = 32;
    const buf = new Uint8Array(witness.length * FIELD_SIZE);
    
    for (let i = 0; i < witness.length; i++) {
        let value = witness[i];
        // Little-Endian: LSB first
        for (let j = 0; j < FIELD_SIZE; j++) {
            buf[i * FIELD_SIZE + j] = Number(value & 0xffn);
            value >>= 8n;
        }
    }
    
    return buf;
}
