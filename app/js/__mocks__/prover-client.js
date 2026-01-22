/**
 * Mock for prover-client.js - used by Jest tests.
 * Avoids the import.meta.url issue in test environment.
 */

const state = {
    modulesReady: true,
    witnessReady: true,
    proverReady: true,
    initializing: false,
    error: null,
};

function onProgress(callback) {
    return () => {};
}

async function initializeProver(options = {}) {
    return { success: true, state };
}

function isReady() {
    return true;
}

function getState() {
    return { ...state };
}

async function isCached() {
    return true;
}

async function clearCache() {}

async function prove(inputs, options = {}) {
    return {
        proof: new Uint8Array(256),
        publicInputs: new Uint8Array(32),
        sorobanFormat: options.sorobanFormat || false,
        timings: { witness: 100, prove: 500 },
    };
}

async function convertProofToSoroban(proofBytes) {
    return new Uint8Array(256);
}

async function verify(proofBytes, publicInputsBytes) {
    return true;
}

async function derivePublicKey(privateKey, asHex = false) {
    const mockKey = new Uint8Array(32).fill(1);
    return asHex ? '0x' + '01'.repeat(32) : mockKey;
}

async function computeCommitment(amount, publicKey, blinding) {
    return new Uint8Array(32).fill(2);
}

async function getVerifyingKey(options = {}) {
    return new Uint8Array(128);
}

async function getCircuitInfo() {
    return { numConstraints: 1000, numPublicInputs: 10 };
}

async function ping() {
    return { success: true, pong: true };
}

function terminate() {}

module.exports = {
    __esModule: true,
    onProgress,
    initializeProver,
    isReady,
    getState,
    isCached,
    clearCache,
    prove,
    convertProofToSoroban,
    verify,
    derivePublicKey,
    computeCommitment,
    getVerifyingKey,
    getCircuitInfo,
    ping,
    terminate,
    default: {
        initializeProver,
        isReady,
        isCached,
        clearCache,
        prove,
        verify,
        derivePublicKey,
        computeCommitment,
        getVerifyingKey,
        getCircuitInfo,
        terminate,
        onProgress,
    },
};
