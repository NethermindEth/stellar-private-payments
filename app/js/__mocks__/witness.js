// app/js/__mocks__/witness/witness.js

const initWitnessWasm = async () => {};

class WitnessCalculator {
    constructor(circuitWasm, r1csBytes) {
        this.circuitWasm = circuitWasm;
        this.r1csBytes = r1csBytes;

        // Match what bridge.getCircuitInfo expects
        this.witness_size = 8;
        this.num_public_inputs = 2;
    }

    compute_witness(_inputsJson) {
        // Return ArrayBuffer-like data; bridge wraps it with new Uint8Array(...)
        return new Uint8Array(64).buffer;
    }
}

function version() {
    return 'mock-witness-version';
}

module.exports = {
    __esModule: true,
    default: initWitnessWasm,
    WitnessCalculator,
    version,
};
