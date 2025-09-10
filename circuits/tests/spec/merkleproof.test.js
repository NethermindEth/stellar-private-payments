// circuits/tests/spec/merkleproof.test.js
const { expect } = require("chai");
const path = require("path");
const fs = require("fs");
const os = require("os");
const { wasm: wasm_tester } = require("circom_tester");

describe("MerkleProof(levels)", function () {

    const CIRCUITS_SRC = path.resolve(__dirname, "../../src");
    const MERKLE_PROOF_CIRCUIT = path.join(CIRCUITS_SRC, "merkleProof.circom");
    const POSEIDON2_HASH_CIRCUIT = path.join(CIRCUITS_SRC, "poseidon2", "poseidon2_hash.circom");

    const LEVELS = 3;
    const leaf = "1";
    const pathElements = ["2", "3", "4"];
    // pathIndices: bit i => 1 means sibling is on the LEFT at level i
    const pathIndices = 0b101;

    let merkleCircuit;
    let hash2Circuit;

    // Read a single named output
    async function readOut(circuit, witness, name) {
        const out = await circuit.getOutput(witness, { [name]: 1 });
        const value = out[name];
        return value.toString();
    }

    // Create a temp wrapper in order to have a main. Basically generate a runtime circuit
    function writeMerkleWrapper(levels) {
        const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "mp-wrapper-"));
        const file = path.join(tmpDir, `MerkleProof_${levels}.circom`);
        const content = `pragma circom 2.2.0;
include "${MERKLE_PROOF_CIRCUIT.replace(/\\/g, "/")}";
component main = MerkleProof(${levels});`;
        fs.writeFileSync(file, content);
        return file;
    }

    // Tiny helper circuit exposing Poseidon2(a,b) -> out. Basically generate a runtime circuit
    async function compileHash2Helper() {
        const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "hash2-"));
        const file = path.join(tmpDir, `Hash2.circom`);
        const content = `pragma circom 2.2.0;
include "${POSEIDON2_HASH_CIRCUIT.replace(/\\/g, "/")}";
template Hash2() {
  signal input a; signal input b; signal output out;
  component h = Poseidon2(2);
  h.inputs[0] <== a;
  h.inputs[1] <== b;
  out <== h.out;
}
component main = Hash2();`;
        fs.writeFileSync(file, content);
        return await wasm_tester(file);
    }

    // js side Poseidon2(a,b) by running the helper circuit once
    async function hash2(a, b) {
        const witness = await hash2Circuit.calculateWitness(
            { a: a.toString(), b: b.toString() },
            true
        );
        await hash2Circuit.checkConstraints(witness);
        return await readOut(hash2Circuit, witness, "out");
    }

    // Compute expected Merkle root off chain using same Poseidon2 params
    async function computeMerkleRootJS(leafVal, siblings, idxBits) {
        let cur = leafVal.toString();
        for (let i = 0; i < siblings.length; i++) {
            const sib = siblings[i].toString();
            const left = (idxBits >> i) & 1; // 1 sib goes LEFT
            cur = left ? await hash2(sib, cur) : await hash2(cur, sib);
        }
        return cur;
    }

    before(async () => {
        const wrapper = writeMerkleWrapper(LEVELS);
        merkleCircuit = await wasm_tester(wrapper);
        hash2Circuit = await compileHash2Helper();
    });

    it(`computes the same root as JS for LEVELS=${LEVELS}`, async () => {
        const expected = await computeMerkleRootJS(leaf, pathElements, pathIndices);

        const witness = await merkleCircuit.calculateWitness(
            { leaf, pathElements, pathIndices: pathIndices.toString() },
            true
        );
        await merkleCircuit.checkConstraints(witness);

        const root = await readOut(merkleCircuit, witness, "root"); // NOTE: no "main."
        expect(root).to.equal(expected);
    });

    it("flipping any single path bit changes the root", async () => {
        // baseline
        const wBase = await merkleCircuit.calculateWitness(
            { leaf, pathElements, pathIndices: pathIndices.toString() }, true
        );
        await merkleCircuit.checkConstraints(wBase);
        const rBase = await readOut(merkleCircuit, wBase, "root");

        // change root
        for (let i = 0; i < LEVELS; i++) {
            const flipped = pathIndices ^ (1 << i);
            const wFlip = await merkleCircuit.calculateWitness(
                { leaf, pathElements, pathIndices: flipped.toString() }, true
            );
            await merkleCircuit.checkConstraints(wFlip);
            const rFlip = await readOut(merkleCircuit, wFlip, "root");
            expect(rFlip, `bit ${i} flip should change the root`).to.not.equal(rBase);
        }
    });
});
