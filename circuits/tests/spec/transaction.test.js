// circuits/tests/spec/transaction.test.js
const { expect } = require("chai");
const path = require("path");
const fs = require("fs");
const os = require("os");
const { wasm: wasm_tester } = require("circom_tester");

describe("Transaction(levels=5, nIns=2, nOuts=2) — circuits/src", function () {
    const CIRCUITS_SRC = path.resolve(__dirname, "../../src");
    const TRANSACTION_CIRCUIT = path.join(CIRCUITS_SRC, "transaction.circom");
    const POSEIDON2_HASH_CIRCUIT = path.join(CIRCUITS_SRC, "poseidon2", "poseidon2_hash.circom");
    const KEYPAIR_CIRCUIT = path.join(CIRCUITS_SRC, "keypair.circom");

    // Same params as transaction2.circom (main)
    const LEVELS = 5;
    const N_INS = 2;
    const N_OUTS = 2;
    const ZEROLEAF = "11850551329423159860688778991827824730037759162201783566284850822760196767874";

    let txCircuit;
    let hash2Circuit;
    let hash3Circuit;
    let keypairCircuit;
    let signatureCircuit;

    function writeTransactionWrapper() {
        const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tx-wrapper-"));
        const file = path.join(tmpDir, `Transaction_${LEVELS}_${N_INS}_${N_OUTS}.circom`);
        const content = `pragma circom 2.2.0;
include "${TRANSACTION_CIRCUIT.replace(/\\/g, "/")}";
component main = Transaction(${LEVELS}, ${N_INS}, ${N_OUTS}, ${ZEROLEAF});`;
        fs.writeFileSync(file, content);
        return file;
    }

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

    async function compileHash3Helper() {
        const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "hash3-"));
        const file = path.join(tmpDir, `Hash3.circom`);
        const content = `pragma circom 2.2.0;
include "${POSEIDON2_HASH_CIRCUIT.replace(/\\/g, "/")}";
template Hash3() {
  signal input a; signal input b; signal input c; signal output out;
  component h = Poseidon2(3);
  h.inputs[0] <== a;
  h.inputs[1] <== b;
  h.inputs[2] <== c;
  out <== h.out;
}
component main = Hash3();`;
        fs.writeFileSync(file, content);
        return await wasm_tester(file);
    }

    async function compileKeypairHelper() {
        const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "keypair-"));
        const file = path.join(tmpDir, `KeypairExpose.circom`);
        const content = `pragma circom 2.2.0;
include "${KEYPAIR_CIRCUIT.replace(/\\/g, "/")}";
template KeypairExpose() {
  signal input sk;  // private key
  signal output pk; // public key
  component k = Keypair();
  k.privateKey <== sk;
  pk <== k.publicKey;
}
component main = KeypairExpose();`;
        fs.writeFileSync(file, content);
        return await wasm_tester(file);
    }

    async function compileSignatureHelper() {
        const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sig-"));
        const file = path.join(tmpDir, `SignatureExpose.circom`);
        const content = `pragma circom 2.2.0;
include "${KEYPAIR_CIRCUIT.replace(/\\/g, "/")}";
template SignatureExpose() {
  signal input sk;
  signal input commitment;
  signal input merklePath; // pathIndices
  signal output sig;
  component s = Signature();
  s.privateKey <== sk;
  s.commitment <== commitment;
  s.merklePath <== merklePath;
  sig <== s.out;
}
component main = SignatureExpose();`;
        fs.writeFileSync(file, content);
        return await wasm_tester(file);
    }

    // Read a single named output
    async function readOut(circuit, witness, name) {
        const out = await circuit.getOutput(witness, { [name]: 1 });
        const value = out[name];
        return value.toString();
    }

    async function poseidon2_3(a, b, c) {
        const w = await hash3Circuit.calculateWitness(
            { a: a.toString(), b: b.toString(), c: c.toString() }, true
        );
        await hash3Circuit.checkConstraints(w);
        return await readOut(hash3Circuit, w, "out");
    }
    async function pubkeyFrom(sk) {
        const w = await keypairCircuit.calculateWitness({ sk: sk.toString() }, true);
        await keypairCircuit.checkConstraints(w);
        return await readOut(keypairCircuit, w, "pk");
    }
    async function signatureOf(sk, commitment, merklePath) {
        const w = await signatureCircuit.calculateWitness(
            { sk: sk.toString(), commitment: commitment.toString(), merklePath: merklePath.toString() }, true
        );
        await signatureCircuit.checkConstraints(w);
        return await readOut(signatureCircuit, w, "sig");
    }

    before(async () => {
        const wrapper = writeTransactionWrapper();
        txCircuit = await wasm_tester(wrapper);
        hash2Circuit = await compileHash2Helper();
        hash3Circuit = await compileHash3Helper();
        keypairCircuit = await compileKeypairHelper();
        signatureCircuit = await compileSignatureHelper();
    });

    it("accepts a valid zero-input (deposit-style) transaction", async () => {
        // Inputs (2 inputs, both with amount 0 so Merkle root check is gated off)
        const inAmount = ["0", "0"];
        const inPrivateKey = ["123", "456"];
        const inBlinding  = ["111", "222"];
        const inPathIndices = ["1", "6"];      // arbitrary
        const inPathElements = [
            Array(LEVELS).fill("10"),            // arbitrary elements (unused since amount=0)
            Array(LEVELS).fill("20")
        ];

        // Compute input commitments, signatures, and nullifiers
        const inPub0 = await pubkeyFrom(inPrivateKey[0]);
        const inPub1 = await pubkeyFrom(inPrivateKey[1]);

        const inCommit0 = await poseidon2_3(inAmount[0], inPub0, inBlinding[0]);
        const inCommit1 = await poseidon2_3(inAmount[1], inPub1, inBlinding[1]);

        const sig0 = await signatureOf(inPrivateKey[0], inCommit0, inPathIndices[0]);
        const sig1 = await signatureOf(inPrivateKey[1], inCommit1, inPathIndices[1]);

        const inputNullifier = [
            await poseidon2_3(inCommit0, inPathIndices[0], sig0),
            await poseidon2_3(inCommit1, inPathIndices[1], sig1)
        ];

        // Outputs (2 outputs)
        const outAmount = ["5", "7"];
        const outPrivForRecipients = ["7777", "8888"];
        const outPubkey = [
            await pubkeyFrom(outPrivForRecipients[0]),
            await pubkeyFrom(outPrivForRecipients[1]),
        ];
        const outBlinding = ["333", "444"];
        const outputCommitment = [
            await poseidon2_3(outAmount[0], outPubkey[0], outBlinding[0]),
            await poseidon2_3(outAmount[1], outPubkey[1], outBlinding[1]),
        ];

        // Public values
        const publicAmount = (BigInt(outAmount[0]) + BigInt(outAmount[1])).toString(); // sumIns(=0) + publicAmount == sumOuts
        const extDataHash = "999";
        const root = "123456789";   // arbitrary since inputs have amount=0 (gates the root check)

        const witness = await txCircuit.calculateWitness(
            {
                root,
                publicAmount,
                extDataHash,
                inputNullifier,
                inAmount,
                inPrivateKey,
                inBlinding,
                inPathIndices,
                inPathElements,
                outputCommitment,
                outAmount,
                outPubkey,
                outBlinding
            },
            true
        );

        await txCircuit.checkConstraints(witness);
    });

    it("rejects duplicate nullifiers (double-spend)", async () => {
        // force duplicate nullifiers
        const inAmount = ["0", "0"];
        const inPrivateKey = ["101", "202"];
        const inBlinding  = ["1", "2"];
        const inPathIndices = ["3", "4"];
        const inPathElements = [Array(LEVELS).fill("0"), Array(LEVELS).fill("0")];

        // make both inputs produce the SAME nullifier: just compute one and reuse it
        const pk0 = await pubkeyFrom(inPrivateKey[0]);
        const commit0 = await poseidon2_3(inAmount[0], pk0, inBlinding[0]);
        const sig0 = await signatureOf(inPrivateKey[0], commit0, inPathIndices[0]);
        const dupNull = await poseidon2_3(commit0, inPathIndices[0], sig0);

        const inputNullifier = [dupNull, dupNull];

        const outAmount = ["1", "2"];
        const outPubkey = ["11", "22"];
        const outBlinding = ["33", "44"];
        const outputCommitment = [
            await poseidon2_3(outAmount[0], outPubkey[0], outBlinding[0]),
            await poseidon2_3(outAmount[1], outPubkey[1], outBlinding[1]),
        ];

        const publicAmount = "3";
        const extDataHash = "7";
        const root = "0";

        const calc = () =>
            txCircuit.calculateWitness(
                {
                    root,
                    publicAmount,
                    extDataHash,
                    inputNullifier,
                    inAmount,
                    inPrivateKey,
                    inBlinding,
                    inPathIndices,
                    inPathElements,
                    outputCommitment,
                    outAmount,
                    outPubkey,
                    outBlinding
                },
                true
            ).then(w => txCircuit.checkConstraints(w));

        let failed = false;
        try { await calc(); } catch (e) { failed = true; }
        expect(failed, "constraints should fail due to duplicate nullifiers").to.equal(true);
    });

    it("rejects amount imbalance (sumIns + publicAmount !== sumOuts)", async () => {
        const inAmount = ["0", "0"];
        const inPrivateKey = ["1", "2"];
        const inBlinding  = ["3", "4"];
        const inPathIndices = ["0", "1"];
        const inPathElements = [Array(LEVELS).fill("0"), Array(LEVELS).fill("0")];

        const pk0 = await pubkeyFrom(inPrivateKey[0]);
        const pk1 = await pubkeyFrom(inPrivateKey[1]);
        const c0 = await poseidon2_3(inAmount[0], pk0, inBlinding[0]);
        const c1 = await poseidon2_3(inAmount[1], pk1, inBlinding[1]);
        const s0 = await signatureOf(inPrivateKey[0], c0, inPathIndices[0]);
        const s1 = await signatureOf(inPrivateKey[1], c1, inPathIndices[1]);

        const inputNullifier = [
            await poseidon2_3(c0, inPathIndices[0], s0),
            await poseidon2_3(c1, inPathIndices[1], s1),
        ];

        const outAmount = ["5", "7"];          // sumOuts = 12
        const outPubkey = ["9", "10"];
        const outBlinding = ["11", "12"];
        const outputCommitment = [
            await poseidon2_3(outAmount[0], outPubkey[0], outBlinding[0]),
            await poseidon2_3(outAmount[1], outPubkey[1], outBlinding[1]),
        ];

        const publicAmount = "11";             // WRONG: sumIns(0) + 11 != 12
        const extDataHash = "1";
        const root = "0";

        const calc = () =>
            txCircuit.calculateWitness(
                {
                    root,
                    publicAmount,
                    extDataHash,
                    inputNullifier,
                    inAmount,
                    inPrivateKey,
                    inBlinding,
                    inPathIndices,
                    inPathElements,
                    outputCommitment,
                    outAmount,
                    outPubkey,
                    outBlinding
                },
                true
            ).then(w => txCircuit.checkConstraints(w));

        let failed = false;
        try { await calc(); } catch (e) { failed = true; }
        expect(failed, "constraints should fail due to amount imbalance").to.equal(true);
    });

    it("rejects outputs whose amount does not fit in 248 bits", async () => {
        const twoPow248 = (1n << 248n).toString();  // 2^248 (one bit too large)
        const inAmount = ["0", "0"];
        const inPrivateKey = ["7", "8"];
        const inBlinding  = ["9", "10"];
        const inPathIndices = ["0", "0"];
        const inPathElements = [Array(LEVELS).fill("0"), Array(LEVELS).fill("0")];

        const pk0 = await pubkeyFrom(inPrivateKey[0]);
        const pk1 = await pubkeyFrom(inPrivateKey[1]);
        const c0 = await poseidon2_3(inAmount[0], pk0, inBlinding[0]);
        const c1 = await poseidon2_3(inAmount[1], pk1, inBlinding[1]);
        const s0 = await signatureOf(inPrivateKey[0], c0, inPathIndices[0]);
        const s1 = await signatureOf(inPrivateKey[1], c1, inPathIndices[1]);

        const inputNullifier = [
            await poseidon2_3(c0, inPathIndices[0], s0),
            await poseidon2_3(c1, inPathIndices[1], s1),
        ];

        // one output deliberately overflows 248 bits
        const outAmount = [twoPow248, "1"];
        const outPubkey = ["1234", "5678"];
        const outBlinding = ["11", "22"];
        const outputCommitment = [
            await poseidon2_3(outAmount[0], outPubkey[0], outBlinding[0]),
            await poseidon2_3(outAmount[1], outPubkey[1], outBlinding[1]),
        ];

        const publicAmount = (BigInt(outAmount[0]) + 1n).toString(); // balance (sumIns=0)
        const extDataHash = "0";
        const root = "0";

        const calc = () =>
            txCircuit.calculateWitness(
                {
                    root,
                    publicAmount,
                    extDataHash,
                    inputNullifier,
                    inAmount,
                    inPrivateKey,
                    inBlinding,
                    inPathIndices,
                    inPathElements,
                    outputCommitment,
                    outAmount,
                    outPubkey,
                    outBlinding
                },
                true
            ).then(w => txCircuit.checkConstraints(w));

        let failed = false;
        try { await calc(); } catch (e) { failed = true; }
        expect(failed, "Num2Bits(248) should fail for outAmount >= 2^248").to.equal(true);
    });
});
