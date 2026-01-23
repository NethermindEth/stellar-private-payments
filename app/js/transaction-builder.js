/**
 * Transaction Builder
 *
 * Builds circuit inputs for the pool's `transact` method.
 * All transaction types (deposit, withdraw, transfer) use the same circuit and contract method,
 * differing only in how inputs are constructed:
 *
 * - Deposit: ext_amount > 0
 * - Withdraw: ext_amount < 0 recipient receives tokens
 * - Transfer: ext_amount = 0. Notes go to recipient
 *
 * @module transaction-builder
 */

import { keccak_256 } from '@noble/hashes/sha3';
import { Address, XdrLargeInt, xdr } from '@stellar/stellar-sdk';
import {
    derivePublicKey,
    computeCommitment,
    computeSignature,
    computeNullifier,
    createMerkleTreeWithZeroLeaf,
    bigintToField,
    hexToField,
    fieldToHex,
    poseidon2Hash2,
    encryptNoteData,
    deriveEncryptionKeypairFromSignature,
    WasmSparseMerkleTree,
    generateBlinding,
} from './bridge.js';
import * as ProverClient from './prover-client.js';

// Circuit constants to match compliant_test.circom parameters
const LEVELS = 5;
const SMT_LEVELS = 5;
const BN256_MOD = BigInt('0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001');
const ZERO_LEAF_HEX = '0x25302288db99350344974183ce310d63b53abb9ef0f8575753eed36e0118f9ce';

/**
 * Converts a signed amount to its field element representation (U256).
 * For positive values, returns the value directly.
 * For negative values, returns FIELD_SIZE - |value|
 * @param {bigint} amount - The signed amount
 * @returns {bigint} The field element representation
 */
function toFieldElement(amount) {
    if (amount >= 0n) {
        return amount;
    }
    // Negative = BN256_MOD - |amount|
    return BN256_MOD + amount;
}

/**
 * Converts bytes to little-endian BigInt.
 * @param {Uint8Array} bytes
 * @returns {bigint}
 */
function bytesToBigIntLE(bytes) {
    let result = 0n;
    for (let i = bytes.length - 1; i >= 0; i--) {
        result = (result << 8n) | BigInt(bytes[i]);
    }
    return result;
}

/**
 * Converts bytes to big-endian BigInt.
 * @param {Uint8Array} bytes
 * @returns {bigint}
 */
function bytesToBigIntBE(bytes) {
    let result = 0n;
    for (let i = 0; i < bytes.length; i++) {
        result = (result << 8n) | BigInt(bytes[i]);
    }
    return result;
}

/**
 * Converts BigInt to big-endian bytes.
 * @param {bigint} value
 * @param {number} length
 * @returns {Uint8Array}
 */
function bigIntToBytesBE(value, length = 32) {
    let hex = value.toString(16);
    if (hex.length > length * 2) {
        throw new Error('Value exceeds byte length');
    }
    hex = hex.padStart(length * 2, '0');
    const out = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
        out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
}

/**
 * Converts BigInt to little-endian bytes.
 * @param {bigint} value
 * @param {number} length
 * @returns {Uint8Array}
 */
function bigIntToBytesLE(value, length = 32) {
    const out = new Uint8Array(length);
    let v = value;
    for (let i = 0; i < length; i++) {
        out[i] = Number(v & 0xffn);
        v >>= 8n;
    }
    return out;
}

/**
 * Converts bytes to BigInt string (little-endian).
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function bytesToBigIntStringLE(bytes) {
    return bytesToBigIntLE(bytes).toString();
}

/**
 * Slices field elements from a byte array.
 * @param {Uint8Array} bytes
 * @param {number} count
 * @returns {string[]}
 */
function sliceFieldElements(bytes, count) {
    const out = [];
    for (let i = 0; i < count; i++) {
        const start = i * 32;
        const chunk = bytes.slice(start, start + 32);
        out.push(bytesToBigIntStringLE(chunk));
    }
    return out;
}

/**
 * Computes keccak256 hash. Used for extDataHash computation
 * @param {Uint8Array} bytes
 * @returns {Uint8Array}
 */
function keccak256(bytes) {
    const msg = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    return keccak_256(msg);
}

/**
 * Computes the extDataHash for circuit verification.
 * ExtData is a Soroban struct that must be serialized in a specific order.
 *
 * @param {Object} extData
 * @param {string} extData.recipient - Stellar address
 * @param {bigint} extData.ext_amount - Public amount
 * @param {bigint} [extData.fee=0n] - Relayer fee
 * @param {Uint8Array} extData.encrypted_output0 - Encrypted note data for output 0
 * @param {Uint8Array} extData.encrypted_output1 - Encrypted note data for output 1
 * @returns {{bigInt: bigint, bytes: Uint8Array}}
 */
export function hashExtData(extData) {
    // Fields must match contract's ExtData struct exactly:
    // - encrypted_output0: Bytes
    // - encrypted_output1: Bytes
    // - ext_amount: I256
    // - recipient: Address
    const entries = [
        {
            key: 'encrypted_output0',
            val: xdr.ScVal.scvBytes(extData.encrypted_output0),
        },
        {
            key: 'encrypted_output1',
            val: xdr.ScVal.scvBytes(extData.encrypted_output1),
        },
        {
            key: 'ext_amount',
            val: new XdrLargeInt('i256', extData.ext_amount.toString()).toScVal(),
        },
        {
            key: 'recipient',
            val: Address.fromString(extData.recipient).toScVal(),
        },
    ];

    // Sort alphabetically by key (Soroban XDR serialization order)
    entries.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));

    const scEntries = entries.map(
        (entry) =>
            new xdr.ScMapEntry({
                key: xdr.ScVal.scvSymbol(entry.key),
                val: entry.val,
            })
    );
    const scVal = xdr.ScVal.scvMap(scEntries);
    const xdrRaw = scVal.toXDR();
    const xdrBytes = xdrRaw instanceof Uint8Array ? xdrRaw : new Uint8Array(xdrRaw);

    // Debug logging
    console.log('[hashExtData] Input:', {
        recipient: extData.recipient,
        ext_amount: extData.ext_amount.toString(),
        encrypted_output0_len: extData.encrypted_output0?.length,
        encrypted_output1_len: extData.encrypted_output1?.length,
    });
    console.log('[hashExtData] XDR bytes length:', xdrBytes.length);

    const digest = keccak256(xdrBytes);
    const digestBig = bytesToBigIntBE(digest);
    const reduced = digestBig % BN256_MOD;

    console.log('[hashExtData] Hash (hex):', reduced.toString(16).padStart(64, '0'));

    return {
        bigInt: reduced,
        bytes: bigIntToBytesBE(reduced, 32),
    };
}

/**
 * Creates a dummy input note
 *
 * @param {Uint8Array} privKeyBytes - User's private key
 * @param {Uint8Array} pubKeyBytes - User's public key
 * @param {bigint} blinding - Blinding factor
 * @returns {Object} Input note data
 */
function createDummyInput(privKeyBytes, pubKeyBytes, blinding) {
    const amount = 0n;
    const amountBytes = bigintToField(amount);
    const blindingBytes = bigintToField(blinding);
    const pathIndicesBytes = bigintToField(0n);

    const commitment = computeCommitment(amountBytes, pubKeyBytes, blindingBytes);
    const signature = computeSignature(privKeyBytes, commitment, pathIndicesBytes);
    const nullifier = computeNullifier(commitment, pathIndicesBytes, signature);

    return {
        amount,
        blinding,
        blindingBytes,
        commitmentBytes: commitment,
        nullifierBytes: nullifier,
        nullifierBig: bytesToBigIntLE(nullifier),
        pathIndices: '0',
        pathElements: Array(LEVELS).fill('0'),
        isDummy: true,
    };
}

/**
 * Creates a real input note from an existing note with its merkle proof.
 * Used for withdrawals and transfers where the user spends existing notes.
 *
 * @param {Uint8Array} privKeyBytes - User's private key (32 bytes)
 * @param {Uint8Array} pubKeyBytes - User's public key (32 bytes)
 * @param {Object} note - Note data from storage
 * @param {bigint} note.amount - Note amount
 * @param {bigint} note.blinding - Note blinding factor
 * @param {number} note.leafIndex - Index in pool merkle tree
 * @param {Object} merkleProof - Merkle proof from pool store
 * @param {Uint8Array} merkleProof.path_elements - Sibling hashes (concatenated)
 * @param {Uint8Array} merkleProof.path_indices - Path indices as bits
 * @returns {Object} Input note data ready for circuit
 */
function createRealInput(privKeyBytes, pubKeyBytes, note, merkleProof) {
    const amount = BigInt(note.amount);
    const blinding = BigInt(note.blinding);
    const leafIndex = note.leafIndex;
    
    const amountBytes = bigintToField(amount);
    const blindingBytes = bigintToField(blinding);
    
    // Compute commitment: poseidon2(amount, pubKey, blinding)
    const commitment = computeCommitment(amountBytes, pubKeyBytes, blindingBytes);
    
    // Path indices as BigInt for nullifier computation
    const pathIndicesBytes = merkleProof.path_indices;
    const pathIndicesBigInt = bytesToBigIntLE(pathIndicesBytes);
    
    // Compute signature: poseidon2(privKey, commitment, pathIndices, domain=0x04)
    const signature = computeSignature(privKeyBytes, commitment, pathIndicesBytes);
    
    // Compute nullifier: poseidon2(commitment, pathIndices, signature, domain=0x05)
    const nullifier = computeNullifier(commitment, pathIndicesBytes, signature);
    
    // Parse merkle proof elements
    const pathElements = sliceFieldElements(merkleProof.path_elements, LEVELS);
    const pathIndicesStr = pathIndicesBigInt.toString();
    
    console.log(`[TxBuilder] Created real input: amount=${amount}, leafIndex=${leafIndex}`);
    
    return {
        amount,
        blinding,
        blindingBytes,
        commitmentBytes: commitment,
        nullifierBytes: nullifier,
        nullifierBig: bytesToBigIntLE(nullifier),
        pathIndices: pathIndicesStr,
        pathElements,
        leafIndex,
        isDummy: false,
    };
}

/**
 * Creates an output note.
 *
 * @param {bigint} amount - Note amount
 * @param {Uint8Array} pubKeyBytes - Recipient's public key
 * @param {bigint} blinding - Blinding factor
 * @returns {Object} Output note data
 */
function createOutput(amount, pubKeyBytes, blinding) {
    const amountBytes = bigintToField(amount);
    const blindingBytes = bigintToField(blinding);
    const commitment = computeCommitment(amountBytes, pubKeyBytes, blindingBytes);

    return {
        amount,
        blinding,
        blindingBytes,
        pubKeyBytes,
        commitmentBytes: commitment,
        commitmentBig: bytesToBigIntLE(commitment),
    };
}

/**
 * Builds membership proof data for circuit inputs.
 * 
 * Automatically finds the user's leaf index in the synced ASP membership tree.
 * Falls back to building a local tree for testing if not synced.
 *
 * @param {Uint8Array} pubKeyBytes - User's public key
 * @param {bigint} membershipRoot - Expected on-chain membership root
 * @param {number} leafIndexHint - Hint for leaf index (used if auto-detection fails)
 * @param {bigint} membershipBlinding - Blinding used when the leaf was added to the tree
 * @param {Object} [stateManager] - StateManager instance for getting real proofs
 * @returns {Promise<Object>} Membership proof data
 */
async function buildMembershipProofData(pubKeyBytes, membershipRoot, leafIndexHint = 0, membershipBlinding = 0n, stateManager = null) {
    // Membership leaf = poseidon2(pubKey, blinding, domain=1)
    const membershipBlindingBytes = bigintToField(membershipBlinding);
    const membershipLeaf = poseidon2Hash2(pubKeyBytes, membershipBlindingBytes, 1);
    const leafHex = fieldToHex(membershipLeaf);

    // Try to find the user's leaf in the synced membership tree
    let leafIndex = leafIndexHint;
    if (stateManager) {
        try {
            const foundLeaf = await stateManager.findASPMembershipLeaf(leafHex);
            if (foundLeaf) {
                leafIndex = foundLeaf.index;
                console.log(`[TxBuilder] Found user's membership leaf at index ${leafIndex}`);
            } else {
                const leafCount = await stateManager.getASPMembershipLeafCount();
                console.warn(`[TxBuilder] User's membership leaf not found in synced tree (${leafCount} leaves synced)`);
                console.warn(`[TxBuilder] Using hint index: ${leafIndexHint}`);
            }
        } catch (e) {
            console.warn('[TxBuilder] Error searching for membership leaf:', e.message);
        }
    }

    // Try to get proof from synced StateManager
    if (stateManager) {
        const syncedProof = await stateManager.getASPMembershipProof(leafIndex);
        console.log('[TxBuilder] Synced proof from StateManager:', syncedProof ? 'found' : 'null');
        if (syncedProof) {
            const syncedRoot = bytesToBigIntLE(syncedProof.root);
            console.log('[TxBuilder] Membership root comparison:', {
                syncedRoot: syncedRoot.toString(16),
                expectedRoot: membershipRoot.toString(16),
                match: syncedRoot === membershipRoot,
            });
            if (syncedRoot === membershipRoot) {
                console.log('[TxBuilder] Using synced ASP membership proof');
                const pathElements = sliceFieldElements(syncedProof.path_elements, LEVELS);
                const pathIndices = bytesToBigIntStringLE(syncedProof.path_indices);
                console.log('[TxBuilder] Membership proof details:', {
                    leaf: bytesToBigIntStringLE(membershipLeaf),
                    blinding: membershipBlinding.toString(),
                    pathIndicesLength: pathIndices.length,
                    pathElementsLength: pathElements.length,
                });
                return {
                    leaf: bytesToBigIntStringLE(membershipLeaf),
                    blinding: membershipBlinding.toString(),
                    pathIndices,
                    pathElements,
                    root: syncedRoot.toString(),
                };
            } else {
                console.warn('[TxBuilder] Synced membership root mismatch, will use fallback');
            }
        }
    }

    // Fallback: Build local membership tree (for testing or when not synced)
    // This will only work if the on-chain tree has ONLY this user's leaf at the specified index
    console.warn('[TxBuilder] Building local membership tree - ensure ASP membership is synced for production');
    const zeroLeaf = hexToField(ZERO_LEAF_HEX);
    const membershipTree = createMerkleTreeWithZeroLeaf(LEVELS, zeroLeaf);
    const totalLeaves = 1 << LEVELS;

    // Insert leaves in order, placing the actual leaf at the correct index
    for (let i = 0; i < totalLeaves; i++) {
        membershipTree.insert(i === leafIndex ? membershipLeaf : zeroLeaf);
    }

    const membershipProof = membershipTree.get_proof(leafIndex);
    const membershipRootBytes = membershipTree.root();
    const computedRoot = bytesToBigIntLE(membershipRootBytes);

    if (computedRoot !== membershipRoot) {
        console.warn('[TxBuilder] Membership root mismatch:', {
            computed: computedRoot.toString(16),
            expected: membershipRoot.toString(16),
            userLeaf: leafHex,
            leafIndex,
        });
        console.warn('[TxBuilder] This likely means:');
        console.warn('  1. ASP membership tree is not synced, OR');
        console.warn('  2. Wrong blinding factor provided');
    }

    const pathElements = sliceFieldElements(membershipProof.path_elements, LEVELS);
    const pathIndices = bytesToBigIntStringLE(membershipProof.path_indices);

    return {
        leaf: bytesToBigIntStringLE(membershipLeaf),
        blinding: membershipBlinding.toString(),
        pathIndices,
        pathElements,
        root: computedRoot.toString(),
    };
}

/**
 * Builds non-membership proof data from StateManager.
 * If the non-membership tree is empty (root = 0), returns a default empty proof.
 *
 * @param {Uint8Array} pubKeyBytes - User's public key
 * @param {Object} stateManager - StateManager instance
 * @param {bigint} nonMembershipRoot - Expected non-membership root from on-chain state
 * @returns {Promise<Object>} Non-membership proof data
 */
async function buildNonMembershipProofDataFromChain(pubKeyBytes, stateManager, nonMembershipRoot) {
    // Handle empty tree case (root = 0)
    if (nonMembershipRoot === 0n || nonMembershipRoot === BigInt(0)) {
        console.log('[TxBuilder] Non-membership tree is empty (root=0), using empty proof');
        // For empty SMT, non-membership is trivially provable
        // Return dummy proof that satisfies circuit constraints for empty tree
        return {
            key: bytesToBigIntStringLE(pubKeyBytes),
            oldKey: '0',
            oldValue: '0',
            isOld0: '1', // Empty branch
            siblings: Array(SMT_LEVELS).fill('0'),
            root: '0',
        };
    }

    const result = await stateManager.getASPNonMembershipProof(pubKeyBytes);

    if (!result.success) {
        throw new Error(`Failed to get non-membership proof: ${result.error}`);
    }

    if (result.keyExists) {
        throw new Error('Key exists in non-membership tree (user is sanctioned)');
    }

    const proof = result.proof;
    
    // Convert siblings and ensure correct length for circuit
    let siblings = (proof.siblings || []).map(s => 
        s instanceof Uint8Array ? bytesToBigIntStringLE(s) : s.toString()
    );
    
    // Pad or trim siblings to match SMT_LEVELS
    if (siblings.length < SMT_LEVELS) {
        siblings = [...siblings, ...Array(SMT_LEVELS - siblings.length).fill('0')];
    } else if (siblings.length > SMT_LEVELS) {
        console.warn(`[TxBuilder] Non-membership proof has ${siblings.length} siblings, trimming to ${SMT_LEVELS}`);
        siblings = siblings.slice(0, SMT_LEVELS);
    }
    
    return {
        key: bytesToBigIntStringLE(pubKeyBytes),
        oldKey: proof.notFoundKey ? bytesToBigIntStringLE(proof.notFoundKey) : '0',
        oldValue: proof.notFoundValue ? bytesToBigIntStringLE(proof.notFoundValue) : '0',
        isOld0: proof.isOld0 ? '1' : '0',
        siblings,
        root: bytesToBigIntStringLE(proof.root),
    };
}


/**
 * Encrypts output notes for on-chain storage.
 * The encrypted data allows recipients to scan and decrypt notes addressed to them.
 *
 * @param {Object} outputNote - Output note with amount, blinding, pubKeyBytes
 * @param {Uint8Array} encryptionPubKey - Recipient's X25519 encryption public key
 * @returns {Uint8Array} Encrypted note data (112 bytes)
 */
function encryptOutput(outputNote, encryptionPubKey) {
    return encryptNoteData(encryptionPubKey, {
        amount: outputNote.amount,
        blinding: outputNote.blindingBytes,
    });
}

/**
 * Builds circuit inputs for a transaction.
 *
 * @param {Object} params
 * @param {Uint8Array} params.privKeyBytes - User's BN254 private key (for spending)
 * @param {Uint8Array} params.encryptionPubKey - User's X25519 public key (for note encryption)
 * @param {bigint} params.poolRoot - Current pool merkle root (on-chain)
 * @param {bigint} params.membershipRoot - ASP membership root (on-chain)
 * @param {bigint} params.nonMembershipRoot - ASP non-membership root (on-chain)
 * @param {Array<{amount: bigint, blinding: bigint}>} params.inputs - Input notes (use [] for deposits)
 * @param {Array<{amount: bigint, blinding: bigint, recipientPubKey?: Uint8Array}>} params.outputs - Output notes
 * @param {Object} params.extData - External data (recipient, ext_amount, fee)
 * @param {Object} [params.stateManager] - StateManager for on-chain proofs
 * @param {number} [params.membershipLeafIndex=0] - User's leaf index in membership tree
 * @param {bigint} [params.membershipBlinding=0n] - Blinding used when user was added to membership tree
 * @returns {Promise<Object>} Circuit inputs and metadata
 */
export async function buildTransactionInputs(params) {
    const {
        privKeyBytes,
        encryptionPubKey,
        poolRoot,
        membershipRoot,
        nonMembershipRoot,
        inputs = [],
        outputs,
        extData,
        stateManager,
        membershipLeafIndex = 0,
        membershipBlinding = 0n,
    } = params;

    // Derive public key
    const pubKeyBytes = derivePublicKey(privKeyBytes);
    const privKeyBigInt = bytesToBigIntLE(privKeyBytes);

    // Create input notes
    const inputNotes = [];
    if (inputs.length === 0) {
        // 2 dummy inputs, each one with separate blindings
        const blinding1 = bytesToBigIntLE(generateBlinding());
        const blinding2 = bytesToBigIntLE(generateBlinding());
        inputNotes.push(createDummyInput(privKeyBytes, pubKeyBytes, blinding1));
        inputNotes.push(createDummyInput(privKeyBytes, pubKeyBytes, blinding2));
    } else {
        // Withdrawal/Transfer: spending real inputs from existing notes
        for (const input of inputs) {
            if (!input.merkleProof) {
                throw new Error(`Input note at index ${input.leafIndex} is missing merkle proof`);
            }
            const realInput = createRealInput(privKeyBytes, pubKeyBytes, input, input.merkleProof);
            inputNotes.push(realInput);
        }
        
        // Pad to 2 inputs if only 1 provided. As circuit requires exactly 2 inputs
        while (inputNotes.length < 2) {
            const dummyBlinding = BigInt(Date.now() + inputNotes.length);
            inputNotes.push(createDummyInput(privKeyBytes, pubKeyBytes, dummyBlinding));
        }
    }

    // Create output notes
    const outputNotes = outputs.map((out) => {
        const recipientPubKey = out.recipientPubKey || pubKeyBytes;
        return createOutput(out.amount, recipientPubKey, out.blinding);
    });

    // Ensure we have exactly 2 outputs (pad with dummy if needed)
    while (outputNotes.length < 2) {
        outputNotes.push(createOutput(0n, pubKeyBytes, BigInt(Date.now())));
    }

    // Encrypt output notes
    const encryptedOutput0 = encryptOutput(outputNotes[0], encryptionPubKey);
    const encryptedOutput1 = encryptOutput(outputNotes[1], encryptionPubKey);

    // Build complete ext_data with encrypted outputs
    const completeExtData = {
        ...extData,
        encrypted_output0: encryptedOutput0,
        encrypted_output1: encryptedOutput1,
    };

    // Build ext data hash
    const extDataHash = hashExtData(completeExtData);

    // Build membership proof
    const membershipProofData = await buildMembershipProofData(pubKeyBytes, membershipRoot, membershipLeafIndex, membershipBlinding, stateManager);

    // Build non-membership proof
    let nonMembershipProofData;
    if (stateManager) {
        nonMembershipProofData = await buildNonMembershipProofDataFromChain(pubKeyBytes, stateManager, nonMembershipRoot);
    } else {
        console.error('[TxBuilder] No state manager provided, skipping non-membership proof');
        throw new Error('[TxBuilder] No state manager provided. Unable to build non-membership proof.');
    }

    // Construct circuit inputs
    // publicAmount must be the field element representation
    // For negative ext_amount, this is FIELD_SIZE - |ext_amount|
    const publicAmountField = toFieldElement(extData.ext_amount);
    
    const circuitInputs = {
        // Public inputs
        root: poolRoot.toString(),
        publicAmount: publicAmountField.toString(),
        extDataHash: extDataHash.bigInt.toString(),
        inputNullifier: inputNotes.map((n) => n.nullifierBig.toString()),
        outputCommitment: outputNotes.map((n) => n.commitmentBig.toString()),

        // Private inputs: input notes
        inAmount: inputNotes.map((n) => n.amount.toString()),
        inPrivateKey: inputNotes.map(() => privKeyBigInt.toString()),
        inBlinding: inputNotes.map((n) => n.blinding.toString()),
        inPathIndices: inputNotes.map((n) => n.pathIndices),
        inPathElements: inputNotes.map((n) => n.pathElements),

        // Private inputs: output notes
        outAmount: outputNotes.map((n) => n.amount.toString()),
        outPubkey: outputNotes.map((n) => bytesToBigIntStringLE(n.pubKeyBytes)),
        outBlinding: outputNotes.map((n) => n.blinding.toString()),

        // ASP proofs
        membershipRoots: inputNotes.map(() => [membershipProofData.root]),
        nonMembershipRoots: inputNotes.map(() => [nonMembershipProofData.root]),
        membershipProofs: inputNotes.map(() => [membershipProofData]),
        nonMembershipProofs: inputNotes.map(() => [nonMembershipProofData]),
    };

    return {
        circuitInputs,
        inputNotes,
        outputNotes,
        extData: completeExtData,
        extDataHash,
    };
}

/**
 * Generates a proof for a transaction.
 *
 * @param {Object} params - Same as buildTransactionInputs
 * @param {Object} options
 * @param {function} options.onProgress - Progress callback
 * @returns {Promise<Object>} Proof result with Soroban-ready data
 */
export async function generateTransactionProof(params, options = {}) {
    const { onProgress } = options;

    // Ensure prover is initialized
    if (!ProverClient.isReady()) {
        onProgress?.({ phase: 'init', message: 'Initializing prover...' });
        await ProverClient.initializeProver({
            onProgress: (loaded, total, msg, pct) => {
                onProgress?.({ phase: 'download', loaded, total, message: msg, percent: pct });
            },
        });
    }

    // Build circuit inputs
    onProgress?.({ phase: 'build', message: 'Building circuit inputs...' });
    const { circuitInputs, inputNotes, outputNotes, extData, extDataHash } = await buildTransactionInputs(params);

    // Generate proof in Soroban format
    onProgress?.({ phase: 'prove', message: 'Generating ZK proof...' });
    
    const { proof, publicInputs, timings } = await ProverClient.prove(circuitInputs, {
        sorobanFormat: true,
    });
    

    // Parse proof bytes into Soroban structure
    const proofStruct = {
        a: proof.slice(0, 64),
        b: proof.slice(64, 64 + 128),
        c: proof.slice(64 + 128),
    };

    // Build Soroban-ready transaction data
    // Public_amount needs special handling for negative values
    const publicAmountField = toFieldElement(params.extData.ext_amount);
    
    const sorobanProof = {
        proof: proofStruct,
        root: params.poolRoot,
        input_nullifiers: inputNotes.map((n) => n.nullifierBig),
        output_commitment0: outputNotes[0].commitmentBig,
        output_commitment1: outputNotes[1].commitmentBig,
        public_amount: publicAmountField,
        ext_data_hash: extDataHash.bytes, // BE bytes (same as contract hash computation)
        asp_membership_root: params.membershipRoot,
        asp_non_membership_root: params.nonMembershipRoot,
    };

    return {
        proof: proofStruct,
        sorobanProof,
        proofBytes: proof,
        publicInputs,
        circuitInputs,
        inputNotes,
        outputNotes,
        extData,
        extDataHash,
        timings,
    };
}

/**
 * Convenience function for deposit transactions.
 *
 * @param {Object} params
 * @param {Uint8Array} params.privKeyBytes - User's BN254 private key
 * @param {Uint8Array} params.encryptionPubKey - User's X25519 public key
 * @param {bigint} params.poolRoot - Current pool root
 * @param {bigint} params.membershipRoot - ASP membership root
 * @param {bigint} params.nonMembershipRoot - ASP non-membership root
 * @param {bigint} params.amount - Total amount to deposit
 * @param {Array<{amount: bigint, blinding: bigint}>} params.outputs - Output distribution
 * @param {string} params.poolAddress - Pool contract address (recipient for ext_data)
 * @param {Object} [params.stateManager] - StateManager instance
 * @param {number} [params.membershipLeafIndex=0] - User's leaf index in membership tree
 * @param {bigint} [params.membershipBlinding=0n] - Blinding used when user was added to membership tree
 * @param {Object} options
 * @returns {Promise<Object>} Proof result
 */
export async function generateDepositProof(params, options = {}) {
    const { poolAddress, amount, outputs, ...rest } = params;

    return generateTransactionProof(
        {
            ...rest,
            inputs: [], // No inputs for deposit
            outputs,
            extData: {
                recipient: poolAddress,
                ext_amount: amount,
            },
        },
        options
    );
}

/**
 * Convenience function for withdrawal transactions.
 * Withdrawals spend input notes and send tokens to an external recipient.
 *
 * @param {Object} params
 * @param {Uint8Array} params.privKeyBytes - User's BN254 private key
 * @param {Uint8Array} params.encryptionPubKey - User's X25519 public key
 * @param {bigint} params.poolRoot - Current pool root
 * @param {bigint} params.membershipRoot - ASP membership root
 * @param {bigint} params.nonMembershipRoot - ASP non-membership root
 * @param {Array<Object>} params.inputNotes - Notes to spend (with merkleProof attached)
 * @param {string} params.recipient - Address to receive withdrawn tokens
 * @param {bigint} params.withdrawAmount - Amount to withdraw (must be <= sum of inputs)
 * @param {Array<{amount: bigint, blinding: bigint}>} [params.changeOutputs] - Change outputs (optional)
 * @param {Object} [params.stateManager] - StateManager instance
 * @param {number} [params.membershipLeafIndex=0] - User's leaf index in membership tree
 * @param {bigint} [params.membershipBlinding=0n] - Blinding used when user was added to membership tree
 * @param {Object} options
 * @returns {Promise<Object>} Proof result
 */
export async function generateWithdrawProof(params, options = {}) {
    const { inputNotes, recipient, withdrawAmount, changeOutputs = [], ...rest } = params;

    // Calculate total input amount
    const inputTotal = inputNotes.reduce((sum, n) => sum + BigInt(n.amount), 0n);
    const change = inputTotal - withdrawAmount;
    
    if (change < 0n) {
        throw new Error(`Insufficient input amount: have ${inputTotal}, need ${withdrawAmount}`);
    }

    // Build outputs: change goes back to self (or use provided changeOutputs)
    let outputs;
    if (changeOutputs.length > 0) {
        outputs = changeOutputs;
    } else {
        // Auto-generate change output
        outputs = [
            { amount: change, blinding: BigInt(Date.now()) },
            { amount: 0n, blinding: BigInt(Date.now() + 1) }, // Dummy second output
        ];
    }

    return generateTransactionProof(
        {
            ...rest,
            inputs: inputNotes,
            outputs,
            extData: {
                recipient,
                ext_amount: -withdrawAmount, // Negative = withdrawal
            },
        },
        options
    );
}

/**
 * Convenience function for transfer transactions.
 * Transfers move notes from one user to another without external token movement.
 *
 * @param {Object} params
 * @param {Uint8Array} params.privKeyBytes - Sender's BN254 private key
 * @param {Uint8Array} params.encryptionPubKey - Sender's X25519 public key
 * @param {Uint8Array} params.recipientPubKey - Recipient's BN254 public key
 * @param {Uint8Array} params.recipientEncryptionPubKey - Recipient's X25519 public key
 * @param {bigint} params.poolRoot - Current pool root
 * @param {bigint} params.membershipRoot - ASP membership root
 * @param {bigint} params.nonMembershipRoot - ASP non-membership root
 * @param {Array<Object>} params.inputNotes - Notes to spend (with merkleProof attached)
 * @param {Array<{amount: bigint, blinding: bigint}>} params.recipientOutputs - Outputs for recipient
 * @param {Array<{amount: bigint, blinding: bigint}>} [params.changeOutputs] - Change outputs for sender
 * @param {string} params.poolAddress - Pool contract address (for ext_data recipient)
 * @param {Object} [params.stateManager] - StateManager instance
 * @param {number} [params.membershipLeafIndex=0] - User's leaf index in membership tree
 * @param {bigint} [params.membershipBlinding=0n] - Blinding used when user was added to membership tree
 * @param {Object} options
 * @returns {Promise<Object>} Proof result
 */
export async function generateTransferProof(params, options = {}) {
    const { 
        inputNotes, 
        recipientPubKey,
        recipientEncryptionPubKey,
        recipientOutputs, 
        changeOutputs = [],
        poolAddress,
        ...rest 
    } = params;

    // Calculate totals
    const inputTotal = inputNotes.reduce((sum, n) => sum + BigInt(n.amount), 0n);
    const recipientTotal = recipientOutputs.reduce((sum, o) => sum + o.amount, 0n);
    const changeTotal = changeOutputs.reduce((sum, o) => sum + o.amount, 0n);
    
    if (inputTotal !== recipientTotal + changeTotal) {
        throw new Error(`Transfer amounts don't balance: inputs=${inputTotal}, outputs=${recipientTotal + changeTotal}`);
    }

    // Build outputs with recipient public keys
    const outputs = [
        ...recipientOutputs.map(o => ({
            ...o,
            recipientPubKey,
            recipientEncryptionPubKey,
        })),
        ...changeOutputs,
    ];
    
    // Ensure we have exactly 2 outputs
    while (outputs.length < 2) {
        outputs.push({ amount: 0n, blinding: BigInt(Date.now() + outputs.length) });
    }

    return generateTransactionProof(
        {
            ...rest,
            inputs: inputNotes,
            outputs,
            extData: {
                recipient: poolAddress,
                ext_amount: 0n, // Transfer: no external token movement
            },
        },
        options
    );
}

export default {
    hashExtData,
    buildTransactionInputs,
    generateTransactionProof,
    generateDepositProof,
    generateWithdrawProof,
    generateTransferProof,
};
