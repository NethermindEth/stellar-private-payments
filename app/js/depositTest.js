import { keccak_256 } from '@noble/hashes/sha3';
import { Address, XdrLargeInt, contract, xdr } from '@stellar/stellar-sdk';
import initProverModule, { WasmSparseMerkleTree } from './prover.js';
import {
  connectWallet as connectFreighter,
  getWalletNetwork,
  signWalletAuthEntry,
  signWalletTransaction,
} from './wallet.js';
import {
  initProver,
  isInitialized,
  derivePublicKey,
  computeCommitment,
  computeSignature,
  computeNullifier,
  createMerkleTree,
  bigintToField,
  hexToField,
  fieldToHex,
  poseidon2Hash2,
  generateWitness,
  generateProofBytes,
  proofBytesToUncompressed,
  verifyProofLocal,
  extractPublicInputs,
} from './bridge.js';

// Private key of the deployed leaf H(leaf || 0)
const PRIVATE_KEY_HEX = '0x3625edaf29a00f40abaf4eb6b423c103287e4bc06f46a41472f5b186e277ea51';
// the deployed leaf
const EXPECTED_MEMBERSHIP_LEAF = '0x1e844e1b3284abb5bdad20ba0707f4c4053b6740814eb888658eb177d18ca2b2';
const LEVELS = 5;
const SMT_LEVELS = 5;
const DEPOSIT_AMOUNT = 500000n;
const BN256_MOD = BigInt('0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001');
const ZERO_LEAF_HEX = '0x25302288db99350344974183ce310d63b53abb9ef0f8575753eed36e0118f9ce';
// Just used to check if the leaf deployed is the expected
const EXPECTED_MEMBERSHIP_ROOT_EMPTY = BigInt('0x19926faa23b0737d467f9476f0f84b2968ff6666e16a23e4d44898f884504764');
const EXPECTED_MEMBERSHIP_ROOT_WITH_LEAF = BigInt('0x111e35f8c229c85e124f5e5653f4501a93bb8fcf0a724a0d15d985772dffda9d');

const statusEl = document.getElementById('status');
const logEl = document.getElementById('log');
const contractsEl = document.getElementById('contracts');
const btnConnect = document.getElementById('btnConnect');
const btnSend = document.getElementById('btnSend');

const state = {
  address: null,
  networkPassphrase: null,
  rpcUrl: null,
  contracts: null,
  poolClient: null,
};

function setStatus(text) {
  statusEl.textContent = text;
}

function log(msg) {
  const time = new Date().toISOString().slice(11, 23);
  logEl.textContent += `[${time}] ${msg}\n`;
  logEl.scrollTop = logEl.scrollHeight;
}

function toLogValue(value) {
  if (value instanceof Uint8Array) {
    return bytesToHex(value);
  }
  if (typeof value === 'bigint') {
    return value.toString();
  }
  if (Array.isArray(value)) {
    return value.map(item => toLogValue(item));
  }
  if (value && typeof value === 'object') {
    const out = {};
    for (const [key, val] of Object.entries(value)) {
      out[key] = toLogValue(val);
    }
    return out;
  }
  return value;
}

function logObject(label, value) {
  const logged = toLogValue(value);
  log(`${label}: ${JSON.stringify(logged)}`);
  console.log(label, logged);
}

function logError(context, err) {
  const details = err?.message || err;
  const message = context ? `${context}: ${details}` : `${details}`;
  log(`Error: ${message}`);
  if (err) {
    console.error(message, err);
  } else {
    console.error(message);
  }
}

function renderDeployments(contractsInfo) {
  if (!contractsEl) return;
  if (!contractsInfo) {
    contractsEl.textContent = 'No deployments loaded.';
    return;
  }
  const lines = [
    `network: ${contractsInfo.network}`,
    `admin: ${contractsInfo.admin}`,
    `pool: ${contractsInfo.pool}`,
    `asp_membership: ${contractsInfo.asp_membership}`,
    `asp_non_membership: ${contractsInfo.asp_non_membership}`,
    `verifier: ${contractsInfo.verifier || 'unknown'}`,
  ];
  contractsEl.textContent = lines.join('\n');
}

function bytesToHex(bytes) {
  return '0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function compareSymbolKeys(a, b) {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

function bytesToBigIntLE(bytes) {
  let result = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

function bytesToBigIntBE(bytes) {
  let result = 0n;
  for (let i = 0; i < bytes.length; i++) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

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

function bytesToBigIntStringLE(bytes) {
  return bytesToBigIntLE(bytes).toString();
}

function asBigInt(value) {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number') return BigInt(value);
  if (typeof value === 'string') return BigInt(value);
  throw new Error('Expected numeric value');
}

function toHex32(value) {
  const v = asBigInt(value);
  return '0x' + v.toString(16).padStart(64, '0');
}

function unwrapResult(result, label) {
  if (result && typeof result.isOk === 'function' && typeof result.isErr === 'function') {
    if (result.isOk()) return result.unwrap();
    const err = result.unwrapErr();
    const msg = err?.message ? err.message : String(err);
    throw new Error(label ? `${label} failed: ${msg}` : msg);
  }
  return result;
}

function keccak256(bytes) {
  const msg = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return keccak_256(msg);
}

function hashExtData(extData) {
  const entries = [
    {
      key: 'recipient',
      val: Address.fromString(extData.recipient).toScVal(),
    },
    {
      key: 'ext_amount',
      val: new XdrLargeInt('i256', extData.ext_amount.toString()).toScVal(),
    },
    {
      key: 'encrypted_output0',
      val: xdr.ScVal.scvBytes(extData.encrypted_output0),
    },
    {
      key: 'encrypted_output1',
      val: xdr.ScVal.scvBytes(extData.encrypted_output1),
    },
  ];
  entries.sort((a, b) => compareSymbolKeys(a.key, b.key));
  log(`ExtData field order: ${entries.map(entry => entry.key).join(', ')}`);
  const scEntries = entries.map(entry => new xdr.ScMapEntry({
    key: xdr.ScVal.scvSymbol(entry.key),
    val: entry.val,
  }));
  const scVal = xdr.ScVal.scvMap(scEntries);
  const xdrRaw = scVal.toXDR();
  const xdrBytes = xdrRaw instanceof Uint8Array ? xdrRaw : new Uint8Array(xdrRaw);
  log(`ExtData XDR bytes: ${xdrBytes.length}`);
  const digest = keccak256(xdrBytes);
  const digestBig = bytesToBigIntBE(digest);
  const reduced = digestBig % BN256_MOD;
  return {
    bigInt: reduced,
    bytes: bigIntToBytesBE(reduced, 32),
  };
}

function sliceFieldElements(bytes, count) {
  const out = [];
  for (let i = 0; i < count; i++) {
    const start = i * 32;
    const chunk = bytes.slice(start, start + 32);
    out.push(bytesToBigIntStringLE(chunk));
  }
  return out;
}

async function connectWallet() {
  const address = await connectFreighter();
  const net = await getWalletNetwork();
  state.address = address;
  state.networkPassphrase = net.networkPassphrase;
  state.rpcUrl = net.sorobanRpcUrl || 'https://soroban-testnet.stellar.org';
  return address;
}

async function loadDeployments() {
  if (state.contracts) return state.contracts;
  const response = await fetch('./deployments.json');
  if (!response.ok) {
    throw new Error(`Failed to load deployments.json: ${response.status}`);
  }
  state.contracts = await response.json();
  renderDeployments(state.contracts);
  return state.contracts;
}

async function loadPoolClient(clientOpts, contractId) {
  if (state.poolClient) return state.poolClient;
  try {
    log('Loading pool contract spec from RPC...');
    state.poolClient = await contract.Client.from({ ...clientOpts, contractId });
  } catch (err) {
    log(`Client.from failed: ${err.message}`);
    throw err;
  }
  return state.poolClient;
}

function buildSigner() {
  return {
    signTransaction: async (transactionXdr, opts = {}) => {
      return signWalletTransaction(transactionXdr, {
        networkPassphrase: state.networkPassphrase,
        address: state.address,
        ...opts,
      });
    },
    signAuthEntry: async (entryXdr, opts = {}) => {
      return signWalletAuthEntry(entryXdr, {
        networkPassphrase: state.networkPassphrase,
        address: state.address,
        ...opts,
      });
    },
  };
}

async function generateAndSend() {
  if (!state.address) {
    throw new Error('Connect wallet first');
  }

  const contracts = await loadDeployments();
  const signer = buildSigner();
  const clientOpts = {
    rpcUrl: state.rpcUrl,
    networkPassphrase: state.networkPassphrase,
    publicKey: state.address,
    signTransaction: signer.signTransaction,
    signAuthEntry: signer.signAuthEntry,
  };

  setStatus('Loading contract clients...');
  const [poolClient, membershipClient, nonMembershipClient] = await Promise.all([
    loadPoolClient(clientOpts, contracts.pool),
    contract.Client.from({ ...clientOpts, contractId: contracts.asp_membership }),
    contract.Client.from({ ...clientOpts, contractId: contracts.asp_non_membership }),
  ]);

  setStatus('Reading on-chain roots...');
  const poolRootRaw = (await poolClient.get_root()).result;
  const membershipRootRaw = (await membershipClient.get_root()).result;
  const nonMembershipRootRaw = (await nonMembershipClient.get_root()).result;
  const poolRoot = asBigInt(unwrapResult(poolRootRaw, 'pool.get_root'));
  const aspMembershipRoot = asBigInt(unwrapResult(membershipRootRaw, 'asp_membership.get_root'));
  const aspNonMembershipRoot = asBigInt(unwrapResult(nonMembershipRootRaw, 'asp_non_membership.get_root'));
  log(`Pool root (on-chain): ${toHex32(poolRoot)}`);
  log(`ASP membership root (on-chain): ${toHex32(aspMembershipRoot)}`);
  log(`ASP non-membership root (on-chain): ${toHex32(aspNonMembershipRoot)}`);
  if (aspMembershipRoot === EXPECTED_MEMBERSHIP_ROOT_EMPTY) {
    log('ASP membership root matches expected empty tree root');
  }
  if (aspMembershipRoot === EXPECTED_MEMBERSHIP_ROOT_WITH_LEAF) {
    log('ASP membership root matches expected single-leaf root');
  }

  setStatus('Initializing prover...');
  if (!isInitialized()) {
    await initProver((loaded, total) => {
      if (total > 0) {
        const pct = ((loaded / total) * 100).toFixed(1);
        setStatus(`Downloading proving artifacts: ${pct}%`);
      }
    });
  }

  const privKey = BigInt(PRIVATE_KEY_HEX);
  const privKeyBytes = bigintToField(privKey);
  const pubKeyBytes = derivePublicKey(privKeyBytes);
  log(`Derived public key: ${fieldToHex(pubKeyBytes)}`);

  const membershipBlindingBytes = bigintToField(0n);
  const membershipLeaf = poseidon2Hash2(pubKeyBytes, membershipBlindingBytes, 1);
  const membershipLeafHex = fieldToHex(membershipLeaf);
  log(`Membership leaf: ${membershipLeafHex}`);
  if (membershipLeafHex !== EXPECTED_MEMBERSHIP_LEAF) {
    log('Warning: membership leaf does not match expected value');
  }

  const membershipTree = createMerkleTree(LEVELS);
  const zeroLeaf = hexToField(ZERO_LEAF_HEX);
  const totalLeaves = 1 << LEVELS;
  for (let i = 0; i < totalLeaves; i++) {
    membershipTree.insert(i === 0 ? membershipLeaf : zeroLeaf);
  }
  const membershipProof = membershipTree.get_proof(0);
  const membershipRootBytes = membershipTree.root();
  const membershipRoot = bytesToBigIntLE(membershipRootBytes);
  log(`Membership root (computed): ${toHex32(membershipRoot)}`);
  log(`Expected membership root (empty): ${toHex32(EXPECTED_MEMBERSHIP_ROOT_EMPTY)}`);
  log(`Expected membership root (with leaf): ${toHex32(EXPECTED_MEMBERSHIP_ROOT_WITH_LEAF)}`);
  if (membershipRoot !== aspMembershipRoot) {
    throw new Error('Membership root mismatch with on-chain ASP contract (ensure the leaf is inserted)');
  }

  const smt = new WasmSparseMerkleTree(SMT_LEVELS);
  const nonMembershipProof = smt.get_proof(pubKeyBytes, SMT_LEVELS);
  const nonMembershipRootBytes = smt.root();
  const nonMembershipRoot = bytesToBigIntLE(nonMembershipRootBytes);
  log(`Non-membership root (computed): ${toHex32(nonMembershipRoot)}`);
  if (nonMembershipRoot !== aspNonMembershipRoot) {
    throw new Error('Non-membership root mismatch with on-chain ASP contract (expected empty tree root)');
  }

  const inputs = [
    { amount: 0n, blinding: 101n },
    { amount: 0n, blinding: 202n },
  ];

  const pathIndicesBytes = bigintToField(0n);
  const pathIndicesStr = bytesToBigIntStringLE(pathIndicesBytes);

  for (const input of inputs) {
    const amountBytes = bigintToField(input.amount);
    const blindingBytes = bigintToField(input.blinding);
    const commitment = computeCommitment(amountBytes, pubKeyBytes, blindingBytes);
    const signature = computeSignature(privKeyBytes, commitment, pathIndicesBytes);
    const nullifier = computeNullifier(commitment, pathIndicesBytes, signature);
    input.commitmentBytes = commitment;
    input.nullifierBytes = nullifier;
    input.nullifierBig = bytesToBigIntLE(nullifier);
  }

  const outputs = [
    { amount: DEPOSIT_AMOUNT, blinding: 303n },
    { amount: 0n, blinding: 404n },
  ];

  for (const output of outputs) {
    const amountBytes = bigintToField(output.amount);
    const blindingBytes = bigintToField(output.blinding);
    const commitment = computeCommitment(amountBytes, pubKeyBytes, blindingBytes);
    output.commitmentBytes = commitment;
    output.commitmentBig = bytesToBigIntLE(commitment);
  }

  const extData = {
    recipient: contracts.pool,
    ext_amount: DEPOSIT_AMOUNT,
    encrypted_output0: new Uint8Array(),
    encrypted_output1: new Uint8Array(),
  };

  const extDataHash = hashExtData(extData);
  log(`ext_data_hash: ${bytesToHex(extDataHash.bytes)}`);

  const membershipPathElements = sliceFieldElements(membershipProof.path_elements, LEVELS);
  const membershipPathIndices = bytesToBigIntStringLE(membershipProof.path_indices);
  const nonMembershipSiblings = sliceFieldElements(nonMembershipProof.siblings, SMT_LEVELS);

  const circuitInputs = {
    root: poolRoot.toString(),
    publicAmount: DEPOSIT_AMOUNT.toString(),
    extDataHash: extDataHash.bigInt.toString(),
    inputNullifier: inputs.map(input => input.nullifierBig.toString()),
    outputCommitment: outputs.map(output => output.commitmentBig.toString()),
    inAmount: inputs.map(input => input.amount.toString()),
    inPrivateKey: inputs.map(() => privKey.toString()),
    inBlinding: inputs.map(input => input.blinding.toString()),
    inPathIndices: inputs.map(() => pathIndicesStr),
    inPathElements: inputs.map(() => Array(LEVELS).fill('0')),
    outAmount: outputs.map(output => output.amount.toString()),
    outPubkey: outputs.map(() => bytesToBigIntStringLE(pubKeyBytes)),
    outBlinding: outputs.map(output => output.blinding.toString()),
    membershipRoots: inputs.map(() => [membershipRoot.toString()]),
    nonMembershipRoots: inputs.map(() => [nonMembershipRoot.toString()]),
    membershipProofs: inputs.map(() => [
      {
        leaf: bytesToBigIntStringLE(membershipLeaf),
        blinding: '0',
        pathIndices: membershipPathIndices,
        pathElements: membershipPathElements,
      },
    ]),
    nonMembershipProofs: inputs.map(() => [
      {
        key: bytesToBigIntStringLE(pubKeyBytes),
        oldKey: bytesToBigIntStringLE(nonMembershipProof.not_found_key),
        oldValue: bytesToBigIntStringLE(nonMembershipProof.not_found_value),
        isOld0: nonMembershipProof.is_old0 ? '1' : '0',
        siblings: nonMembershipSiblings,
      },
    ]),
  };

  setStatus('Generating witness and proof...');
  console.log('CIRCUIT_INPUTS_JSON=', JSON.stringify(circuitInputs, null, 2));
  const witnessBytes = await generateWitness(circuitInputs);
  const proofBytes = generateProofBytes(witnessBytes);
  log(`Proof bytes (compressed): ${proofBytes.length} bytes`);
  const proofBytesUncompressed = proofBytesToUncompressed(proofBytes);
  log(`Proof bytes (uncompressed): ${proofBytesUncompressed.length} bytes`);
  if (proofBytesUncompressed.length !== 256) {
    throw new Error(`Unexpected uncompressed proof length: ${proofBytesUncompressed.length}`);
  }

  const publicInputs = extractPublicInputs(witnessBytes);
  const verified = verifyProofLocal(proofBytes, publicInputs);
  log(`Local proof verification: ${verified ? 'OK' : 'FAILED'}`);
  if (!verified) {
    throw new Error('Local proof verification failed');
  }

  const proof = {
    proof: {
      a: proofBytesUncompressed.slice(0, 64),
      b: proofBytesUncompressed.slice(64, 64 + 128),
      c: proofBytesUncompressed.slice(64 + 128),
    },
    root: poolRoot,
    input_nullifiers: inputs.map(input => input.nullifierBig),
    output_commitment0: outputs[0].commitmentBig,
    output_commitment1: outputs[1].commitmentBig,
    public_amount: DEPOSIT_AMOUNT,
    ext_data_hash: extDataHash.bytes,
    asp_membership_root: membershipRoot,
    asp_non_membership_root: nonMembershipRoot,
  };

  logObject('Transact proof', proof);
  logObject('Transact ext_data', extData);
  logObject('Transact sender', state.address);

  setStatus('Sending transaction...');
  const tx = await poolClient.transact({
    proof,
    ext_data: extData,
    sender: state.address,
  });

  const sent = await tx.signAndSend();
  log(`Sent transaction: ${sent.sendTransactionResponse.hash}`);
  setStatus('Transaction submitted');
}

async function init() {
  setStatus('Loading prover module...');
  await initProverModule();
  const keccakEmpty = bytesToHex(keccak256(new Uint8Array()));
  if (keccakEmpty !== '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470') {
    throw new Error('Keccak self-check failed');
  }
  try {
    await loadDeployments();
  } catch (err) {
    if (contractsEl) {
      contractsEl.textContent = `Failed to load deployments.json: ${err.message}`;
    }
    logError('Failed to load deployments.json', err);
  }
  setStatus('Ready');
}

btnConnect.addEventListener('click', async () => {
  try {
    setStatus('Connecting wallet...');
    const address = await connectWallet();
    log(`Wallet connected: ${address}`);
    btnSend.disabled = false;
    setStatus('Wallet connected');
  } catch (err) {
    setStatus('Wallet connection failed');
    logError('Wallet connection failed', err);
  }
});

btnSend.addEventListener('click', async () => {
  btnSend.disabled = true;
  try {
    await generateAndSend();
  } catch (err) {
    setStatus('Transaction failed');
    logError('Transaction failed', err);
  } finally {
    btnSend.disabled = false;
  }
});

init().catch(err => {
  setStatus('Initialization failed');
  logError('Initialization failed', err);
});
