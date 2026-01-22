import { contract } from '@stellar/stellar-sdk';
import { connectWallet, getWalletNetwork, signWalletAuthEntry, signWalletTransaction } from './wallet.js';
import { loadDeployedContracts, readASPMembershipState, readASPNonMembershipState } from './stellar.js';
import { initProverWasm, derivePublicKey, poseidon2Hash2, bigintToField, fieldToHex } from './bridge.js';

// -----------------------------
// DOM element references
// -----------------------------


const statusEl = document.getElementById('status');
const logEl = document.getElementById('log');
const networkChip = document.getElementById('networkChip');
const walletChip = document.getElementById('walletChip');
const connectBtn = document.getElementById('connectBtn');
const refreshBtn = document.getElementById('refreshBtn');

// Contract/state display
const membershipContractInput = document.getElementById('membershipContract');
const nonMembershipContractInput = document.getElementById('nonMembershipContract');
const membershipRootEl = document.getElementById('membershipRoot');
const membershipLevelsEl = document.getElementById('membershipLevels');
const membershipNextIndexEl = document.getElementById('membershipNextIndex');
const nonMembershipRootEl = document.getElementById('nonMembershipRoot');

// Membership leaf builder inputs
const privateKeyInput = document.getElementById('privateKey');
const publicKeyInput = document.getElementById('publicKey');
const blindingInput = document.getElementById('blinding');
const computeMembershipLeafBtn = document.getElementById('computeMembershipLeafBtn');
const useMembershipLeafBtn = document.getElementById('useMembershipLeafBtn');
const derivedPubKeyEl = document.getElementById('derivedPubKey');
const computedMembershipLeafHexEl = document.getElementById('computedMembershipLeafHex');
const computedMembershipLeafDecEl = document.getElementById('computedMembershipLeafDec');
const membershipLeafInput = document.getElementById('membershipLeafInput');
const insertMembershipLeafBtn = document.getElementById('insertMembershipLeafBtn');

// Non-membership leaf builder inputs
const blockedKeyInput = document.getElementById('blockedKey');
const blockedValueInput = document.getElementById('blockedValue');
const valueSameCheckbox = document.getElementById('valueSame');
const computeNonMembershipLeafBtn = document.getElementById('computeNonMembershipLeafBtn');
const computedNonMembershipLeafHexEl = document.getElementById('computedNonMembershipLeafHex');
const insertNonMembershipLeafBtn = document.getElementById('insertNonMembershipLeafBtn');

const state = {
  address: null,
  networkPassphrase: null,
  rpcUrl: null,
  contracts: null,
  membershipClient: null,
  nonMembershipClient: null,
  membershipClientId: null,
  nonMembershipClientId: null,
  cryptoReady: false,
  computedMembershipLeaf: null,
};

const statusBaseClass = statusEl ? statusEl.className : '';

const STATUS_STYLES = {
  info: '',
  ok: 'bg-emerald-500/10 border-emerald-500/40 text-emerald-300',
  error: 'bg-rose-500/10 border-rose-500/40 text-rose-300',
};

// Update status banner text + color
function setStatus(text, kind = 'info') {
  if (!statusEl) return;
  statusEl.textContent = text;
  const classes = STATUS_STYLES[kind] || STATUS_STYLES.info;
  statusEl.className = `${statusBaseClass} ${classes}`.trim();
}

// Append timestamped log entry
function log(message) {
  if (!logEl) return;
  const time = new Date().toISOString().slice(11, 19);
  logEl.textContent += `[${time}] ${message}\n`;
  logEl.scrollTop = logEl.scrollHeight;
}

function shortAddress(address) {
  if (!address) return 'Disconnected';
  return `${address.slice(0, 6)}...${address.slice(-4)}`;
}

// -----------------------------
// Parsing & conversion helpers
// -----------------------------

// Parse user input into a non-negative BigInt (hex or decimal)
function parseBigIntInput(value, label) {
  const trimmed = (value || '').trim();
  if (!trimmed) return null;
  try {
    const parsed = BigInt(trimmed);
    if (parsed < 0n) {
      throw new Error('negative');
    }
    return parsed;
  } catch (err) {
    throw new Error(`${label} must be a hex or decimal integer`);
  }
}

// Convert byte array (little-endian) to BigInt
// Used only for display / cached BigInt values
function bytesToBigIntLE(bytes) {
  let result = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

// -----------------------------
// Wallet & signer helpers
// -----------------------------

function ensureWalletConnected() {
  if (!state.address) {
    throw new Error('Connect wallet first');
  }
}

// Build Soroban-compatible signer wrapper around wallet functions
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

// -----------------------------
// Contract client factories
// -----------------------------

async function getMembershipClient(contractId) {
  if (state.membershipClient && state.membershipClientId === contractId) {
    return state.membershipClient;
  }
  const signer = buildSigner();
  state.membershipClient = await contract.Client.from({
    rpcUrl: state.rpcUrl,
    networkPassphrase: state.networkPassphrase,
    publicKey: state.address,
    signTransaction: signer.signTransaction,
    signAuthEntry: signer.signAuthEntry,
    contractId,
  });
  state.membershipClientId = contractId;
  return state.membershipClient;
}

async function getNonMembershipClient(contractId) {
  if (state.nonMembershipClient && state.nonMembershipClientId === contractId) {
    return state.nonMembershipClient;
  }
  const signer = buildSigner();
  state.nonMembershipClient = await contract.Client.from({
    rpcUrl: state.rpcUrl,
    networkPassphrase: state.networkPassphrase,
    publicKey: state.address,
    signTransaction: signer.signTransaction,
    signAuthEntry: signer.signAuthEntry,
    contractId,
  });
  state.nonMembershipClientId = contractId;
  return state.nonMembershipClient;
}

// Initialize WASM prover / crypto primitives
async function ensureCryptoReady() {
  if (!state.cryptoReady) {
    setStatus('Loading cryptography...', 'info');
    await initProverWasm();
    state.cryptoReady = true;
    setStatus('Cryptography ready', 'ok');
  }
}

// -----------------------------
// Wallet & network actions
// -----------------------------

async function connect() {
  try {
    setStatus('Connecting wallet...', 'info');
    const address = await connectWallet();
    const net = await getWalletNetwork();
    state.address = address;
    state.networkPassphrase = net.networkPassphrase;
    state.rpcUrl = net.sorobanRpcUrl || 'https://soroban-testnet.stellar.org';
    walletChip.textContent = `Wallet: ${shortAddress(address)}`;
    networkChip.textContent = `Network: ${net.network || 'unknown'}`;
    setStatus('Wallet connected', 'ok');
    log(`Wallet connected: ${address}`);
  } catch (err) {
    setStatus('Wallet error', 'error');
    log(`Wallet connection failed: ${err.message}`);
  }
}

async function loadDeployments() {
  try {
    state.contracts = await loadDeployedContracts();
    if (membershipContractInput && state.contracts?.aspMembership) {
      membershipContractInput.value = state.contracts.aspMembership;
    }
    if (nonMembershipContractInput && state.contracts?.aspNonMembership) {
      nonMembershipContractInput.value = state.contracts.aspNonMembership;
    }
    log('Loaded deployments.json');
  } catch (err) {
    log(`Failed to load deployments.json: ${err.message}`);
  }
}

async function refreshState() {
  try {
    setStatus('Loading contract state...', 'info');
    const membershipId = membershipContractInput.value.trim() || undefined;
    const nonMembershipId = nonMembershipContractInput.value.trim() || undefined;

    const [membershipState, nonMembershipState] = await Promise.all([
      readASPMembershipState(membershipId),
      readASPNonMembershipState(nonMembershipId),
    ]);

    if (membershipState.success) {
      membershipRootEl.textContent = membershipState.root || '--';
      membershipLevelsEl.textContent = membershipState.levels ?? '--';
      membershipNextIndexEl.textContent = membershipState.nextIndex ?? '--';
      log('Loaded membership state');
    } else {
      log(`Membership state error: ${membershipState.error}`);
    }

    if (nonMembershipState.success) {
      nonMembershipRootEl.textContent = nonMembershipState.root || '--';
      log('Loaded non-membership state');
    } else {
      log(`Non-membership state error: ${nonMembershipState.error}`);
    }

    setStatus('State loaded', membershipState.success && nonMembershipState.success ? 'ok' : 'error');
  } catch (err) {
    setStatus('State load error', 'error');
    log(`State refresh failed: ${err.message}`);
  }
}

// -----------------------------
// Membership and non leaf computation
// -----------------------------

async function computeMembershipLeaf() {
  try {
    await ensureCryptoReady();
    const blindingValue = parseBigIntInput(blindingInput.value, 'Blinding');
    if (blindingValue === null) {
      throw new Error('Blinding is required');
    }

    const publicOverride = parseBigIntInput(publicKeyInput.value, 'Public key');
    const privateValue = parseBigIntInput(privateKeyInput.value, 'Private key');

    let pubKeyBytes = null;
    if (publicOverride !== null) {
      pubKeyBytes = bigintToField(publicOverride);
    } else if (privateValue !== null) {
      const privateBytes = bigintToField(privateValue);
      pubKeyBytes = derivePublicKey(privateBytes);
    } else {
      throw new Error('Provide a private key or a public key override');
    }

    const blindingBytes = bigintToField(blindingValue);
    const leafBytes = poseidon2Hash2(pubKeyBytes, blindingBytes, 1);

    const pubKeyHex = fieldToHex(pubKeyBytes);
    const leafHex = fieldToHex(leafBytes);
    const leafDec = bytesToBigIntLE(leafBytes).toString();

    derivedPubKeyEl.textContent = pubKeyHex;
    computedMembershipLeafHexEl.textContent = leafHex;
    computedMembershipLeafDecEl.textContent = leafDec;

    state.computedMembershipLeaf = {
      leafHex,
      leafDec,
      leafBigInt: bytesToBigIntLE(leafBytes),
    };
    useMembershipLeafBtn.disabled = false;
    log('Computed membership leaf');
  } catch (err) {
    log(`Membership leaf error: ${err.message}`);
  }
}

function useComputedMembershipLeaf() {
  if (!state.computedMembershipLeaf) return;
  membershipLeafInput.value = state.computedMembershipLeaf.leafHex;
}

async function insertMembershipLeaf() {
  try {
    ensureWalletConnected();
    const contractId = membershipContractInput.value.trim();
    if (!contractId) {
      throw new Error('Membership contract ID is required');
    }

    let leafValue = parseBigIntInput(membershipLeafInput.value, 'Leaf');
    if (leafValue === null && state.computedMembershipLeaf) {
      leafValue = state.computedMembershipLeaf.leafBigInt;
    }
    if (leafValue === null) {
      throw new Error('Leaf value is required');
    }

    setStatus('Submitting membership leaf...', 'info');
    const client = await getMembershipClient(contractId);
    const tx = await client.insert_leaf({ leaf: leafValue });
    const sent = await tx.signAndSend();
    log(`Membership leaf submitted: ${sent.sendTransactionResponse?.hash || 'ok'}`);
    setStatus('Membership leaf sent', 'ok');
    await refreshState();
  } catch (err) {
    setStatus('Membership insert failed', 'error');
    log(`Membership insert error: ${err.message}`);
  }
}

function syncNonMembershipValue() {
  if (!valueSameCheckbox.checked) {
    blockedValueInput.removeAttribute('disabled');
    return;
  }
  blockedValueInput.value = blockedKeyInput.value;
  blockedValueInput.setAttribute('disabled', 'disabled');
}

async function computeNonMembershipLeaf() {
  try {
    await ensureCryptoReady();
    const keyValue = parseBigIntInput(blockedKeyInput.value, 'Key');
    if (keyValue === null) {
      throw new Error('Key is required');
    }
    const valueValue = parseBigIntInput(blockedValueInput.value, 'Value');
    if (valueValue === null) {
      throw new Error('Value is required');
    }
    const keyBytes = bigintToField(keyValue);
    const valueBytes = bigintToField(valueValue);
    const leafBytes = poseidon2Hash2(keyBytes, valueBytes, 1);
    computedNonMembershipLeafHexEl.textContent = fieldToHex(leafBytes);
    log('Computed non-membership leaf hash');
  } catch (err) {
    log(`Non-membership leaf error: ${err.message}`);
  }
}

async function insertNonMembershipLeaf() {
  try {
    ensureWalletConnected();
    const contractId = nonMembershipContractInput.value.trim();
    if (!contractId) {
      throw new Error('Non-membership contract ID is required');
    }

    const keyValue = parseBigIntInput(blockedKeyInput.value, 'Key');
    const valueValue = parseBigIntInput(blockedValueInput.value, 'Value');
    if (keyValue === null || valueValue === null) {
      throw new Error('Key and value are required');
    }

    setStatus('Submitting non-membership leaf...', 'info');
    const client = await getNonMembershipClient(contractId);
    const tx = await client.insert_leaf({ key: keyValue, value: valueValue });
    const sent = await tx.signAndSend();
    log(`Non-membership leaf submitted: ${sent.sendTransactionResponse?.hash || 'ok'}`);
    setStatus('Non-membership leaf sent', 'ok');
    await refreshState();
  } catch (err) {
    setStatus('Non-membership insert failed', 'error');
    log(`Non-membership insert error: ${err.message}`);
  }
}

connectBtn.addEventListener('click', () => {
  connect();
});
refreshBtn.addEventListener('click', () => {
  refreshState();
});
computeMembershipLeafBtn.addEventListener('click', () => {
  computeMembershipLeaf();
});
useMembershipLeafBtn.addEventListener('click', () => {
  useComputedMembershipLeaf();
});
insertMembershipLeafBtn.addEventListener('click', () => {
  insertMembershipLeaf();
});
computeNonMembershipLeafBtn.addEventListener('click', () => {
  computeNonMembershipLeaf();
});
insertNonMembershipLeafBtn.addEventListener('click', () => {
  insertNonMembershipLeaf();
});
valueSameCheckbox.addEventListener('change', () => {
  syncNonMembershipValue();
});
blockedKeyInput.addEventListener('input', () => {
  syncNonMembershipValue();
});

async function init() {
  setStatus('Initializing...', 'info');
  await ensureCryptoReady();
  await loadDeployments();
  syncNonMembershipValue();
  setStatus('Ready', 'ok');
}

init().catch(err => {
  setStatus('Init failed', 'error');
  log(`Init error: ${err.message}`);
});
