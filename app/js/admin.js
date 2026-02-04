import { contract } from '@stellar/stellar-sdk';
import { connectWallet, getWalletNetwork, signWalletAuthEntry, signWalletTransaction, signWalletMessage } from './wallet.js';
import { loadDeployedContracts, readASPMembershipState, readASPNonMembershipState } from './stellar.js';
import { initProverWasm, derivePublicKey, poseidon2Hash2, bigintToField, fieldToHex, deriveNotePrivateKeyFromSignature } from './bridge.js';

// DOM element references
const statusEl = document.getElementById('status');
const logEl = document.getElementById('log');
const networkChip = document.getElementById('networkChip');
const walletChip = document.getElementById('walletChip');
const connectBtn = document.getElementById('connectBtn');
const refreshBtn = document.getElementById('refreshBtn');

// Key derivation elements
const deriveKeysBtn = document.getElementById('deriveKeysBtn');
const deriveKeysBtnText = document.getElementById('deriveKeysBtnText');
const derivedFromAccount = document.getElementById('derivedFromAccount');
const derivedKeysDisplay = document.getElementById('derivedKeysDisplay');
const derivedPrivateKeyEl = document.getElementById('derivedPrivateKey');
const derivedPublicKeyEl = document.getElementById('derivedPublicKey');
const toastContainer = document.getElementById('toast-container');
const toastTemplate = document.getElementById('tpl-toast');

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
  // Derived keys (persist across account changes)
  derivedKeys: {
    sourceAccount: null,
    privateKeyHex: null,
    publicKeyHex: null,
    privateKeyBytes: null,
    publicKeyBytes: null,
  },
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

// Toast notification system
function showToast(message, type = 'success', duration = 4000) {
  if (!toastContainer || !toastTemplate) return;
  const toast = toastTemplate.content.cloneNode(true).firstElementChild;
  
  toast.querySelector('.toast-message').textContent = message;
  
  const icon = toast.querySelector('.toast-icon');
  if (type === 'success') {
    icon.innerHTML = '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>';
    toast.classList.add('border-emerald-500/50');
    icon.classList.add('text-emerald-500');
  } else {
    icon.innerHTML = '<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>';
    toast.classList.add('border-red-500/50');
    icon.classList.add('text-red-500');
  }
  
  toast.querySelector('.toast-close').addEventListener('click', () => toast.remove());
  
  toastContainer.appendChild(toast);
  
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    setTimeout(() => toast.remove(), 200);
  }, duration);
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

// Derive ZK keys from wallet signature
async function deriveKeys() {
  try {
    ensureWalletConnected();
    await ensureCryptoReady();

    setStatus('Sign message to derive keys...', 'info');
    deriveKeysBtnText.textContent = 'Signing...';
    deriveKeysBtn.disabled = true;

    let spendingResult;
    try {
      spendingResult = await signWalletMessage('Privacy Pool Spending Key [v1]', {
        networkPassphrase: state.networkPassphrase,
        address: state.address,
      });
    } catch (e) {
      if (e.code === 'USER_REJECTED') {
        throw new Error('Please approve the message signature to derive your spending key');
      }
      throw e;
    }

    if (!spendingResult?.signedMessage) {
      throw new Error('Spending key signature rejected');
    }

    const spendingSigBytes = Uint8Array.from(atob(spendingResult.signedMessage), c => c.charCodeAt(0));
    const privKeyBytes = deriveNotePrivateKeyFromSignature(spendingSigBytes);
    const pubKeyBytes = derivePublicKey(privKeyBytes);
    
    const privateKeyHex = fieldToHex(privKeyBytes);
    const publicKeyHex = fieldToHex(pubKeyBytes);

    // Store in state (persists across account changes)
    state.derivedKeys = {
      sourceAccount: state.address,
      privateKeyHex,
      publicKeyHex,
      privateKeyBytes: privKeyBytes,
      publicKeyBytes: pubKeyBytes,
    };

    // Update UI
    updateDerivedKeysDisplay();
    autofillKeys();

    setStatus('Keys derived successfully', 'ok');
    showToast('Keys derived and auto-filled!', 'success');
    log(`Keys derived for account: ${shortAddress(state.address)}`);
    log(`Public Key: ${publicKeyHex}`);
  } catch (err) {
    setStatus('Key derivation failed', 'error');
    showToast(err.message, 'error');
    log(`Key derivation error: ${err.message}`);
  } finally {
    deriveKeysBtnText.textContent = 'Derive Keys';
    deriveKeysBtn.disabled = false;
  }
}

// Update the derived keys display section
function updateDerivedKeysDisplay() {
  if (!state.derivedKeys.privateKeyHex) {
    derivedKeysDisplay.classList.add('hidden');
    derivedFromAccount.textContent = '--';
    return;
  }

  derivedKeysDisplay.classList.remove('hidden');
  derivedFromAccount.textContent = shortAddress(state.derivedKeys.sourceAccount);
  derivedPrivateKeyEl.textContent = state.derivedKeys.privateKeyHex;
  derivedPublicKeyEl.textContent = state.derivedKeys.publicKeyHex;
}

// Auto-fill the membership and non-membership input fields with derived keys
function autofillKeys() {
  if (!state.derivedKeys.publicKeyHex) return;

  // Auto-fill membership leaf builder
  if (privateKeyInput) {
    privateKeyInput.value = state.derivedKeys.privateKeyHex;
  }
  if (publicKeyInput) {
    publicKeyInput.value = state.derivedKeys.publicKeyHex;
  }

  // Auto-fill non-membership (blocked key = public key)
  if (blockedKeyInput) {
    blockedKeyInput.value = state.derivedKeys.publicKeyHex;
    // Trigger sync if "value equals key" is checked
    syncNonMembershipValue();
  }

  log('Auto-filled keys in membership and non-membership forms');
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
    
    // Update wallet button to show connected state
    walletChip.textContent = shortAddress(address);
    networkChip.textContent = net.network || 'Testnet';
    connectBtn.classList.remove('bg-dark-800', 'hover:bg-dark-700');
    connectBtn.classList.add('bg-brand-500/10', 'border-brand-500/30', 'text-brand-400');
    
    // Invalidate contract clients (new account may have different auth)
    state.membershipClient = null;
    state.nonMembershipClient = null;
    
    setStatus('Wallet connected', 'ok');
    log(`Wallet connected: ${address}`);
    showToast(`Connected: ${shortAddress(address)}`, 'success');
    
    // If no keys derived yet, prompt to derive
    if (!state.derivedKeys.privateKeyHex) {
      log('Tip: Click "Derive Keys" to generate ZK keys for this account');
    }
  } catch (err) {
    if (err.code === 'USER_REJECTED') {
      setStatus('Connection cancelled', 'info');
      log('Wallet connection cancelled by user');
    } else {
      setStatus('Wallet error', 'error');
      log(`Wallet connection failed: ${err.message}`);
      showToast('Wallet connection failed', 'error');
    }
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
deriveKeysBtn.addEventListener('click', () => {
  deriveKeys();
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

// Copy button handlers for derived keys display
document.querySelectorAll('#derivedKeysDisplay .copy-btn').forEach(btn => {
  btn.addEventListener('click', async () => {
    const targetId = btn.dataset.target;
    const targetEl = document.getElementById(targetId);
    if (targetEl && targetEl.textContent !== '--') {
      try {
        await navigator.clipboard.writeText(targetEl.textContent);
        showToast('Copied to clipboard!', 'success');
      } catch {
        showToast('Failed to copy', 'error');
      }
    }
  });
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
