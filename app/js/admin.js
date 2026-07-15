import { contract } from '@stellar/stellar-sdk';
import { client, initializeRuntime } from './wasm-facade.js';
import { connectWallet, getWalletNetwork, signWalletAuthEntry, signWalletTransaction } from './wallet.js';
import { isDbLockedError, showDbLockedModal } from './db-locked.js';

// DOM element references
const statusEl = document.getElementById('status');
const networkChip = document.getElementById('networkChip');
const syncDot = document.getElementById('sync-dot');
const walletChip = document.getElementById('walletChip');
const connectBtn = document.getElementById('connectBtn');
const refreshBtn = document.getElementById('refreshBtn');

const toastContainer = document.getElementById('toast-container');
const toastTemplate = document.getElementById('tpl-toast');

// Contract/state display
const membershipContractInput = document.getElementById('membershipContract');
const nonMembershipContractInput = document.getElementById('nonMembershipContract');
const membershipRootEl = document.getElementById('membershipRoot');
const membershipLevelsEl = document.getElementById('membershipLevels');
const membershipNextIndexEl = document.getElementById('membershipNextIndex');
const nonMembershipRootEl = document.getElementById('nonMembershipRoot');

// Admin insert only toggle
const adminInsertOnlyStatusEl = document.getElementById('adminInsertOnlyStatus');
const toggleAdminInsertOnlyBtn = document.getElementById('toggleAdminInsertOnlyBtn');
const openInsertWarningEl = document.getElementById('openInsertWarning');

// Inputs & Action Buttons
const allowlistPublicKeyInput = document.getElementById('allowlistPublicKey');
const allowlistAspSecretInput = document.getElementById('allowlistAspSecret');
const blocklistPublicKeyInput = document.getElementById('blocklistPublicKey');

const addToAllowlistBtn = document.getElementById('addToAllowlistBtn');
const addToBlocklistBtn = document.getElementById('addToBlocklistBtn');
const removeFromBlocklistBtn = document.getElementById('removeFromBlocklistBtn');

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
  adminInsertOnly: null,
};

// -----------------------------
// UI Updates & Toasts
// -----------------------------

const STATUS_STYLES = {
  info: 'border-white/10 bg-white/[0.03] text-slate-300',
  ok: 'border-emerald-500/20 bg-emerald-500/10 text-emerald-300',
  error: 'border-rose-500/20 bg-rose-500/10 text-rose-300',
};

function setStatus(text, kind = 'info') {
  if (!statusEl) return;
  statusEl.textContent = text;
  statusEl.className = 'rounded-xl border px-4 py-2 text-center text-sm font-medium transition-colors ' + (STATUS_STYLES[kind] || STATUS_STYLES.info);
}

function shortAddress(address) {
  if (!address) return 'Disconnected';
  return `${address.slice(0, 6)}...${address.slice(-4)}`;
}

function showToast(message, type = 'success', duration = 4000) {
  if (!toastContainer || !toastTemplate) return;
  const toastWrapper = toastTemplate.content.cloneNode(true).firstElementChild;

  toastWrapper.querySelector('.toast-message').textContent = message;

  const icon = toastWrapper.querySelector('.toast-icon');
  if (type === 'success') {
      icon.className = 'toast-icon mt-0.5 h-2.5 w-2.5 rounded-full bg-emerald-400 shrink-0 shadow-[0_0_8px_rgba(52,211,153,0.8)]';
  } else if (type === 'error') {
      icon.className = 'toast-icon mt-0.5 h-2.5 w-2.5 rounded-full bg-rose-500 shrink-0 shadow-[0_0_8px_rgba(244,63,94,0.8)]';
  } else {
      icon.className = 'toast-icon mt-0.5 h-2.5 w-2.5 rounded-full bg-cyan-300 shrink-0 shadow-[0_0_8px_rgba(103,232,249,0.8)]';
  }

  toastWrapper.querySelector('.toast-close').addEventListener('click', () => {
    toastWrapper.classList.remove('translate-x-0', 'opacity-100');
    toastWrapper.classList.add('translate-x-full', 'opacity-0');
    setTimeout(() => toastWrapper.remove(), 300);
  });

  toastContainer.appendChild(toastWrapper);

  requestAnimationFrame(() => {
    toastWrapper.classList.remove('translate-x-full', 'opacity-0');
    toastWrapper.classList.add('translate-x-0', 'opacity-100');
  });

  setTimeout(() => {
    if (toastWrapper.parentNode) {
        toastWrapper.classList.remove('translate-x-0', 'opacity-100');
        toastWrapper.classList.add('translate-x-full', 'opacity-0');
        setTimeout(() => {
            if(toastWrapper.parentNode) toastWrapper.remove();
        }, 300);
    }
  }, duration);
}

// -----------------------------
// Parsing & conversion helpers
// -----------------------------
function parseBigIntInput(value, label) {
  const trimmed = (value || '').trim();
  if (!trimmed) return null;
  try {
    const parsed = BigInt(trimmed);
    if (parsed < 0n) throw new Error('negative');
    return parsed;
  } catch (err) {
    throw new Error(`${label} must be a hex or decimal integer`);
  }
}

const reverseHexWithPrefix = (hex) => {
  const hasPrefix = hex.startsWith("0x");
  const pureHex = hasPrefix ? hex.slice(2) : hex;
  const reversed = pureHex.match(/.{1,2}/g).reverse().join("");
  return hasPrefix ? "0x" + reversed : reversed;
};

// -----------------------------
// Wallet & signer helpers
// -----------------------------
function ensureWalletConnected() {
  if (!state.address) {
    throw new Error('Connect wallet first');
  }
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

async function getMembershipClient(contractId) {
  if (state.membershipClient && state.membershipClientId === contractId) return state.membershipClient;
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
  if (state.nonMembershipClient && state.nonMembershipClientId === contractId) return state.nonMembershipClient;
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

async function ensureCryptoReady() {
  if (!state.cryptoReady) {
    setStatus('Loading app...', 'info');
    const { sorobanRpcUrl, ...network } = await getWalletNetwork();
    try {
      await initializeRuntime(sorobanRpcUrl);
      await client().startSync();
    } catch (e) {
      if (isDbLockedError(e?.message)) showDbLockedModal(e.message);
      throw e;
    }
    state.cryptoReady = true;
    setStatus('App ready', 'ok');
  }
}

// -----------------------------
// Wallet actions
// -----------------------------
async function connect() {
  try {
    setStatus('Connecting wallet...', 'info');
    const address = await connectWallet();
    const net = await getWalletNetwork();
    state.address = address;
    state.networkPassphrase = net.networkPassphrase;
    state.rpcUrl = net.sorobanRpcUrl || 'https://soroban-testnet.stellar.org';

    walletChip.textContent = shortAddress(address);
    connectBtn.title = "Click to disconnect";
    networkChip.textContent = net.network || 'Testnet';

    // UI states reflecting connection
    syncDot.classList.remove('bg-emerald-500', 'animate-pulse', 'shadow-emerald-500');
    syncDot.classList.add('bg-cyan-400', 'shadow-cyan-400');
    connectBtn.classList.remove('bg-[linear-gradient(135deg,#74c5ff,#2f6dff)]', 'text-ink-950');
    connectBtn.classList.add('bg-white/[0.05]', 'text-slate-100');

    // Enable Action Buttons & remove tooltips
    const actionBtns = [addToAllowlistBtn, addToBlocklistBtn, removeFromBlocklistBtn];
    actionBtns.forEach(btn => {
      btn.disabled = false;
      btn.removeAttribute('title');
    });

    state.membershipClient = null;
    state.nonMembershipClient = null;

    updateAdminInsertOnlyDisplay(state.adminInsertOnly);
    setStatus('Wallet connected', 'ok');
    showToast(`Connected: ${shortAddress(address)}`, 'success');

  } catch (err) {
    if (err.code === 'USER_REJECTED') {
      setStatus('Connection cancelled', 'info');
    } else {
      setStatus('Wallet error', 'error');
      showToast('Wallet connection failed', 'error');
    }
  }
}

function disconnect() {
  state.address = null;
  state.networkPassphrase = null;
  state.rpcUrl = null;
  state.membershipClient = null;
  state.nonMembershipClient = null;

  walletChip.textContent = 'Connect Freighter';
  connectBtn.removeAttribute('title');
  networkChip.textContent = 'Disconnected';

  syncDot.classList.remove('bg-cyan-400', 'shadow-cyan-400');
  syncDot.classList.add('bg-emerald-500', 'animate-pulse', 'shadow-emerald-500');
  connectBtn.classList.add('bg-[linear-gradient(135deg,#74c5ff,#2f6dff)]', 'text-ink-950');
  connectBtn.classList.remove('bg-white/[0.05]', 'text-slate-100');

  // Disable Action Buttons & restore tooltips
  const actionBtns = [addToAllowlistBtn, addToBlocklistBtn, removeFromBlocklistBtn, toggleAdminInsertOnlyBtn];
  actionBtns.forEach(btn => {
    btn.disabled = true;
    btn.title = "Please connect your wallet first";
  });

  updateAdminInsertOnlyDisplay(state.adminInsertOnly);
  setStatus('Wallet disconnected', 'info');
  showToast('Wallet disconnected', 'info');
}

async function refreshState() {
  try {
    setStatus('Loading contract state...', 'info');
    const appState = await client().aspState();
    const membershipState = appState.aspMembership;
    const nonMembershipState = appState.aspNonMembership;

    if (membershipContractInput) membershipContractInput.value = membershipState.contractId;
    if (nonMembershipContractInput) nonMembershipContractInput.value = nonMembershipState.contractId;

    membershipRootEl.textContent = membershipState.root || '--';
    membershipLevelsEl.textContent = membershipState.levels ?? '--';
    membershipNextIndexEl.textContent = membershipState.nextIndex ?? '--';
    updateAdminInsertOnlyDisplay(membershipState.adminInsertOnly);
    nonMembershipRootEl.textContent = nonMembershipState.root || '--';

    setStatus('State loaded', 'ok');
  } catch (err) {
    updateAdminInsertOnlyDisplay(undefined);
    setStatus('State load error', 'error');
  }
}

function updateAdminInsertOnlyDisplay(value) {
  if (value === undefined || value === null) {
    adminInsertOnlyStatusEl.textContent = '--';
    toggleAdminInsertOnlyBtn.disabled = true;
    openInsertWarningEl.classList.add('hidden');
    return;
  }
  state.adminInsertOnly = value;
  adminInsertOnlyStatusEl.textContent = value ? 'Enabled' : 'Disabled';
  adminInsertOnlyStatusEl.className = value ? 'font-mono text-sm text-emerald-400' : 'font-mono text-sm text-amber-400';
  toggleAdminInsertOnlyBtn.textContent = value ? 'Disable' : 'Enable';

  if (state.address) {
    toggleAdminInsertOnlyBtn.disabled = false;
    toggleAdminInsertOnlyBtn.removeAttribute('title');
  } else {
    toggleAdminInsertOnlyBtn.disabled = true;
    toggleAdminInsertOnlyBtn.title = "Please connect your wallet first";
  }

  openInsertWarningEl.classList.toggle('hidden', value);
}

async function toggleAdminInsertOnly() {
  const originalText = toggleAdminInsertOnlyBtn.textContent;
  try {
    ensureWalletConnected();
    const contractId = membershipContractInput.value.trim();
    if (!contractId) throw new Error('Membership contract ID is required');
    if (state.adminInsertOnly === null || state.adminInsertOnly === undefined) {
      throw new Error('Cannot toggle: state unknown. Refresh first.');
    }

    toggleAdminInsertOnlyBtn.disabled = true;
    toggleAdminInsertOnlyBtn.textContent = 'Processing...';

    const newValue = !state.adminInsertOnly;
    setStatus(`Setting admin-only insert to ${newValue ? 'enabled' : 'disabled'}...`, 'info');

    const mClient = await getMembershipClient(contractId);
    const tx = await mClient.set_admin_insert_only({ admin_only: newValue });
    await tx.signAndSend();

    setStatus('Setting updated', 'ok');
    showToast(`Admin-only insert ${newValue ? 'enabled' : 'disabled'}`, 'success');
    await refreshState();
  } catch (err) {
    setStatus('Toggle failed', 'error');
    showToast('Failed to toggle admin-only insert', 'error');
  } finally {
    if (state.address) toggleAdminInsertOnlyBtn.disabled = false;
    toggleAdminInsertOnlyBtn.textContent = originalText;
  }
}

// -----------------------------
// Transaction Submissions
// -----------------------------
async function insertMembershipLeaf() {
  const originalText = addToAllowlistBtn.textContent;
  try {
    ensureWalletConnected();
    const contractId = membershipContractInput.value.trim();
    if (!contractId) throw new Error('Membership contract ID is required');

    const notePublicKey = parseBigIntInput(allowlistPublicKeyInput.value, 'Public key');
    if (notePublicKey === null) throw new Error('User note public key is required');

    const aspSecret = parseBigIntInput(allowlistAspSecretInput.value, 'ASP secret');
    if (aspSecret === null) throw new Error('ASP secret is required');

    addToAllowlistBtn.disabled = true;
    addToAllowlistBtn.textContent = 'Processing...';

    setStatus('Computing and submitting allowlist insert transaction...', 'info');
    await ensureCryptoReady();

    const leafHex = await client().account().deriveAspUserLeaf({
        membershipBlinding: aspSecret,
        notePublicKey,
    });
    const leafValue = BigInt(leafHex);

    const mClient = await getMembershipClient(contractId);
    const tx = await mClient.insert_leaf({ leaf: leafValue });
    await tx.signAndSend();

    setStatus('The allowlist insert transaction sent', 'ok');
    showToast('Added to the allowlist successfully', 'success');
    allowlistPublicKeyInput.value = '';
    allowlistAspSecretInput.value = '';
    await refreshState();
  } catch (err) {
    setStatus('Allowlist insert failed', 'error');
    showToast(`Allowlist insert failed: ${err.message}`, 'error');
  } finally {
    if (state.address) addToAllowlistBtn.disabled = false;
    addToAllowlistBtn.textContent = originalText;
  }
}

async function insertNonMembershipLeaf() {
  const originalText = addToBlocklistBtn.textContent;
  try {
    ensureWalletConnected();
    const contractId = nonMembershipContractInput.value.trim();
    if (!contractId) throw new Error('Non-membership contract ID is required');

    const keyValue = parseBigIntInput(reverseHexWithPrefix(blocklistPublicKeyInput.value), 'Key');
    if (keyValue === null) throw new Error('User note public key is required');

    const valueValue = keyValue;

    addToBlocklistBtn.disabled = true;
    addToBlocklistBtn.textContent = 'Processing...';

    setStatus('Submitting blocklist insert transaction...', 'info');
    const nmClient = await getNonMembershipClient(contractId);
    const tx = await nmClient.insert_leaf({ key: keyValue, value: valueValue });
    await tx.signAndSend();

    setStatus('The blocklist insert transaction sent', 'ok');
    showToast('Added to the blocklist successfully', 'success');
    blocklistPublicKeyInput.value = '';
    await refreshState();
  } catch (err) {
    setStatus('Blocklist insert failed', 'error');
    showToast(`Blocklist insert failed: ${err.message}`, 'error');
  } finally {
    if (state.address) addToBlocklistBtn.disabled = false;
    addToBlocklistBtn.textContent = originalText;
  }
}

async function removeNonMembershipLeaf() {
  const originalText = removeFromBlocklistBtn.textContent;
  try {
    ensureWalletConnected();
    const contractId = nonMembershipContractInput.value.trim();
    if (!contractId) throw new Error('Non-membership contract ID is required');

    const keyValue = parseBigIntInput(reverseHexWithPrefix(blocklistPublicKeyInput.value), 'Key');
    if (keyValue === null) throw new Error('User note public key is required');

    removeFromBlocklistBtn.disabled = true;
    removeFromBlocklistBtn.textContent = 'Processing...';

    setStatus('Submitting blocklist removal transaction...', 'info');
    const nmClient = await getNonMembershipClient(contractId);
    const tx = await nmClient.delete_leaf({ key: keyValue });
    await tx.signAndSend();

    setStatus('The blocklist removal transaction sent', 'ok');
    showToast('Removed from the blocklist successfully', 'success');
    blocklistPublicKeyInput.value = '';
    await refreshState();
  } catch (err) {
    setStatus('User key removal from the blocklist failed', 'error');
    showToast(`User key removal from the blocklist failed: ${err.message}`, 'error');
  } finally {
    if (state.address) removeFromBlocklistBtn.disabled = false;
    removeFromBlocklistBtn.textContent = originalText;
  }
}

// -----------------------------
// Tab Switching Logic
// -----------------------------
const tabBtns = document.querySelectorAll('.tab-btn');
const tabContents = document.querySelectorAll('.tab-content');

tabBtns.forEach(btn => {
  btn.addEventListener('click', () => {
    tabBtns.forEach(t => {
      t.className = 'tab-btn rounded-full border border-white/10 px-4 py-2 text-sm font-medium text-slate-400 transition hover:border-cyan-300/30 hover:text-cyan-100';
    });
    btn.className = 'tab-btn rounded-full border border-cyan-300/30 bg-cyan-400/10 px-4 py-2 text-sm font-medium text-cyan-100 transition';

    tabContents.forEach(c => c.classList.add('hidden'));

    const targetId = btn.getAttribute('data-target');
    document.getElementById(targetId).classList.remove('hidden');
  });
});

// -----------------------------
// Event Listeners & Init
// -----------------------------
connectBtn.addEventListener('click', () => {
  if (state.address) {
    disconnect();
  } else {
    connect();
  }
});
refreshBtn.addEventListener('click', refreshState);
toggleAdminInsertOnlyBtn.addEventListener('click', toggleAdminInsertOnly);

addToAllowlistBtn.addEventListener('click', insertMembershipLeaf);
addToBlocklistBtn.addEventListener('click', insertNonMembershipLeaf);
removeFromBlocklistBtn.addEventListener('click', removeNonMembershipLeaf);

async function init() {
  setStatus('Initializing...', 'info');
  await ensureCryptoReady();
  await refreshState();
  setStatus('Ready', 'ok');
}

init().catch(err => {
  setStatus('Init failed', 'error');
  console.error('Init error:', err);
});
