import { deploymentDefaults } from './network-config.js';
import { contract, scValToNative, xdr } from '@stellar/stellar-sdk';
import { client, initializeRuntime, bootnodeRequired, ensureStorage, deriveAspUserLeaf } from './wasm-facade.js';
import { connectWallet, getWalletNetwork, signWalletTransaction } from './wallet.js';
import { isDbLockedError, showDbLockedModal } from './db-locked.js';
import { friendlyErrorMessage } from './facade-errors.js';
import { App, Utils } from './ui/core.js';
import { initGvkAuditPanel } from './admin-gvk.js';
import { buildAdminCall, describeAdminCall, explainFailure, rpcServer, signatureCount, signingRule, signRefusal, submitAdminCall } from './admin-transactions.js';
import { blocklistInsertCall, blocklistKeyToNoteKey, parseBlocklistKeys } from './blocklist-keys.js';

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
const membershipContractLinkEl = document.getElementById('membershipContractLink');
const nonMembershipContractLinkEl = document.getElementById('nonMembershipContractLink');
const membershipRootEl = document.getElementById('membershipRoot');
const membershipLevelsEl = document.getElementById('membershipLevels');
const membershipNextIndexEl = document.getElementById('membershipNextIndex');
const nonMembershipRootEl = document.getElementById('nonMembershipRoot');

// Inputs & Action Buttons
const allowlistPublicKeyInput = document.getElementById('allowlistPublicKey');
const allowlistAspSecretInput = document.getElementById('allowlistAspSecret');
const blocklistPublicKeyInput = document.getElementById('blocklistPublicKey');

const addToAllowlistBtn = document.getElementById('addToAllowlistBtn');
const addToBlocklistBtn = document.getElementById('addToBlocklistBtn');
const removeFromBlocklistBtn = document.getElementById('removeFromBlocklistBtn');

// Admin transaction card
const adminTxXdrInput = document.getElementById('adminTxXdr');
const adminTxDescriptionEl = document.getElementById('adminTxDescription');
const adminTxSignaturesEl = document.getElementById('adminTxSignatures');
const signAdminTxBtn = document.getElementById('signAdminTxBtn');
const submitAdminTxBtn = document.getElementById('submitAdminTxBtn');
const copyAdminTxBtn = document.getElementById('copyAdminTxBtn');

// The buttons that need a connected wallet.
const ACTION_BUTTONS = [addToAllowlistBtn, addToBlocklistBtn, removeFromBlocklistBtn, signAdminTxBtn, submitAdminTxBtn];

const state = {
  address: null,
  networkPassphrase: null,
  rpcUrl: null,
  contracts: null,
  adminTxKind: null,
  cryptoReady: false,
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

  toastWrapper.querySelector('.toast-message').textContent = friendlyErrorMessage(message);

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

// -----------------------------
// Wallet & signer helpers
// -----------------------------
function ensureWalletConnected() {
  if (!state.address) {
    throw new Error('Connect wallet first');
  }
}

async function ensureCryptoReady() {
  if (!state.cryptoReady) {
    setStatus('Loading app...', 'info');
    const { sorobanRpcUrl, ...network } = await getWalletNetwork();
    try {
      const storage = await ensureStorage();
      if (await bootnodeRequired(sorobanRpcUrl)) {
        if (!(await storage.getStoredBootnodeUrl())) {
          throw new Error('RPC_SYNC_GAP: bootnode required');
        }
      }
      await initializeRuntime(sorobanRpcUrl);
      await client().backgroundSync();
    } catch (e) {
      if (isDbLockedError(e?.message)) showDbLockedModal(e.message);
      throw e;
    }
    state.cryptoReady = true;
    setStatus('App ready', 'ok');
  }
}

// -----------------------------
// Block explorer links
// -----------------------------
async function loadExplorerSetting() {
  try {
    const storage = await ensureStorage();
    const explorerSetting = await storage.getExplorerSetting();
    App.state.settings.explorerBaseUrl = explorerSetting?.baseUrl || Utils.defaultExplorerBaseUrl;
  } catch (err) {
    console.warn('Explorer setting unavailable, using default explorer:', err);
  }
}

function updateContractLink(linkEl, contractId) {
  if (!linkEl) return;
  linkEl.href = contractId ? Utils.explorerContractUrl(contractId) : '#';
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
    state.rpcUrl = net.sorobanRpcUrl || deploymentDefaults.rpcUrl;

    walletChip.textContent = shortAddress(address);
    connectBtn.title = "Click to disconnect";
    networkChip.textContent = deploymentDefaults.displayName || deploymentDefaults.network;

    // UI states reflecting connection
    syncDot.classList.remove('bg-emerald-500', 'animate-pulse', 'shadow-emerald-500');
    syncDot.classList.add('bg-cyan-400', 'shadow-cyan-400');
    connectBtn.classList.remove('bg-[linear-gradient(135deg,#74c5ff,#2f6dff)]', 'text-ink-950');
    connectBtn.classList.add('bg-white/[0.05]', 'text-slate-100');

    // Enable Action Buttons & remove tooltips
    ACTION_BUTTONS.forEach(btn => {
      btn.disabled = false;
      btn.removeAttribute('title');
    });

    renderAdminTx();
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

  walletChip.textContent = 'Connect Freighter';
  connectBtn.removeAttribute('title');
  networkChip.textContent = 'Disconnected';

  syncDot.classList.remove('bg-cyan-400', 'shadow-cyan-400');
  syncDot.classList.add('bg-emerald-500', 'animate-pulse', 'shadow-emerald-500');
  connectBtn.classList.add('bg-[linear-gradient(135deg,#74c5ff,#2f6dff)]', 'text-ink-950');
  connectBtn.classList.remove('bg-white/[0.05]', 'text-slate-100');

  // Disable Action Buttons & restore tooltips
  ACTION_BUTTONS.forEach(btn => {
    btn.disabled = true;
    btn.title = "Please connect your wallet first";
  });

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
    updateContractLink(membershipContractLinkEl, membershipState.contractId);
    updateContractLink(nonMembershipContractLinkEl, nonMembershipState.contractId);

    const membershipStorageUrl = membershipState.contractId
      ? Utils.explorerContractStorageUrl(membershipState.contractId)
      : '#';
    const nonMembershipStorageUrl = nonMembershipState.contractId
      ? Utils.explorerContractStorageUrl(nonMembershipState.contractId)
      : '#';

    membershipRootEl.textContent = membershipState.root || '--';
    membershipRootEl.href = membershipStorageUrl;
    membershipLevelsEl.textContent = membershipState.levels ?? '--';
    membershipLevelsEl.href = membershipStorageUrl;
    membershipNextIndexEl.textContent = membershipState.nextIndex ?? '--';
    membershipNextIndexEl.href = membershipStorageUrl;
    nonMembershipRootEl.textContent = nonMembershipState.root || '--';
    nonMembershipRootEl.href = nonMembershipStorageUrl;

    setStatus('State loaded', 'ok');
  } catch (err) {
    setStatus('State load error', 'error');
  }
}

// -----------------------------
// Admin transaction card
// -----------------------------
// The kind of contract a pasted admin call targets, which decides how its
// error codes read. A contract the page does not list is `unknown`, and the
// card marks it, since signers would otherwise read it as a pool.
function kindOf(contractId) {
  if (contractId === membershipContractInput.value.trim()) return 'asp-membership';
  if (contractId === nonMembershipContractInput.value.trim()) return 'asp-non-membership';
  return 'unknown';
}

function formatAdminCall({ source, sequence, fee, validUntil, contract, method, args }, kind) {
  // Every number a blocklist call takes is a key or its value, which signers
  // compare with the note public keys they were asked to list or release.
  const number = kind === 'asp-non-membership' ? blocklistKeyToNoteKey : (value) => value.toString();
  return [
    `Source: ${source}`,
    `Sequence: ${sequence}`,
    `Maximum fee: ${fee} stroops`,
    `Valid until: ${new Date(validUntil * 1000).toISOString()}`,
    `Contract: ${contract}${kind === 'unknown' ? ' (not a contract this page lists)' : ''}`,
    `Function: ${method}`,
    `Arguments: ${JSON.stringify(args, (_, value) => (typeof value === 'bigint' ? number(value) : value))}`,
  ].join('\n');
}

// Describes the envelope in the card. `kind` is the kind of contract the call
// targets when the page built it, and is read from the contract otherwise.
function renderAdminTx(kind) {
  const xdr = adminTxXdrInput.value.trim();
  state.adminTxKind = null;
  adminTxSignaturesEl.textContent = '0';
  adminTxDescriptionEl.textContent = '';
  if (!xdr) return;
  if (!state.networkPassphrase) {
    adminTxDescriptionEl.textContent = 'Connect your wallet to read the transaction.';
    return;
  }
  try {
    const call = describeAdminCall(xdr, state.networkPassphrase);
    const count = signatureCount(xdr, state.networkPassphrase);
    state.adminTxKind = kind ?? kindOf(call.contract);
    adminTxDescriptionEl.textContent = formatAdminCall(call, state.adminTxKind);
    adminTxSignaturesEl.textContent = count;
    // The threshold is read from the network after the card is drawn. "Sign"
    // reads it again, so a failed read leaves only the count.
    rpcServer(state.rpcUrl).getAccountEntry(call.source).then((account) => {
      if (adminTxXdrInput.value.trim() === xdr) adminTxSignaturesEl.textContent = `${count} of ${signingRule(account).threshold}`;
    }, () => {});
  } catch (err) {
    adminTxDescriptionEl.textContent = `Not an admin call: ${err.message}`;
  }
}

function loadAdminTx(xdr, kind) {
  adminTxXdrInput.value = xdr;
  renderAdminTx(kind);
}

// Builds an admin call to a contract of the given kind into the card.
async function prepareAdminCall(kind, call) {
  const { xdr } = await buildAdminCall({
    rpcUrl: state.rpcUrl,
    networkPassphrase: state.networkPassphrase,
    ...call,
  });
  loadAdminTx(xdr, kind);
  setStatus('Admin call built. Each signer signs it, then submit it.', 'ok');
}

async function signAdminTx() {
  try {
    ensureWalletConnected();
    // The card sets a kind only once it has described the envelope.
    if (!state.adminTxKind) throw new Error('Only an envelope the card can describe can be signed');
    const envelope = adminTxXdrInput.value.trim();
    const { source } = describeAdminCall(envelope, state.networkPassphrase);
    const rule = signingRule(await rpcServer(state.rpcUrl).getAccountEntry(source));
    const refusal = signRefusal(rule, envelope, state.networkPassphrase, state.address);
    if (refusal) throw new Error(refusal);
    const { signedTxXdr } = await signWalletTransaction(envelope, { networkPassphrase: state.networkPassphrase, address: state.address });
    loadAdminTx(signedTxXdr, state.adminTxKind);
    showToast('Signed. Pass the XDR to the next signer, or submit it.', 'success');
  } catch (err) {
    showToast(`Signing failed: ${explainFailure(err, state.adminTxKind)}`, 'error');
  }
}

async function submitAdminTx() {
  try {
    ensureWalletConnected();
    setStatus('Submitting the admin transaction...', 'info');
    await submitAdminCall({
      rpcUrl: state.rpcUrl,
      networkPassphrase: state.networkPassphrase,
      xdr: adminTxXdrInput.value.trim(),
    });
    setStatus('Admin transaction succeeded', 'ok');
    showToast('Admin transaction succeeded', 'success');
    loadAdminTx('');
    await refreshState();
  } catch (err) {
    setStatus('Admin transaction failed', 'error');
    showToast(`Admin transaction failed: ${explainFailure(err, state.adminTxKind)}`, 'error');
  }
}

async function copyAdminTx() {
  try {
    await navigator.clipboard.writeText(adminTxXdrInput.value.trim());
    showToast('Transaction XDR copied', 'success');
  } catch (err) {
    showToast(`Copy failed: ${err.message}`, 'error');
  }
}

// -----------------------------
// Admin calls
// -----------------------------
// Reads a contract's admin from its `Admin` entry, which every contract
// stores, while contracts deployed before the two-step admin transfer have no
// `get_admin` entry point. The admin is the source of every call the page
// builds for that contract.
async function storedAdmin(contractId) {
  const { val } = await rpcServer(state.rpcUrl).getContractData(contractId, xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('Admin')]));
  return scValToNative(val.contractData.val);
}

// Returns a client that reads a contract by simulation, with no account to sign.
function readClient(contractId) {
  return contract.Client.from({
    rpcUrl: state.rpcUrl,
    networkPassphrase: state.networkPassphrase,
    contractId,
    server: rpcServer(state.rpcUrl),
  });
}

async function insertMembershipLeaf() {
  const originalText = addToAllowlistBtn.textContent;
  try {
    ensureWalletConnected();
    const contractId = membershipContractInput.value.trim();
    if (!contractId) throw new Error('Membership contract ID is required');

    const notePublicKey = allowlistPublicKeyInput.value.trim();
    if (parseBigIntInput(notePublicKey, 'Public key') === null) {
      throw new Error('User note public key is required');
    }

    const aspSecret = allowlistAspSecretInput.value.trim();
    if (parseBigIntInput(aspSecret, 'ASP secret') === null) {
      throw new Error('ASP secret is required');
    }

    addToAllowlistBtn.disabled = true;
    addToAllowlistBtn.textContent = 'Processing...';

    setStatus('Building the allowlist insert...', 'info');
    await ensureCryptoReady();

    const leafHex = await deriveAspUserLeaf(notePublicKey, aspSecret);
    const leafValue = BigInt(leafHex);

    await prepareAdminCall('asp-membership', {
      source: await storedAdmin(contractId),
      contractId,
      method: 'insert_leaf',
      args: { leaf: leafValue },
    });

    allowlistPublicKeyInput.value = '';
    allowlistAspSecretInput.value = '';
  } catch (err) {
    setStatus('Allowlist insert failed', 'error');
    showToast(`Allowlist insert failed: ${explainFailure(err, 'asp-membership')}`, 'error');
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

    const keys = parseBlocklistKeys(blocklistPublicKeyInput.value);
    if (keys.length === 0) throw new Error('User note public key is required');

    addToBlocklistBtn.disabled = true;
    addToBlocklistBtn.textContent = 'Processing...';

    setStatus('Building the blocklist insert...', 'info');
    const call = blocklistInsertCall(keys, Boolean((await readClient(contractId)).insert_leaves));
    await prepareAdminCall('asp-non-membership', { source: await storedAdmin(contractId), contractId, ...call });

    blocklistPublicKeyInput.value = '';
  } catch (err) {
    setStatus('Blocklist insert failed', 'error');
    showToast(`Blocklist insert failed: ${explainFailure(err, 'asp-non-membership')}`, 'error');
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

    const [keyValue, ...others] = parseBlocklistKeys(blocklistPublicKeyInput.value);
    if (keyValue === undefined) throw new Error('User note public key is required');
    if (others.length > 0) throw new Error('Remove takes one note public key at a time');

    removeFromBlocklistBtn.disabled = true;
    removeFromBlocklistBtn.textContent = 'Processing...';

    setStatus('Building the blocklist removal...', 'info');
    await prepareAdminCall('asp-non-membership', {
      source: await storedAdmin(contractId),
      contractId,
      method: 'delete_leaf',
      args: { key: keyValue },
    });

    blocklistPublicKeyInput.value = '';
  } catch (err) {
    setStatus('User key removal from the blocklist failed', 'error');
    showToast(`User key removal from the blocklist failed: ${explainFailure(err, 'asp-non-membership')}`, 'error');
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

addToAllowlistBtn.addEventListener('click', insertMembershipLeaf);
addToBlocklistBtn.addEventListener('click', insertNonMembershipLeaf);
removeFromBlocklistBtn.addEventListener('click', removeNonMembershipLeaf);

adminTxXdrInput.addEventListener('input', () => renderAdminTx());
signAdminTxBtn.addEventListener('click', signAdminTx);
submitAdminTxBtn.addEventListener('click', submitAdminTx);
copyAdminTxBtn.addEventListener('click', copyAdminTx);

membershipContractInput?.addEventListener('input', () => {
  updateContractLink(membershipContractLinkEl, membershipContractInput.value.trim());
});
nonMembershipContractInput?.addEventListener('input', () => {
  updateContractLink(nonMembershipContractLinkEl, nonMembershipContractInput.value.trim());
});

async function init() {
  setStatus('Initializing...', 'info');
  await loadExplorerSetting();
  await ensureCryptoReady();
  await refreshState();
  await initGvkAuditPanel({
    ensureCryptoReady,
    showToast,
    getWalletAccount: () =>
      state.address
        ? { userAddress: state.address, networkPassphrase: state.networkPassphrase }
        : null,
  });
  setStatus('Ready', 'ok');
}

init().catch(err => {
  setStatus('Init failed', 'error');
  console.error('Init error:', err);
});
