import { contract } from '@stellar/stellar-sdk';
import { client, initializeRuntime, bootnodeRequired, ensureStorage, deriveAspUserLeaf } from './wasm-facade.js';
import { connectWallet, getConnectedAddress, getWalletNetwork, signWalletAuthEntry, signWalletTransaction, startWalletWatcher } from './wallet.js';
import { createPinnedSigner } from './wallet-signer-guard.js';
import { createWalletSessionMonitor, requireTestnetNetwork, UNREADABLE_WALLET_MESSAGE } from './wallet-session-policy.js';
import { beginPoolOp, endPoolOp, hasInFlightPoolOps, waitForPoolOpsToDrainNotified } from './pool-ops.js';
import { isDbLockedError, showDbLockedModal } from './db-locked.js';
import { friendlyErrorMessage } from './facade-errors.js';
import { App, Utils } from './ui/core.js';

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
  network: null,
  networkPassphrase: null,
  rpcUrl: null,
  contracts: null,
  membershipClient: null,
  nonMembershipClient: null,
  // Cache keys now carry the signing identity, not just the contract ID. A
  // contract.Client is built around a signer pinned to one address and one
  // passphrase (see contractClient below), so a client cached under the
  // contract ID alone would be handed back after an account change and sign
  // as the previous account.
  membershipClientKey: null,
  nonMembershipClientKey: null,
  // Distinct from any real address, including null (init()'s pre-connect state).
  cryptoReadyForAddress: Symbol('never-initialized'),
  adminInsertOnly: null,
  stopWatcher: null,
  pendingChange: false,
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

/**
 * Clear the ASP-secret field. Called from the insert's `finally`, from
 * disconnect() and on pagehide, so the secret does not outlive the submission
 * it was typed for.
 */
function clearAspSecretInput() {
  if (allowlistAspSecretInput) allowlistAspSecretInput.value = '';
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

/** Read and guard the wallet's network. The only writer of state.network/rpcUrl. */
async function refreshNetwork() {
  const net = requireTestnetNetwork(await getWalletNetwork());
  state.network = net.network;
  state.networkPassphrase = net.networkPassphrase;
  state.rpcUrl = net.sorobanRpcUrl;
  return net;
}

/**
 * Re-read the wallet immediately before a privileged write.
 *
 * The watcher polls every two seconds, so `state` can be stale at the moment
 * of the click. This page is privileged, so it does not rely on watcher timing:
 * it re-confirms the network and the active account synchronously each time.
 * getConnectedAddress() never prompts and returns null when the wallet is
 * locked or has not granted this origin — a write must not proceed then.
 *
 * Read-only paths are left unguarded so the page stays usable for inspection.
 */
async function requireWritableSession() {
  const net = requireTestnetNetwork(await getWalletNetwork());
  if (state.networkPassphrase && net.networkPassphrase !== state.networkPassphrase) {
    throw new Error('Freighter network changed. Reconnect before submitting.');
  }
  const active = await getConnectedAddress();
  if (!active) {
    throw new Error('Freighter is not reporting an active account for this site. Reconnect before submitting.');
  }
  if (active !== state.address) {
    throw new Error('Freighter is on a different account than this page connected as. Reconnect before submitting.');
  }
  return net;
}

/**
 * Build (or reuse) a contract.Client bound to the connected admin account.
 *
 * The signer is wallet.js's adapter with this page's identity pinned, so
 * contract.Client cannot override it.
 */
async function contractClient(slot, contractId) {
  ensureWalletConnected();
  const key = `${contractId}|${state.address}|${state.networkPassphrase}`;
  if (state[`${slot}Client`] && state[`${slot}ClientKey`] === key) {
    return state[`${slot}Client`];
  }
  const signer = createPinnedSigner(
    { signTransaction: signWalletTransaction, signAuthEntry: signWalletAuthEntry },
    { address: state.address, networkPassphrase: state.networkPassphrase },
  );
  const built = await contract.Client.from({
    rpcUrl: state.rpcUrl,
    networkPassphrase: state.networkPassphrase,
    publicKey: state.address,
    signTransaction: signer.signTransaction,
    signAuthEntry: signer.signAuthEntry,
    contractId,
  });
  state[`${slot}Client`] = built;
  state[`${slot}ClientKey`] = key;
  return built;
}

const getMembershipClient = (contractId) => contractClient('membership', contractId);
const getNonMembershipClient = (contractId) => contractClient('nonMembership', contractId);

function forgetContractClients() {
  state.membershipClient = null;
  state.nonMembershipClient = null;
  state.membershipClientKey = null;
  state.nonMembershipClientKey = null;
}

async function ensureCryptoReady() {
  // Keyed on the address the runtime was last built for, so this re-runs once
  // a real address replaces the pre-connect null.
  if (state.cryptoReadyForAddress !== state.address) {
    setStatus('Loading app...', 'info');
    // One guarded read, recorded in `state`; no second opinion, and no
    // hard-coded fallback endpoint to disagree with it.
    if (!state.rpcUrl) await refreshNetwork();
    const sorobanRpcUrl = state.rpcUrl;
    try {
      const storage = await ensureStorage();
      if (await bootnodeRequired(sorobanRpcUrl)) {
        if (!(await storage.getStoredBootnodeUrl(state.address))) {
          throw new Error('RPC_SYNC_GAP: bootnode required');
        }
      }
      await initializeRuntime(sorobanRpcUrl, { address: state.address });
      await client().backgroundSync();
    } catch (e) {
      if (isDbLockedError(e?.message)) showDbLockedModal(e.message);
      throw e;
    }
    state.cryptoReadyForAddress = state.address;
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
    // Guarded, and the only network read on this path: no second
    // getWalletNetwork() call to disagree with it, and no hard-coded
    // soroban-testnet fallback standing in for a wallet that reported no RPC
    // endpoint at all.
    const net = await refreshNetwork();
    state.address = address;
    await ensureCryptoReady();

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

    forgetContractClients();

    // Observe the live wallet from here on. This page had no watcher at all,
    // so an account or network switch after connect left it signing under one
    // identity while every label on screen named another.
    startWatcher();

    updateAdminInsertOnlyDisplay(state.adminInsertOnly);
    setStatus('Wallet connected', 'ok');
    showToast(`Connected: ${shortAddress(address)}`, 'success');

  } catch (err) {
    // startWatcher() can throw after the address and buttons are already set,
    // so unwind rather than advertise a session the page does not have.
    if (state.address) disconnect();
    if (err.code === 'USER_REJECTED') {
      setStatus('Connection cancelled', 'info');
    } else {
      setStatus('Wallet error', 'error');
      // The network guard's message names the actual problem ("testnet only",
      // "no RPC URL"); replacing it with a generic failure string would hide
      // the one thing the admin can act on.
      showToast(err?.message || 'Wallet connection failed', 'error');
    }
  }
}

/**
 * Watch the wallet for account and network changes.
 *
 * Detection is shared with the main app; the response is simpler here. This
 * page holds no per-account key material, so there is nothing to re-bind to
 * and every change ends the session. Contract state stays on screen and
 * refreshable; only the write controls are disabled.
 */
function startWatcher() {
  if (state.stopWatcher) return;
  // One monitor per watcher, so a streak cannot outlive its session.
  const monitor = createWalletSessionMonitor();
  state.stopWatcher = startWalletWatcher({
    intervalMs: 2_000,
    onChange: async (info) => {
      if (!state.address) return;
      const { networkChanged, changed, sessionUnverifiable } = monitor.observe(info, state);
      // The watcher answered but could not say which account is
      // active, for long enough that this is not a blip. This page used to
      // read that as "nothing changed" and stay connected with the allowlist
      // and blocklist controls enabled, under an identity it could no longer
      // confirm.
      if (sessionUnverifiable) {
        await endSession(UNREADABLE_WALLET_MESSAGE);
        return;
      }
      if (!changed) return;
      await endSession(
        networkChanged
          ? 'Freighter network changed. Reconnect to continue.'
          : 'Freighter account changed. Reconnect to continue.',
      );
    },
  });
}

/**
 * End the wallet session for a reason the admin must act on.
 *
 * The try/finally matters — if disconnect() throws, pendingChange would stay
 * true and mute every later change.
 */
async function endSession(message) {
  if (state.pendingChange) return;
  state.pendingChange = true;
  try {
    // Do not sever state out from under a submission already awaiting a
    // signature. pool-ops.js holds the in-flight counter; its name
    // is the main app's, but the module is generic and this page loads its own
    // instance, so there is no cross-page interaction.
    if (hasInFlightPoolOps()) {
      await waitForPoolOpsToDrainNotified({
        onTimeout: () => console.warn(
          '[admin] pool operations did not drain in time; disconnecting anyway',
        ),
      });
    }
    disconnect();
    showToast(message, 'info', 6000);
  } finally {
    state.pendingChange = false;
  }
}

function disconnect() {
  state.stopWatcher?.();
  state.stopWatcher = null;
  state.address = null;
  state.network = null;
  state.networkPassphrase = null;
  state.rpcUrl = null;
  forgetContractClients();
  // A disconnect is an exit path for the ASP secret too: the field must not
  // keep holding it for whoever connects next.
  clearAspSecretInput();

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
    updateAdminInsertOnlyDisplay(membershipState.adminInsertOnly);
    nonMembershipRootEl.textContent = nonMembershipState.root || '--';
    nonMembershipRootEl.href = nonMembershipStorageUrl;

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

    await requireWritableSession();
    const mClient = await getMembershipClient(contractId);
    beginPoolOp();
    try {
      const tx = await mClient.set_admin_insert_only({ admin_only: newValue });
      await tx.signAndSend();
    } finally {
      endPoolOp();
    }

    setStatus('Setting updated', 'ok');
    showToast(`Admin-only insert ${newValue ? 'enabled' : 'disabled'}`, 'success');
    await refreshState();
  } catch (err) {
    setStatus('Toggle failed', 'error');
    showToast(err?.message || 'Failed to toggle admin-only insert', 'error');
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

    setStatus('Computing and submitting allowlist insert transaction...', 'info');
    await ensureCryptoReady();
    // Checked here, before the secret is used for anything, so a wrong network costs the
    // admin a retype rather than a leaf inserted into a tree on a chain the
    // pool does not read.
    await requireWritableSession();

    const leafHex = await deriveAspUserLeaf(notePublicKey, aspSecret);
    const leafValue = BigInt(leafHex);

    const mClient = await getMembershipClient(contractId);
    beginPoolOp();
    try {
      const tx = await mClient.insert_leaf({ leaf: leafValue });
      await tx.signAndSend();
    } finally {
      endPoolOp();
    }

    setStatus('The allowlist insert transaction sent', 'ok');
    showToast('Added to the allowlist successfully', 'success');
    allowlistPublicKeyInput.value = '';
    await refreshState();
  } catch (err) {
    setStatus('Allowlist insert failed', 'error');
    // err.message is a validation label, a wallet error or an RPC error; none
    // of them carry the secret. It is interpolated deliberately so the admin
    // can tell a rejected signature from a wrong network.
    showToast(`Allowlist insert failed: ${err.message}`, 'error');
  } finally {
    // Every exit path, not just success: thrown validation errors, a declined
    // signature, an RPC failure and the happy path all land here.
    clearAspSecretInput();
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
    await requireWritableSession();
    const nmClient = await getNonMembershipClient(contractId);
    beginPoolOp();
    try {
      const tx = await nmClient.insert_leaf({ key: keyValue, value: valueValue });
      await tx.signAndSend();
    } finally {
      endPoolOp();
    }

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
    await requireWritableSession();
    const nmClient = await getNonMembershipClient(contractId);
    beginPoolOp();
    try {
      const tx = await nmClient.delete_leaf({ key: keyValue });
      await tx.signAndSend();
    } finally {
      endPoolOp();
    }

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

membershipContractInput?.addEventListener('input', () => {
  updateContractLink(membershipContractLinkEl, membershipContractInput.value.trim());
});
nonMembershipContractInput?.addEventListener('input', () => {
  updateContractLink(nonMembershipContractLinkEl, nonMembershipContractInput.value.trim());
});

// Navigation away is an exit path too, and the only one the handlers above
// cannot reach. `pagehide` rather than `beforeunload`: it also fires when the
// page enters the back/forward cache, which is precisely the case where the
// DOM survives with the field still populated and can be restored later.
window.addEventListener('pagehide', () => {
  clearAspSecretInput();
});

async function init() {
  setStatus('Initializing...', 'info');
  await loadExplorerSetting();
  await ensureCryptoReady();
  await refreshState();
  setStatus('Ready', 'ok');
}

init().catch(err => {
  setStatus('Init failed', 'error');
  // The network guard fires on this path (refreshNetwork -> ensureCryptoReady).
  // Leaving it in the console only would present a wrong-network wallet as an
  // unexplained dead page.
  showToast(err?.message || 'Initialization failed', 'error', 8000);
  console.error('Init error:', err);
});
