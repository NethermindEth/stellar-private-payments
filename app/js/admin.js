import { deploymentDefaults } from './network-config.js';
import { StrKey, contract, scValToNative, xdr } from '@stellar/stellar-sdk';
import { client, initializeRuntime, bootnodeRequired, ensureStorage, deriveAspUserLeaf, loadDeploymentConfig, isStorageUnlocked, lockStorage, storageWasLocked, STORAGE_STATE_EVENT } from './wasm-facade.js';
import { explorerPreference } from './public-settings.js';
import { connectWallet, getWalletNetwork, signWalletAuthEntry, signWalletTransaction } from './wallet.js';
import { isDbLockedError, showDbLockedModal } from './db-locked.js';
import { friendlyErrorMessage } from './facade-errors.js';
import { App, Utils } from './ui/core.js';
import { initGvkAuditPanel } from './admin-gvk.js';
import { NoAnswer, adminTxFromHash, adminTxLink, buildAdminCall, custodyProblems, deadCall, describeAdminCall, explainFailure, maxEntryTtl, newAdminRefusal, repointsTo, rpcServer, shortAddress, signatureCount, signedBy, signedWeight, signerStatus, signingRule, signRefusal, submitAdminCall } from './admin-transactions.js';
import { blocklistInsertCall, blocklistKeyToNoteKey, parseBlocklistKeys } from './blocklist-keys.js';
import { adminLine, allowlistLeavesFromEvents, blocklistKeys, codeLine, compareEntries, entriesLine, eventsSince, historyStart, levelsLine, manifestLine, parseRecords, readInstance, replacesLine, unusedListWarning, usesList } from './tree-check.js';
import { addSignature, authorizationPreimage, buildPauseAuthorization, countedEntry, decodeAuthorization, depositsPaused, describeAuthorization, encodeAuthorization, ledgerDate, mergeSignatures, nonceSpent, pauseFileProblem, pauseFileState, pauseFileWeight, pauseTransaction, uncountedSigners, verifySignatures, walletSignature } from './pause-authorization.js';

// DOM element references
const statusEl = document.getElementById('status');
const networkChip = document.getElementById('networkChip');
const syncDot = document.getElementById('sync-dot');
const walletChip = document.getElementById('walletChip');
const storageLockBtn = document.getElementById('storage-lock-btn');
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
const adminTxCardEl = document.getElementById('admin-transaction');
const adminTxXdrInput = document.getElementById('adminTxXdr');
const adminTxDescriptionEl = document.getElementById('adminTxDescription');
const adminTxSignaturesEl = document.getElementById('adminTxSignatures');
const adminTxSignaturesLineEl = document.getElementById('adminTxSignaturesLine');
const adminTxSignersEl = document.getElementById('adminTxSigners');
const adminTxNoticeEl = document.getElementById('adminTxNotice');
const submitAdminTxBtn = document.getElementById('submitAdminTxBtn');
const copyAdminTxBtn = document.getElementById('copyAdminTxBtn');
const copyAdminTxLinkBtn = document.getElementById('copyAdminTxLinkBtn');

// Pools tab
const poolRowsEl = document.getElementById('poolRows');
const poolsNoticeEl = document.getElementById('poolsNotice');
const poolRowTemplate = document.getElementById('tpl-pool-row');

// Re-point panel
const repointPoolSelect = document.getElementById('repointPool');
const repointKindSelect = document.getElementById('repointKind');
const repointTreeInput = document.getElementById('repointTree');
const repointRecordsInput = document.getElementById('repointRecords');
const repointRecordsNameEl = document.getElementById('repointRecordsName');
const clearRepointRecordsBtn = document.getElementById('clearRepointRecordsBtn');
const repointChecksEl = document.getElementById('repointChecks');
const checkRepointBtn = document.getElementById('checkRepointBtn');
const buildRepointBtn = document.getElementById('buildRepointBtn');

// Pre-signed deposit pauses panel
const pauseAuthPoolSelect = document.getElementById('pauseAuthPool');
const pauseAuthFilesInput = document.getElementById('pauseAuthFiles');
const pauseAuthResultsEl = document.getElementById('pauseAuthResults');
const pauseAuthFileListEl = document.getElementById('pauseAuthFileList');
const pauseFileTemplate = document.getElementById('tpl-pause-file');
const buildPauseAuthBtn = document.getElementById('buildPauseAuthBtn');
const submitPauseAuthBtn = document.getElementById('submitPauseAuthBtn');
const pauseAuthHintEl = document.getElementById('pauseAuthHint');

// Admins tab
const adminRowsEl = document.getElementById('adminRows');
const adminsNoticeEl = document.getElementById('adminsNotice');
const adminRowTemplate = document.getElementById('tpl-admin-row');
const signerTemplate = document.getElementById('tpl-signer');

const ACTION_BUTTONS = [addToAllowlistBtn, addToBlocklistBtn, removeFromBlocklistBtn, submitAdminTxBtn, checkRepointBtn];

const state = {
  address: null,
  networkPassphrase: null,
  rpcUrl: null,
  contracts: null,
  adminTxKind: null,
  // The manifest's pools and added allowlists; `kindOf` reads a pasted call against them.
  pools: [],
  addedAllowlists: [],
  // Last re-point check, or its Done note.
  repoint: null,
  // Re-renders the card when its time bound passes.
  adminTxExpiry: null,
  // Pool -> the lists its policy uses. null until every pool is read.
  poolLists: null,
  // Each with its admin's signing rule.
  pauseFiles: [],
  // The latest refreshPauseFiles; an older one landing late is dropped.
  pauseRefresh: null,
  // Card or pause panel waiting on Freighter or the network. Set via setBusy.
  busy: false,
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

async function ensureCryptoReady({ unlock = false } = {}) {
  if (!state.cryptoReady) {
    setStatus('Loading app...', 'info');
    const { sorobanRpcUrl, ...network } = await getWalletNetwork();
    try {
      const storage = await ensureStorage({ unlock });
      const explorerSetting = await storage.getExplorerSetting().catch(() => null);
      App.state.settings.explorerBaseUrl = explorerPreference() || explorerSetting?.baseUrl || Utils.defaultExplorerBaseUrl;
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
  const preferred = explorerPreference();
  if (preferred) {
    App.state.settings.explorerBaseUrl = preferred;
    return;
  }
  if (!isStorageUnlocked()) {
    App.state.settings.explorerBaseUrl = Utils.defaultExplorerBaseUrl;
    return;
  }
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
    // The card keeps Submit off until it has read the admin account.
    renderAdminTx();

    setStatus('Wallet connected', 'ok');
    showToast(`Connected: ${shortAddress(address)}`, 'success');
    await refreshPools();
    await refreshAdmins();
    // The card reads a pasted call's kind against the contracts the tables load.
    renderAdminTx();

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
  renderAdminTx();
  resetRepoint();

  refreshPools();
  refreshAdmins();
  setStatus('Wallet disconnected', 'info');
  showToast('Wallet disconnected', 'info');
}

async function refreshState({ unlock = false } = {}) {
  try {
    setStatus('Loading contract state...', 'info');
    await ensureCryptoReady({ unlock });
    const appState = await client().aspState();
    const membershipState = appState.aspMembership;
    const nonMembershipState = appState.aspNonMembership;

    // Keep an address the operator entered; fill an empty one from the manifest.
    membershipContractInput.value ||= membershipState.contractId;
    nonMembershipContractInput.value ||= nonMembershipState.contractId;
    updateContractLink(membershipContractLinkEl, membershipContractInput.value);
    updateContractLink(nonMembershipContractLinkEl, nonMembershipContractInput.value);

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
  await refreshPools();
  await refreshAdmins();
}

// -----------------------------
// Admin transaction card
// -----------------------------
// Returns the kind of contract a pasted call targets, which decides how its
// error codes read. The card flags an unlisted contract as `unknown`.
function kindOf(contractId) {
  if (contractId === membershipContractInput.value.trim()) return 'asp-membership';
  if (contractId === nonMembershipContractInput.value.trim()) return 'asp-non-membership';
  if (state.pools.includes(contractId)) return 'pool';
  if (state.addedAllowlists.includes(contractId)) return 'asp-membership';
  return 'unknown';
}

// For status and toasts. The card shows the raw function, as Freighter does.
const CALL_NAMES = {
  pause_deposits: 'Pausing deposits',
  unpause_deposits: 'Unpausing deposits',
  update_asp_membership: 'Switching the allowlist',
  update_asp_non_membership: 'Switching the blocklist',
  insert_leaf: 'Adding the entry',
  insert_leaves: 'Adding the keys',
  delete_leaf: 'Removing the key',
  update_admin: 'Proposing the new admin',
  cancel_admin_transfer: 'Cancelling the admin transfer',
  accept_admin: 'Accepting the admin role',
};
const callName = (method) => CALL_NAMES[method] ?? method;

const KIND_LABELS = { pool: 'pool', 'asp-membership': 'allowlist', 'asp-non-membership': 'blocklist', unknown: 'not a contract this page lists' };

function formatAdminCall({ source, sequence, fee, validUntil, contract, method, args }, kind) {
  // Show blocklist keys as the note public keys signers were asked about.
  const number = kind === 'asp-non-membership' ? blocklistKeyToNoteKey : (value) => value.toString();
  return [
    `Source: ${source}`,
    `Sequence: ${sequence}`,
    `Maximum fee: ${fee} stroops`,
    `Valid until: ${new Date(validUntil * 1000).toISOString()}`,
    `Contract: ${contract} (${KIND_LABELS[kind]})`,
    `Function: ${method}`,
    `Arguments: ${JSON.stringify(args, (_, value) => (typeof value === 'bigint' ? number(value) : value))}`,
  ].join('\n');
}

const SIGNED_LABELS = new Map([[true, 'signed'], [false, 'not yet'], [null, 'cannot tell: not an ed25519 key']]);

// Describes the envelope and its signers in the card, and enables Submit only
// once the admin account is read. `kind` comes from the page when it built the
// call, and from the contract otherwise.
function renderAdminTx(kind) {
  const xdr = adminTxXdrInput.value.trim();
  clearTimeout(state.adminTxExpiry);
  // The re-point panel mirrors the card.
  renderRepoint();
  state.adminTxKind = null;
  adminTxSignaturesEl.textContent = '0';
  adminTxSignersEl.replaceChildren();
  adminTxDescriptionEl.textContent = '';
  adminTxNoticeEl.textContent = '';
  adminTxNoticeEl.classList.replace('text-amber-300', 'text-slate-400');
  submitAdminTxBtn.disabled = true;
  adminTxSignaturesLineEl.classList.toggle('hidden', !xdr || !state.networkPassphrase);
  copyAdminTxBtn.disabled = copyAdminTxLinkBtn.disabled = !xdr;
  if (!xdr) {
    adminTxNoticeEl.textContent = 'No admin call loaded. Build one above, or open a link from a signer.';
    return;
  }
  if (!state.networkPassphrase) {
    adminTxNoticeEl.textContent = 'Connect your wallet to read the transaction.';
    return;
  }
  try {
    const call = describeAdminCall(xdr, state.networkPassphrase);
    const count = signatureCount(xdr, state.networkPassphrase);
    state.adminTxKind = kind ?? kindOf(call.contract);
    adminTxDescriptionEl.textContent = formatAdminCall(call, state.adminTxKind);
    adminTxSignaturesEl.textContent = count;
    // setTimeout fires at once past 2^31 - 1 ms.
    const untilExpiry = call.validUntil * 1000 - Date.now() + 1000;
    if (untilExpiry > 1000) state.adminTxExpiry = setTimeout(() => renderAdminTx(state.adminTxKind), Math.min(untilExpiry, 2 ** 31 - 1));
    // A read landing after the card changed or the wallet disconnected is stale.
    const current = () => adminTxXdrInput.value.trim() === xdr && state.address;
    const server = rpcServer(state.rpcUrl);
    // Takes ~10 s when another transaction used the sequence number.
    adminTxSignersEl.replaceChildren(Object.assign(document.createElement('li'), { className: 'text-sm text-slate-400', textContent: 'Checking this call with the network...' }));
    server.getAccountEntry(call.source).then(async (account) => {
      if (!current()) return;
      const dead = await deadCall({ server, envelope: xdr, networkPassphrase: state.networkPassphrase, account, now: Date.now(), kind: state.adminTxKind });
      if (!current()) return;
      // Settle a call a co-signer sent, or one that died, as if sent here.
      if (dead) {
        await settleAdminTx(call, dead);
        return;
      }
      const rule = signingRule(account);
      const weight = signedWeight(rule, xdr, state.networkPassphrase);
      const signable = weight < rule.threshold;
      adminTxSignaturesEl.textContent = weight === count
        ? `${count} of ${rule.threshold}`
        : `${count}, weight ${weight} of ${rule.threshold}`;
      adminTxSignersEl.replaceChildren(...signerStatus(rule, xdr, state.networkPassphrase).map(({ key, signed }) =>
        signerItem(key, signed, signed === false && signable && ((button) => signAdminTx(key, button)), !signable)));
      // Same sequence number: Sign waits for any call in progress.
      setBusy(state.busy);
      submitAdminTxBtn.disabled = state.busy || signable;
    }).catch((err) => {
      if (!current()) return;
      adminTxSignersEl.replaceChildren();
      let text = `Couldn't check this call: ${err.message}`;
      // A reload would drop the call, so check again here.
      if (err instanceof NoAnswer) {
        text = 'Couldn\'t check this call: the network didn\'t answer. Checking again in 10 seconds.';
        clearTimeout(state.adminTxExpiry);
        state.adminTxExpiry = setTimeout(() => renderAdminTx(state.adminTxKind), 10_000);
      }
      // Keep an earlier warning, not the signing note.
      const prior = adminTxNoticeEl.classList.contains('text-amber-300') ? adminTxNoticeEl.textContent : '';
      warnAdminTx([prior, text].filter(Boolean).join(' '));
    });
  } catch (err) {
    adminTxSignaturesLineEl.classList.add('hidden');
    copyAdminTxLinkBtn.disabled = true;
    adminTxNoticeEl.textContent = `Not an admin call: ${err.message}`;
  }
}

// Freighter takes one request at a time, so the card and the pause panel share a lock.
function setBusy(busy) {
  state.busy = busy;
  adminTxSignersEl.querySelectorAll('.sign-as-btn').forEach((button) => {
    button.disabled = busy;
  });
  renderPauseFiles();
}

function refuseWhileBusy() {
  if (state.busy) showToast('Wait for the current step to finish.', 'info');
  return state.busy;
}

// `sign` adds a Sign button. `enough`: the threshold is met.
function signerItem(key, signed, sign, enough) {
  const item = signerTemplate.content.cloneNode(true).firstElementChild;
  item.querySelector('.signer-key').textContent = key;
  const status = item.querySelector('.signer-status');
  status.textContent = signed === false && enough ? 'not needed' : SIGNED_LABELS.get(signed);
  status.classList.add(signed ? 'text-emerald-300' : 'text-slate-400');
  const button = item.querySelector('.sign-as-btn');
  if (sign) {
    button.addEventListener('click', () => sign(button));
  } else {
    button.remove();
  }
  return item;
}

function loadAdminTx(xdr, kind) {
  adminTxXdrInput.value = xdr;
  renderAdminTx(kind);
}

// Builds an admin call into the card, and signs and submits it at once when the
// connected account's weight alone meets the source's threshold.
async function prepareAdminCall(kind, call) {
  if (state.busy) throw new Error('Wait for the current step to finish.');
  setBusy(true);
  let signed;
  try {
    let built;
    try {
      built = await buildAdminCall({
        rpcUrl: state.rpcUrl,
        networkPassphrase: state.networkPassphrase,
        ...call,
      });
    } catch (err) {
      // The card keeps the extend commands, which outlast the toast.
      if (err.extendCommands) {
        loadAdminTx('', kind);
        adminTxNoticeEl.textContent = '';
        adminTxDescriptionEl.textContent = [err.message, ...err.extendCommands].join('\n\n');
      }
      throw err;
    }
    loadAdminTx(built.xdr, kind);
    // The card reports an account it cannot read.
    const account = await rpcServer(state.rpcUrl).getAccountEntry(call.source).catch(() => null);
    const rule = account && signingRule(account);
    if (!rule || (rule.weights.get(state.address) ?? 0) < rule.threshold) {
      setStatus('Admin call built. Each signer signs it, then submit it.', 'ok');
      showToast('Built. Each signer signs it in the Admin Transaction card.', 'info');
      adminTxCardEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
      return;
    }
    try {
      setStatus('Sign the admin call in Freighter...', 'info');
      signed = await walletSign(built.xdr, state.address);
    } catch (err) {
      setStatus('Admin call built but not signed', 'error');
      showToast(`Signing failed, so the call stays in the card: ${explainFailure(err, kind)}`, 'error');
      return;
    }
  } finally {
    setBusy(false);
  }
  loadAdminTx(signed, kind);
  await submitAdminTx();
}

// Signs `envelope` with Freighter as `address`; Freighter switches to that
// account when it holds it.
async function walletSign(envelope, address) {
  const { signedTxXdr } = await signWalletTransaction(envelope, { networkPassphrase: state.networkPassphrase, address });
  // The wallet's own check passes a reply that names no signer.
  if (!signedBy(signedTxXdr, state.networkPassphrase, address)) throw new Error(`Freighter did not sign as ${shortAddress(address)}`);
  return signedTxXdr;
}

async function signAdminTx(signer, button) {
  if (state.busy) return;
  setBusy(true);
  button.textContent = 'Signing...';
  try {
    const envelope = adminTxXdrInput.value.trim();
    const call = describeAdminCall(envelope, state.networkPassphrase);
    const server = rpcServer(state.rpcUrl);
    const account = await server.getAccountEntry(call.source);
    // A co-signer may have sent it, or it died, since the Sign buttons were drawn.
    const dead = await deadCall({ server, envelope, networkPassphrase: state.networkPassphrase, account, now: Date.now(), kind: state.adminTxKind });
    if (dead) {
      showToast(dead.reason, dead.landed ? 'success' : 'info');
      await settleAdminTx(call, dead);
      return;
    }
    const rule = signingRule(account);
    const refusal = signRefusal(rule, envelope, state.networkPassphrase, signer);
    if (refusal) throw new Error(refusal);
    const signedTxXdr = await walletSign(envelope, signer);
    if (adminTxXdrInput.value.trim() !== envelope) throw new Error('The card changed while Freighter was signing. Sign again.');
    loadAdminTx(signedTxXdr, state.adminTxKind);
    // In the card: a toast would cover Copy link.
    adminTxNoticeEl.textContent = signedWeight(rule, signedTxXdr, state.networkPassphrase) >= rule.threshold
      ? 'Signed. That\'s enough signatures: press Submit.'
      : 'Signed. Press Copy link and send the new link to the next signer.';
  } catch (err) {
    const reason = err.code === 'SIGNER_ADDRESS_MISMATCH'
      ? `Freighter does not hold ${shortAddress(signer)}. Pass the link to that signer.`
      : explainFailure(err, state.adminTxKind);
    showToast(`Signing failed: ${reason}`, 'error');
  } finally {
    button.textContent = 'Sign';
    setBusy(false);
  }
}

async function submitAdminTx() {
  if (refuseWhileBusy()) return;
  setBusy(true);
  submitAdminTxBtn.disabled = true;
  submitAdminTxBtn.textContent = 'Submitting...';
  adminTxXdrInput.readOnly = true;
  let call;
  try {
    ensureWalletConnected();
    const envelope = adminTxXdrInput.value.trim();
    call = describeAdminCall(envelope, state.networkPassphrase);
    setStatus('Submitting the admin transaction...', 'info');
    await submitAdminCall({ rpcUrl: state.rpcUrl, networkPassphrase: state.networkPassphrase, xdr: envelope });
  } catch (err) {
    const reason = explainFailure(err, state.adminTxKind);
    setStatus('Admin transaction failed', 'error');
    showToast('Admin transaction failed. The card shows why.', 'error');
    renderAdminTx(state.adminTxKind);
    warnAdminTx(`Last submit: ${reason}`);
    return;
  } finally {
    setBusy(false);
    submitAdminTxBtn.textContent = 'Submit';
    adminTxXdrInput.readOnly = false;
  }
  setStatus('Admin transaction succeeded', 'ok');
  showToast(`${callName(call.method)}: done`, 'success');
  await settleAdminTx(call);
}

// Empties the card and re-reads the chain. Drops the check first so Build can't reuse it.
async function settleAdminTx(call, { landed = true, reason = '' } = {}) {
  resetRepoint();
  loadAdminTx('');
  if (!landed) warnAdminTx(reason);
  else if (reason) adminTxNoticeEl.textContent = reason;
  await refreshState();
  // Unless a new check started during the refresh.
  if (landed && !state.repoint && repointDescribes(call)) showRepointDone(call);
}

// Amber until the card renders again.
function warnAdminTx(text) {
  adminTxNoticeEl.textContent = text;
  adminTxNoticeEl.classList.replace('text-slate-400', 'text-amber-300');
}

async function copyText(text, what) {
  try {
    await navigator.clipboard.writeText(text);
    showToast(`${what} copied`, 'success');
  } catch (err) {
    showToast(`Copy failed: ${err.message}`, 'error');
  }
}

// -----------------------------
// Admin calls
// -----------------------------
// Reads a contract's admin from its `Admin` entry, which also works for
// contracts without `get_admin`. Every call the page builds uses it as source.
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
  if (refuseWhileBusy()) return;
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
    if (!confirmListWrite(contractId, true)) return;

    addToAllowlistBtn.disabled = true;
    addToAllowlistBtn.textContent = 'Processing...';

    setStatus('Building the allowlist insert...', 'info');
    await ensureCryptoReady({ unlock: true });

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

// Asks before writing to a list no pool uses, once every pool has been read.
function confirmListWrite(list, allowlist) {
  if (!state.poolLists) return true;
  const used = [...state.poolLists.values()].map((lists) => lists[allowlist ? 'allowlist' : 'blocklist']);
  const warning = unusedListWarning(list, used, allowlist);
  return !warning || window.confirm(warning);
}

async function insertNonMembershipLeaf() {
  if (refuseWhileBusy()) return;
  const originalText = addToBlocklistBtn.textContent;
  try {
    ensureWalletConnected();
    const contractId = nonMembershipContractInput.value.trim();
    if (!contractId) throw new Error('Non-membership contract ID is required');

    const keys = parseBlocklistKeys(blocklistPublicKeyInput.value);
    if (keys.length === 0) throw new Error('User note public key is required');
    if (!confirmListWrite(contractId, false)) return;

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
  if (refuseWhileBusy()) return;
  const originalText = removeFromBlocklistBtn.textContent;
  try {
    ensureWalletConnected();
    const contractId = nonMembershipContractInput.value.trim();
    if (!contractId) throw new Error('Non-membership contract ID is required');

    const [keyValue, ...others] = parseBlocklistKeys(blocklistPublicKeyInput.value);
    if (keyValue === undefined) throw new Error('User note public key is required');
    if (others.length > 0) throw new Error('Remove takes one note public key at a time');
    if (!confirmListWrite(contractId, false)) return;

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
// Pools
// -----------------------------
// Fills a table with the rows `rowsFor` builds from the manifest. Rows read
// contracts by simulation, so they need the connected wallet's network.
async function fillTable(rowsEl, noticeEl, noun, rowsFor) {
  rowsEl.replaceChildren();
  if (!state.rpcUrl) {
    noticeEl.textContent = `Connect your wallet to read the ${noun}.`;
    return;
  }
  try {
    rowsEl.replaceChildren(...(await Promise.all(rowsFor(await loadDeploymentConfig()))));
    noticeEl.textContent = '';
  } catch (err) {
    noticeEl.textContent = `The ${noun} could not be read: ${err.message}`;
  }
}

// Every manifest pool, disabled ones too: they still take deposits.
async function refreshPools() {
  state.poolLists = null;
  const lists = new Map();
  let listed = -1;
  await fillTable(poolRowsEl, poolsNoticeEl, 'pools', ({ pools }) => {
    state.pools = pools.map(({ poolContractId }) => poolContractId);
    [repointPoolSelect, pauseAuthPoolSelect].forEach((select) => {
      // Keep the operator's pick across a refresh.
      const chosen = select.value;
      select.replaceChildren(...state.pools.map((contractId) => new Option(shortAddress(contractId), contractId)));
      if (state.pools.includes(chosen)) select.value = chosen;
    });
    listed = state.pools.length;
    return state.pools.map((contractId) => poolRow(contractId, lists));
  });
  // One unread pool: can't tell which lists are unused.
  state.poolLists = lists.size === listed ? lists : null;
  await refreshPauseFiles();
}

// No `deposits_paused`, or unreadable: no buttons. Records the lists it uses in `lists`.
async function poolRow(contractId, lists) {
  const row = poolRowTemplate.content.cloneNode(true).firstElementChild;
  showAddress(row.querySelector('.pool-id'), contractId);
  const depositsEl = row.querySelector('.pool-deposits');
  try {
    const [pool, { stored }] = await Promise.all([readClient(contractId), readInstance(rpcServer(state.rpcUrl), contractId)]);
    const flags = stored.get('PolicyFlags');
    const used = (allowlist) => (usesList(flags, allowlist) ? stored.get(allowlist ? 'ASPMembership' : 'ASPNonMembership') : null);
    lists.set(contractId, { allowlist: used(true), blocklist: used(false) });
    row.querySelector('.pool-trees').replaceChildren(...[['Allowlist', 'ASPMembership', true], ['Blocklist', 'ASPNonMembership', false]].map(([label, key, allowlist]) => {
      const line = document.createElement('div');
      showAddress(line, stored.get(key));
      // Before the address, which a phone cuts off.
      const unused = !usesList(flags, allowlist);
      line.prepend(unused ? `${label} (not used) ` : `${label} `);
      line.classList.toggle('text-slate-400', unused);
      return line;
    }));
    if (!pool.deposits_paused) {
      depositsEl.textContent = 'cannot be paused: the pool has no deposits_paused entry point';
      row.querySelector('.pool-actions').remove();
      return row;
    }
    const [{ result }, admin] = await Promise.all([pool.deposits_paused(), storedAdmin(contractId)]);
    const paused = result.unwrap();
    depositsEl.textContent = paused ? 'paused' : 'open';
    // A pause on a paused pool changes nothing but still costs a signed transaction.
    const pause = row.querySelector('.pause-deposits-btn');
    const unpause = row.querySelector('.unpause-deposits-btn');
    pause.disabled = paused;
    unpause.disabled = !paused;
    pause.addEventListener('click', () => buildRowCall(pause, 'pool', { source: admin, contractId, method: 'pause_deposits' }));
    unpause.addEventListener('click', () => buildRowCall(unpause, 'pool', { source: admin, contractId, method: 'unpause_deposits' }));
  } catch (err) {
    depositsEl.textContent = `could not be read: ${err.message}`;
    row.querySelector('.pool-actions').remove();
  }
  return row;
}

// Builds a table row's call, holding the pressed button at its width until done.
async function buildRowCall(button, kind, call) {
  if (refuseWhileBusy()) return;
  const { disabled, textContent } = button;
  button.style.minWidth = `${button.offsetWidth}px`;
  button.disabled = true;
  button.textContent = 'Processing...';
  try {
    ensureWalletConnected();
    setStatus(`${callName(call.method)}: building the call...`, 'info');
    await prepareAdminCall(kind, call);
  } catch (err) {
    setStatus(`${callName(call.method)}: couldn't build the call`, 'error');
    showToast(`${callName(call.method)} failed: ${explainFailure(err, kind)}`, 'error');
  } finally {
    Object.assign(button, { disabled, textContent });
    button.style.minWidth = '';
  }
}

// -----------------------------
// Re-point
// -----------------------------
// Build waits for every line; a confirm line passes once ticked.
function renderRepoint() {
  const lines = state.repoint?.lines ?? [];
  const built = repointInCard();
  const passes = ({ ok, confirm, confirmed }) => ok || (Boolean(confirm) && Boolean(confirmed));
  // Once built, Build stays off: a rebuild drops the card's signatures.
  const note = document.createElement('li');
  const paintNote = () => {
    const ready = lines.length > 0 && lines.every(passes);
    const [text, className] = state.repoint?.done
      ? [state.repoint.done, 'text-emerald-300']
      : (!built ? ['', ''] : (ready
        ? ['Built. Signers sign it in the Admin Transaction card below.', 'text-cyan-200']
        : ['A box above is unticked, so don\'t sign the call in the card below.', 'text-rose-300']));
    Object.assign(note, { textContent: text, className });
    if (text) repointChecksEl.append(note);
    else note.remove();
    buildRepointBtn.disabled = built || !ready;
  };
  repointChecksEl.replaceChildren(...lines.map((line) => {
    const item = document.createElement('li');
    const text = document.createElement('span');
    item.append(text);
    const paint = () => {
      // Ticked means accepted, not passed.
      const [word, className] = line.ok ? ['OK', 'text-emerald-300'] : (line.confirm ? [line.confirmed ? 'ACCEPTED' : 'CONFIRM', 'text-amber-300'] : ['FAIL', 'text-rose-300']);
      item.className = className;
      text.textContent = `${word} ${line.label}: ${line.text}`;
    };
    if (line.confirm) {
      const box = Object.assign(document.createElement('input'), { type: 'checkbox', checked: Boolean(line.confirmed), className: 'mt-0.5 h-4 w-4 shrink-0 accent-cyan-400' });
      // Repaint only this line so the box keeps focus.
      box.addEventListener('change', () => {
        line.confirmed = box.checked;
        paint();
        paintNote();
      });
      const label = Object.assign(document.createElement('label'), { className: 'mb-1 mt-2 flex cursor-pointer items-start gap-3 font-sans text-sm text-slate-200' });
      label.append(box, line.confirm);
      item.append(label);
    }
    paint();
    return item;
  }));
  paintNote();
}

const repointMethod = (allowlist) => (allowlist ? 'update_asp_membership' : 'update_asp_non_membership');

// The card holds the checked re-point, unexpired.
function repointInCard() {
  const check = state.repoint;
  if (!check?.call || !state.networkPassphrase) return false;
  try {
    const call = describeAdminCall(adminTxXdrInput.value.trim(), state.networkPassphrase);
    return call.validUntil * 1000 > Date.now()
      && repointsTo(call, { pool: check.call.contractId, method: check.call.method, tree: check.tree, source: check.call.source });
  } catch {
    return false;
  }
}

const repointDescribes = (call) => repointsTo(call, {
  pool: repointPoolSelect.value,
  method: repointMethod(repointKindSelect.value === 'asp-membership'),
  tree: repointTreeInput.value.trim(),
});

function resetRepoint() {
  state.repoint = null;
  renderRepoint();
}

// Done note. Clears the address.
function showRepointDone({ contract, method, args: [tree] }) {
  const noun = method === 'update_asp_membership' ? 'allowlist' : 'blocklist';
  state.repoint = { lines: [], done: `Done. Pool ${shortAddress(contract)} now uses ${noun} ${shortAddress(tree)}.` };
  repointTreeInput.value = '';
  renderRepoint();
}

// Replaces and Code first; the rest only if the pool accepts the code.
async function checkRepoint() {
  resetRepoint();
  // Editing a field mid-check drops its result.
  const pending = {};
  state.repoint = pending;
  const originalText = checkRepointBtn.textContent;
  try {
    ensureWalletConnected();
    const pool = repointPoolSelect.value;
    const tree = repointTreeInput.value.trim();
    if (!pool || !tree) throw new Error('Choose a pool and enter the new contract address');
    const allowlist = repointKindSelect.value === 'asp-membership';

    checkRepointBtn.disabled = true;
    checkRepointBtn.textContent = 'Checking...';
    setStatus('Checking the contract...', 'info');
    const server = rpcServer(state.rpcUrl);
    const [manifest, admin, poolInstance, treeInstance] = await Promise.all([
      loadDeploymentConfig(),
      storedAdmin(pool),
      readInstance(server, pool),
      readInstance(server, tree),
    ]);
    // No answer on any line fails the whole check.
    const run = (checks) => Promise.all(checks.filter(Boolean).map(([label, check]) => check().then(
      (text) => ({ label, ok: true, text }),
      (err) => {
        if (err instanceof NoAnswer) throw err;
        return { label, ok: false, text: err.message, confirm: err.confirm };
      },
    )));
    // A list the policy ignores decides nothing: check only its code.
    const uses = usesList(poolInstance.stored.get('PolicyFlags'), allowlist);
    const [replaces, code] = await run([
      ['Replaces', async () => replacesLine(poolInstance.stored.get(allowlist ? 'ASPMembership' : 'ASPNonMembership'), tree)],
      ['Code', async () => {
        const client = await readClient(pool);
        if (!client.get_asp_wasm_hashes) {
          throw new Error('the pool has no get_asp_wasm_hashes entry point, so it accepts a contract running any code');
        }
        return codeLine((await client.get_asp_wasm_hashes()).result.unwrap(), treeInstance.wasmHash, allowlist);
      }],
    ]);
    const lines = !code.ok ? [replaces, code] : [replaces, code, ...(await run([
      !uses && [allowlist ? 'Allowlist' : 'Blocklist', async () => 'not used by this pool, so this changes nothing for users'],
      uses && allowlist && ['Levels', async () => {
        const levels = (await readInstance(server, poolInstance.stored.get('ASPMembership'))).stored.get('Levels');
        return levelsLine(levels, treeInstance.stored.get('Levels'));
      }],
      uses && ['Admin', async () => {
        const client = await readClient(tree);
        if (!client.get_admin) throw new Error('the contract has no get_admin entry point');
        return adminLine((await client.get_admin()).result.unwrap(), admin);
      }],
      uses && allowlist && ['App', async () => manifestLine(manifest, tree)],
      uses && ['Entries', async () => {
        const [file] = repointRecordsInput.files;
        const nextIndex = (contract = tree) => server.getContractData(contract, xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('NextIndex')]))
          .then(({ val }) => scValToNative(val.contractData.val));
        const keys = async (contract = tree, instance = treeInstance) => blocklistKeys(server, contract, instance.stored.get('Root'));
        // No file: compare with the pool's current list, which storage holds at any age.
        if (!file) {
          const current = poolInstance.stored.get(allowlist ? 'ASPMembership' : 'ASPNonMembership');
          const unreadable = (err) => {
            if (err instanceof NoAnswer) throw err;
            throw new Error(`couldn't read the pool's current list: ${err.message}. Add a file to compare with instead.`);
          };
          if (allowlist) {
            const [count, held] = await Promise.all([nextIndex(), nextIndex(current).catch(unreadable)]);
            return entriesLine(true, count, null, { current: held });
          }
          const [fresh, held] = await Promise.all([keys(), readInstance(server, current).then((instance) => keys(current, instance)).catch(unreadable)]);
          return entriesLine(false, fresh.length, null, { released: compareEntries(fresh, held).missing.length });
        }
        // Keys in Blocklist tab form, so a wrong byte order fails.
        const records = (allowlist ? parseRecords : parseBlocklistKeys)(await file.text());
        const onChain = allowlist
          ? await Promise.all([eventsSince(server, tree, historyStart({ tree, manifest })), nextIndex()])
            .then(([events, count]) => allowlistLeavesFromEvents(events, count))
            .catch((err) => {
              if (err instanceof NoAnswer) throw err;
              throw new Error(`${err.message}. Clear the file to check just the count.`);
            })
          : await keys();
        const { missing, unexpected } = compareEntries(onChain, records);
        const shown = allowlist ? (value) => `0x${value.toString(16)}` : blocklistKeyToNoteKey;
        return entriesLine(allowlist, onChain.length, { missing: missing.map(shown), unexpected: unexpected.map(shown) });
      }],
    ]))];
    if (state.repoint !== pending) return;
    setStatus('Contract checked', 'info');
    Object.assign(pending, {
      lines,
      tree,
      call: {
        source: admin,
        contractId: pool,
        method: repointMethod(allowlist),
        args: allowlist ? { new_asp_membership: tree } : { new_asp_non_membership: tree },
      },
    });
    renderRepoint();
  } catch (err) {
    setStatus('Contract check failed', 'error');
    // In the panel: a toast is gone in seconds.
    if (state.repoint === pending) {
      pending.lines = [{ label: 'Check', ok: false, text: err.message }];
      renderRepoint();
    }
  } finally {
    if (state.address) checkRepointBtn.disabled = false;
    checkRepointBtn.textContent = originalText;
  }
}

// -----------------------------
// Pre-signed deposit pauses
// -----------------------------
function offerFile(name, text) {
  Object.assign(document.createElement('a'), {
    href: `data:application/json;charset=utf-8,${encodeURIComponent(text)}`,
    download: name,
  }).click();
}

function reportPause(text) {
  pauseAuthResultsEl.append(Object.assign(document.createElement('li'), { textContent: text }));
}

// Everything that decides whether a file can pause its pool.
async function pauseChain({ admin, pool, nonce }) {
  const server = rpcServer(state.rpcUrl);
  const [account, poolAdmin, paused, { sequence }, ttl, spent] = await Promise.all([
    server.getAccountEntry(admin),
    storedAdmin(pool),
    depositsPaused(server, pool, state.networkPassphrase),
    server.getLatestLedger(),
    maxEntryTtl(server),
    nonceSpent(server, admin, nonce),
  ]);
  return { rule: signingRule(account), poolAdmin, paused, latestLedger: sequence, maxEntryTtl: ttl, spent };
}

// Match the admin too: the signed preimage omits it.
const heldPauseFile = ({ admin, pool, nonce, expirationLedger }) => state.pauseFiles.find(({ authorization: held }) =>
  held.admin === admin && held.pool === pool && held.nonce === nonce && held.expirationLedger === expirationLedger);

// A copy of a held file adds only what it lacks. Every signature is checked.
async function addPauseFile(authorization) {
  const chain = await pauseChain(authorization);
  const held = heldPauseFile(authorization);
  const opened = verifySignatures(authorization.entry, state.networkPassphrase);
  const checked = describeAuthorization(held ? mergeSignatures(held.authorization.entry, opened, state.networkPassphrase, chain.rule) : opened);
  // Opened from disk means saved; signatures a copy adds aren't.
  const file = held ?? { signing: new Set(), saved: true };
  if (held && checked.signers.length > held.authorization.signers.length) file.saved = false;
  Object.assign(file, chain, { authorization: checked, readError: null });
  if (!held) state.pauseFiles.push(file);
  renderPauseFiles();
  return file;
}

// Admin calls and signer changes can change what a file can do.
async function refreshPauseFiles() {
  const refresh = {};
  state.pauseRefresh = refresh;
  if (state.rpcUrl) {
    await Promise.all(state.pauseFiles.map((file) => pauseChain(file.authorization).then(
      (chain) => state.pauseRefresh === refresh && Object.assign(file, chain, { readError: null }),
      (err) => state.pauseRefresh === refresh && Object.assign(file, {
        readError: err instanceof NoAnswer
          ? 'Couldn\'t check this file: the network didn\'t answer. The page checks it again before it signs or pauses.'
          : `Couldn't check this file: ${err.message}`,
      }),
    )));
  }
  if (state.pauseRefresh === refresh) renderPauseFiles();
}

// Signatures only this page holds. A dead file has none worth keeping.
const unsaved = (file) => !file.saved && file.authorization.signers.length > 0 && !pauseFileProblem(file.authorization, file);

function renderPauseFiles() {
  const locked = state.busy || !state.address;
  buildPauseAuthBtn.disabled = locked;
  pauseAuthFilesInput.disabled = locked;
  const states = new Map(state.pauseFiles.map((file) => [file, pauseFileState(file.authorization, file)]));
  const ready = state.pauseFiles.filter((file) => states.get(file).ready || states.get(file).paused);
  const open = state.pauseFiles.filter((file) => states.get(file).ready);
  submitPauseAuthBtn.disabled = locked || open.length === 0;
  let hint = '';
  if (!state.address) hint = 'Connect your wallet first.';
  else if (locked) hint = 'Wait for the current step to finish.';
  else if (ready.length === 0) hint = 'To pause, you need a file marked Ready.';
  else if (open.length === 0) hint = `Deposits into ${[...new Set(ready.map(({ authorization: { pool } }) => shortAddress(pool)))].join(', ')} are already paused.`;
  pauseAuthHintEl.textContent = hint;
  pauseAuthFileListEl.replaceChildren(...state.pauseFiles.map((file) => {
    const { authorization: { pool, admin, nonce, expirationLedger, signers }, rule, latestLedger } = file;
    const item = pauseFileTemplate.content.cloneNode(true).firstElementChild;
    item.querySelector('.pause-file-pool').textContent = `Pool ${shortAddress(pool)}`;
    const { problem, short, paused } = states.get(file);
    const weight = pauseFileWeight(file.authorization, rule);
    // Zero-weight signatures are left out of the pause.
    const uncounted = uncountedSigners(file.authorization, rule).map(shortAddress);
    const counted = signers.length - uncounted.length;
    const count = weight === counted ? `${counted} of ${rule.threshold}` : `${counted}, weight ${weight} of ${rule.threshold}`;
    const until = `Works until about ${ledgerDate(expirationLedger, latestLedger)}.`;
    const status = item.querySelector('.pause-file-status');
    let text = `${count} signatures. Sign below, or save it for the next signer.`;
    if (problem) text = problem;
    else if (paused) text = `Ready. Deposits are already paused, so keep it for later. ${until}`;
    else if (!short) text = `Ready. ${until} Save it for whoever will pause deposits.`;
    if (!problem && uncounted.length > 0) {
      text += uncounted.length === 1
        ? ` ${uncounted[0]} doesn't sign for the admin, so its signature is left out.`
        : ` ${uncounted.join(', ')} don't sign for the admin, so their signatures are left out.`;
    }
    // A dead file keeps its reason. A live one keeps its buttons: Sign and Pause read it again.
    const readError = problem ? null : file.readError;
    status.textContent = readError ?? text;
    status.classList.add(readError ? 'text-amber-300' : (problem ? 'text-rose-300' : (short ? 'text-slate-300' : 'text-emerald-300')));
    const dead = Boolean(problem);
    item.querySelector('.pause-file-signers').replaceChildren(...[...(dead ? [] : rule.weights)]
      .filter(([key, keyWeight]) => keyWeight > 0 && StrKey.isValidEd25519PublicKey(key))
      .map(([key]) => {
        const signed = signers.includes(key);
        const signer = signerItem(key, signed, short && !signed && (() => signPauseFile(file, key)), weight >= rule.threshold);
        const button = signer.querySelector('.sign-as-btn');
        if (button) Object.assign(button, { disabled: locked, textContent: file.signing.has(key) ? 'Signing...' : 'Sign' });
        return signer;
      }));
    item.querySelector('.pause-file-details').textContent = `Pool ${pool} · admin ${admin} · nonce ${nonce} · expires at ledger ${expirationLedger}`;
    const save = item.querySelector('.save-pause-file-btn');
    if (dead) save.remove();
    save.addEventListener('click', () => {
      offerFile(`pause-${pool}-${nonce}${signers.length > 0 ? `-signed-${signers.length}` : ''}.json`, encodeAuthorization(file.authorization.entry));
      file.saved = true;
      setStatus('Pause file saved', 'ok');
    });
    const remove = item.querySelector('.remove-pause-file-btn');
    remove.disabled = state.busy;
    remove.addEventListener('click', () => {
      if (unsaved(file) && !window.confirm('Remove this pause file? Its signatures haven\'t been saved, so they will be lost.')) return;
      state.pauseFiles = state.pauseFiles.filter((held) => held !== file);
      pauseAuthResultsEl.replaceChildren();
      renderPauseFiles();
    });
    return item;
  }));
}

// Signs at once when the connected key can sign alone.
async function buildPauseFile() {
  if (refuseWhileBusy()) return;
  let file;
  try {
    ensureWalletConnected();
    const pool = pauseAuthPoolSelect.value;
    if (!pool) throw new Error('Choose a pool');
    pauseAuthResultsEl.replaceChildren();
    setBusy(true);
    const server = rpcServer(state.rpcUrl);
    const [admin, { sequence }, ttl] = await Promise.all([storedAdmin(pool), server.getLatestLedger(), maxEntryTtl(server)]);
    // Non-negative, so the file name carries no minus sign.
    const nonce = crypto.getRandomValues(new BigUint64Array(1))[0] >> 1n;
    const entry = buildPauseAuthorization({ admin, pool, nonce, latestLedger: sequence, maxEntryTtl: ttl });
    file = await addPauseFile(describeAuthorization(entry));
    setStatus('Pause file built', 'ok');
  } catch (err) {
    showToast(`Building the pause file failed: ${err.message}`, 'error');
  } finally {
    setBusy(false);
  }
  if (file && (file.rule.weights.get(state.address) ?? 0) >= file.rule.threshold) {
    setStatus('Sign the new pause file in Freighter...', 'info');
    await signPauseFile(file, state.address);
  }
}

// Clear the picker so the same file can be chosen again.
async function openPauseFiles() {
  const files = [...pauseAuthFilesInput.files];
  pauseAuthFilesInput.value = '';
  if (refuseWhileBusy()) return;
  pauseAuthResultsEl.replaceChildren();
  setBusy(true);
  for (const file of files) {
    try {
      ensureWalletConnected();
      await addPauseFile(decodeAuthorization(await file.text()));
    } catch (err) {
      showToast(`${file.name} could not be opened: ${err.message}`, 'error');
    }
  }
  setBusy(false);
}

// Freighter switches to `key` if it holds it.
async function signPauseFile(file, key) {
  if (refuseWhileBusy()) return;
  file.signing.add(key);
  setBusy(true);
  try {
    // Re-read: the chain may have changed since the Sign buttons were drawn.
    Object.assign(file, await pauseChain(file.authorization), { readError: null });
    if (!(file.rule.weights.get(key) > 0)) throw new Error(`${shortAddress(key)} no longer signs for the admin`);
    const { problem, short } = pauseFileState(file.authorization, file);
    if (problem) throw new Error(problem);
    if (!short) throw new Error('The file already has the signatures it needs');
    const { signedAuthEntry } = await signWalletAuthEntry(authorizationPreimage(file.authorization.entry, state.networkPassphrase), {
      networkPassphrase: state.networkPassphrase,
      address: key,
    });
    // The file may have left the panel, or merged with a copy, while Freighter was open.
    const held = heldPauseFile(file.authorization);
    if (!held) throw new Error('The file left the panel while Freighter was signing');
    held.authorization = describeAuthorization(addSignature(held.authorization.entry, key, walletSignature(signedAuthEntry), state.networkPassphrase));
    held.saved = false;
    setStatus(`Pause file signed as ${shortAddress(key)}`, 'ok');
  } catch (err) {
    const reason = err.code === 'SIGNER_ADDRESS_MISMATCH'
      ? `Freighter does not hold ${shortAddress(key)}. Save the file and pass it to that signer.`
      : err.message;
    setStatus('Pause file not signed', 'error');
    showToast(`Signing failed: ${reason}`, 'error');
  } finally {
    file.signing.delete(key);
    setBusy(false);
  }
}

// One line per pool; a failure stops no other. A pool already paused keeps its file.
async function sendPauseFiles(files) {
  setStatus('Pausing deposits...', 'info');
  const network = { rpcUrl: state.rpcUrl, networkPassphrase: state.networkPassphrase };
  let sent = 0;
  let failed = 0;
  for (const file of files) {
    const authorization = { ...file.authorization, entry: countedEntry(file.authorization.entry, file.rule) };
    const pool = shortAddress(authorization.pool);
    try {
      const built = await pauseTransaction({ ...network, source: state.address, authorization });
      if (built.paused) {
        reportPause(`${pool}: already paused. File kept for later.`);
        continue;
      }
      const { signedTxXdr } = await signWalletTransaction(built.xdr, { networkPassphrase: state.networkPassphrase, address: state.address });
      await submitAdminCall({ ...network, xdr: signedTxXdr });
      sent += 1;
      state.pauseFiles = state.pauseFiles.filter((held) => held !== file);
      reportPause(`${pool}: deposits paused`);
    } catch (err) {
      failed += 1;
      reportPause(`${pool}: not paused: ${explainFailure(err, 'pool')}`);
    }
  }
  const held = files.length - sent - failed;
  if (failed > 0) setStatus(`${failed} of ${files.length} pauses failed`, 'error');
  else setStatus(`Deposits paused in ${sent} pool${sent === 1 ? '' : 's'}${held > 0 ? `; ${held} already paused` : ''}`, 'ok');
}

// Re-reads each pool, asks, then sends every file that can pause.
async function submitPauseFiles() {
  if (refuseWhileBusy()) return;
  setBusy(true);
  submitPauseAuthBtn.textContent = 'Pausing...';
  pauseAuthResultsEl.replaceChildren();
  setStatus('Pausing deposits...', 'info');
  try {
    const files = [...state.pauseFiles];
    // Pool, signers or flag can change after opening; one unreadable file blocks no other.
    const reads = await Promise.allSettled(files.map((file) => pauseChain(file.authorization)));
    const sendable = files.filter((file, index) => {
      const read = reads[index];
      const pool = shortAddress(file.authorization.pool);
      if (read.status === 'rejected') {
        reportPause(`${pool}: not sent. Couldn't check this file: ${read.reason.message}`);
        return false;
      }
      Object.assign(file, read.value, { readError: null });
      // Its card may still say Ready, so say here why it's left out.
      const { problem, short, paused } = pauseFileState(file.authorization, file);
      const why = problem ? `not sent. ${problem}`
        : (short ? 'not sent. It needs more signatures.'
          : (paused ? 'already paused. File kept for later.' : null));
      if (why) reportPause(`${pool}: ${why}`);
      return !why;
    });
    const pools = [...new Set(sendable.map(({ authorization: { pool } }) => pool))];
    if (pools.length === 0) {
      setStatus('Nothing paused', 'error');
    } else if (window.confirm(`Pause deposits into ${pools.map(shortAddress).join(', ')} now? No one can deposit there until the admin unpauses.`)) {
      await sendPauseFiles(sendable);
    } else {
      setStatus('Nothing paused', 'info');
    }
  } catch (err) {
    setStatus('Pausing deposits failed', 'error');
    showToast(`Pausing deposits failed: ${err.message}`, 'error');
  } finally {
    submitPauseAuthBtn.textContent = 'Pause deposits now';
    setBusy(false);
  }
  await refreshPools();
}

// -----------------------------
// Admins
// -----------------------------
// Lists each contract the manifest names, a disabled pool too, with its admin
// and its pending admin.
function refreshAdmins() {
  return fillTable(adminRowsEl, adminsNoticeEl, 'admins', ({ pools, asp_membership, added_asp_memberships: added = [], asp_non_membership }) => {
    state.addedAllowlists = added.map(({ contractId }) => contractId);
    return [
      ...pools.map(({ poolContractId }) => ({ label: 'Pool', kind: 'pool', contractId: poolContractId })),
      { label: 'Allowlist', kind: 'asp-membership', contractId: asp_membership },
      ...added.map(({ contractId }) => ({ label: 'Added allowlist', kind: 'asp-membership', contractId })),
      { label: 'Blocklist', kind: 'asp-non-membership', contractId: asp_non_membership },
    ].map(adminRow);
  });
}

// Reports whether to propose `newAdmin`. No contract can read an account's
// signers, so the page checks custody.
async function confirmCustody(newAdmin) {
  let problems;
  if (StrKey.isValidContract(newAdmin)) {
    problems = ['it is a contract, which has no signers to read'];
  } else {
    try {
      problems = custodyProblems(await rpcServer(state.rpcUrl).getAccountEntry(newAdmin));
    } catch (err) {
      showToast(err instanceof NoAnswer ? `Couldn't check the new admin: ${err.message}` : `New admin ${err.message}`, 'error');
      return false;
    }
  }
  return problems.length === 0
    || window.confirm(`The new admin is not a multisig account: ${problems.join('; ')}.\n\nPropose it anyway?`);
}

function showAddress(cell, address) {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'transition hover:text-cyan-100';
  button.title = `${address} (click to copy)`;
  button.textContent = shortAddress(address);
  button.addEventListener('click', () => copyText(address, 'Address'));
  cell.replaceChildren(button);
}

// A contract without `get_pending_admin` hands over control at once on
// `update_admin`, and an unreadable contract shows its error; neither row gets
// buttons.
async function adminRow({ label, kind, contractId }) {
  const row = adminRowTemplate.content.cloneNode(true).firstElementChild;
  row.querySelector('.admin-label').textContent = label;
  showAddress(row.querySelector('.admin-contract'), contractId);
  const adminEl = row.querySelector('.admin-current');
  const pendingEl = row.querySelector('.admin-pending');
  try {
    const [admin, target] = await Promise.all([storedAdmin(contractId), readClient(contractId)]);
    showAddress(adminEl, admin);
    if (!target.get_pending_admin) {
      pendingEl.textContent = 'not available';
      row.querySelector('.admin-actions').remove();
      return row;
    }
    const { result: pending } = await target.get_pending_admin();
    const newAdminInput = row.querySelector('.new-admin-input');
    const propose = row.querySelector('.propose-admin-btn');
    propose.addEventListener('click', async () => {
      if (refuseWhileBusy()) return;
      const newAdmin = newAdminInput.value.trim();
      const refusal = newAdminRefusal(newAdmin, { admin, pending });
      if (refusal) {
        showToast(refusal, 'error');
        return;
      }
      propose.disabled = true;
      const confirmed = await confirmCustody(newAdmin).finally(() => { propose.disabled = false; });
      if (confirmed) {
        buildRowCall(propose, kind, { source: admin, contractId, method: 'update_admin', args: { new_admin: newAdmin } });
      }
    });
    if (!pending) {
      pendingEl.textContent = 'none';
      row.querySelectorAll('.cancel-admin-btn, .accept-admin-btn').forEach((btn) => btn.remove());
      return row;
    }
    showAddress(pendingEl, pending);
    const cancel = row.querySelector('.cancel-admin-btn');
    const accept = row.querySelector('.accept-admin-btn');
    cancel.addEventListener('click', () => buildRowCall(cancel, kind, { source: admin, contractId, method: 'cancel_admin_transfer' }));
    accept.addEventListener('click', () => buildRowCall(accept, kind, { source: pending, contractId, method: 'accept_admin' }));
  } catch (err) {
    adminEl.textContent = `could not be read: ${err.message}`;
    row.querySelector('.admin-actions').remove();
  }
  return row;
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
function renderStorageLockBtn() {
  if (!storageLockBtn) return;
  const unlocked = isStorageUnlocked();
  storageLockBtn.textContent = unlocked ? 'Lock' : 'Unlock';
  storageLockBtn.title = unlocked ? 'Lock local data' : 'Unlock local data';
  storageLockBtn.dataset.state = unlocked ? 'unlocked' : 'locked';
  storageLockBtn.disabled = ['unlocking', 'locking'].includes(document.body.dataset.storageState);
}
window.addEventListener(STORAGE_STATE_EVENT, renderStorageLockBtn);
renderStorageLockBtn();

storageLockBtn?.addEventListener('click', async () => {
  if (isStorageUnlocked()) {
    await lockStorage();
    return;
  }
  try {
    await ensureCryptoReady({ unlock: true });
    await refreshState();
    setStatus('Ready', 'ok');
  } catch (error) {
    if (error?.code === 'unlock-cancelled') return;
    setStatus('Unlock failed', 'error');
    if (!isDbLockedError(error?.message)) {
      showToast(error?.message || 'Could not unlock local data.', 'error');
    }
  }
});

connectBtn.addEventListener('click', () => {
  if (state.address) {
    disconnect();
  } else {
    connect();
  }
});
// Refresh drops a finished check (the pool may have changed); a running one reads live data.
refreshBtn.addEventListener('click', () => {
  if (state.repoint?.lines) resetRepoint();
  if (!state.busy) renderAdminTx(state.adminTxKind);
  refreshState({ unlock: true });
});

addToAllowlistBtn.addEventListener('click', insertMembershipLeaf);
addToBlocklistBtn.addEventListener('click', insertNonMembershipLeaf);
removeFromBlocklistBtn.addEventListener('click', removeNonMembershipLeaf);

adminTxXdrInput.addEventListener('input', () => renderAdminTx());
submitAdminTxBtn.addEventListener('click', submitAdminTx);
copyAdminTxBtn.addEventListener('click', () => copyText(adminTxXdrInput.value.trim(), 'Transaction XDR'));
copyAdminTxLinkBtn.addEventListener('click', () =>
  copyText(adminTxLink(window.location.origin + window.location.pathname, adminTxXdrInput.value.trim()), 'Link'));

const sharedTx = adminTxFromHash(window.location.hash);
loadAdminTx(sharedTx);
if (sharedTx) {
  // A reload would otherwise bring back an envelope that was since submitted.
  window.history.replaceState(null, '', window.location.pathname + window.location.search);
}

// A changed field makes the last re-point check stale.
[repointPoolSelect, repointKindSelect, repointTreeInput, repointRecordsInput]
  .forEach((field) => field.addEventListener('input', resetRepoint));
// The native control's text follows the browser's language, so name the file here.
repointRecordsInput.addEventListener('change', () => {
  const [file] = repointRecordsInput.files;
  repointRecordsNameEl.textContent = file?.name ?? 'No file chosen';
  clearRepointRecordsBtn.classList.toggle('hidden', !file);
});
clearRepointRecordsBtn.addEventListener('click', () => {
  repointRecordsInput.value = '';
  repointRecordsInput.dispatchEvent(new Event('change'));
  resetRepoint();
});
checkRepointBtn.addEventListener('click', checkRepoint);
// The build restores the button; re-sync it with the check and the card.
buildRepointBtn.addEventListener('click', async () => {
  await buildRowCall(buildRepointBtn, 'pool', state.repoint.call);
  renderRepoint();
});

buildPauseAuthBtn.addEventListener('click', buildPauseFile);
// Signatures live only in this page until saved.
window.addEventListener('beforeunload', (event) => {
  if (state.pauseFiles.some(unsaved)) event.preventDefault();
});
pauseAuthFilesInput.addEventListener('change', openPauseFiles);
submitPauseAuthBtn.addEventListener('click', submitPauseFiles);

membershipContractInput?.addEventListener('input', () => {
  updateContractLink(membershipContractLinkEl, membershipContractInput.value.trim());
});
nonMembershipContractInput?.addEventListener('input', () => {
  updateContractLink(nonMembershipContractLinkEl, nonMembershipContractInput.value.trim());
});

async function init() {
  setStatus('Initializing...', 'info');
  await loadExplorerSetting();
  if (storageWasLocked() && !isStorageUnlocked()) {
    await refreshPools();
    await refreshAdmins();
    await initGvkAuditPanel({
      ensureCryptoReady,
      showToast,
      getWalletAccount: () =>
        state.address
          ? { userAddress: state.address, networkPassphrase: state.networkPassphrase }
          : null,
    });
    setStatus('Local data is locked. Use Unlock to continue.', 'info');
    return;
  }
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
