import { deploymentDefaults } from './network-config.js';
import { StrKey, contract, scValToNative, xdr } from '@stellar/stellar-sdk';
import { client, initializeRuntime, bootnodeRequired, ensureStorage, deriveAspUserLeaf, loadDeploymentConfig } from './wasm-facade.js';
import { connectWallet, getWalletNetwork, signWalletAuthEntry, signWalletTransaction } from './wallet.js';
import { isDbLockedError, showDbLockedModal } from './db-locked.js';
import { friendlyErrorMessage } from './facade-errors.js';
import { App, Utils } from './ui/core.js';
import { initGvkAuditPanel } from './admin-gvk.js';
import { adminTxFromHash, adminTxLink, buildAdminCall, custodyProblems, describeAdminCall, explainFailure, maxEntryTtl, newAdminRefusal, rpcServer, signatureCount, signedBy, signedWeight, signerStatus, signingRule, signRefusal, submitAdminCall } from './admin-transactions.js';
import { blocklistInsertCall, blocklistKeyToNoteKey, parseBlocklistKeys, unreadBlocklistWarning } from './blocklist-keys.js';
import { adminLine, allowlistLeavesFromEvents, blocklistKeys, codeLine, compareEntries, eventsSince, historyStart, levelsLine, manifestLine, parseRecords, readInstance } from './tree-check.js';
import { addSignature, authorizationPreimage, buildPauseAuthorization, decodeAuthorization, encodeAuthorization, pauseTransaction, walletSignature } from './pause-authorization.js';

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
const repointChecksEl = document.getElementById('repointChecks');
const repointConfirmEl = document.getElementById('repointConfirm');
const repointConfirmBox = document.getElementById('repointConfirmBox');
const repointConfirmTextEl = document.getElementById('repointConfirmText');
const checkRepointBtn = document.getElementById('checkRepointBtn');
const buildRepointBtn = document.getElementById('buildRepointBtn');

// Pause authorizations panel
const pauseAuthPoolSelect = document.getElementById('pauseAuthPool');
const pauseAuthFilesInput = document.getElementById('pauseAuthFiles');
const pauseAuthResultsEl = document.getElementById('pauseAuthResults');
const buildPauseAuthBtn = document.getElementById('buildPauseAuthBtn');
const signPauseAuthBtn = document.getElementById('signPauseAuthBtn');
const submitPauseAuthBtn = document.getElementById('submitPauseAuthBtn');

// Admins tab
const adminRowsEl = document.getElementById('adminRows');
const adminsNoticeEl = document.getElementById('adminsNotice');
const adminRowTemplate = document.getElementById('tpl-admin-row');
const signerTemplate = document.getElementById('tpl-signer');

// The buttons that need a connected wallet.
const ACTION_BUTTONS = [addToAllowlistBtn, addToBlocklistBtn, removeFromBlocklistBtn, submitAdminTxBtn, checkRepointBtn, buildPauseAuthBtn, signPauseAuthBtn, submitPauseAuthBtn];

const state = {
  address: null,
  networkPassphrase: null,
  rpcUrl: null,
  contracts: null,
  adminTxKind: null,
  // The manifest's pools and added allowlists; `kindOf` reads a pasted call against them.
  pools: [],
  addedAllowlists: [],
  // The last re-point check: its lines, and the call they allow once each passes.
  repoint: null,
  // Pool to the blocklist it reads, which a re-point changes without the
  // manifest.
  poolBlocklists: new Map(),
  // Set while an admin call is built, signed, or sent; change it through `setBusy`.
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

  refreshPools();
  refreshAdmins();
  setStatus('Wallet disconnected', 'info');
  showToast('Wallet disconnected', 'info');
}

async function refreshState() {
  try {
    setStatus('Loading contract state...', 'info');
    const appState = await client().aspState();
    const membershipState = appState.aspMembership;
    const nonMembershipState = appState.aspNonMembership;

    // Keep a tree the operator entered, such as a re-pointed blocklist; fill an
    // empty field from the manifest.
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
  state.adminTxKind = null;
  adminTxSignaturesEl.textContent = '0';
  adminTxSignersEl.replaceChildren();
  adminTxDescriptionEl.textContent = '';
  adminTxNoticeEl.textContent = '';
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
    // A read landing after the card changed or the wallet disconnected is stale.
    const current = () => adminTxXdrInput.value.trim() === xdr && state.address;
    rpcServer(state.rpcUrl).getAccountEntry(call.source).then((account) => {
      if (!current()) return;
      const rule = signingRule(account);
      const weight = signedWeight(rule, xdr, state.networkPassphrase);
      adminTxSignaturesEl.textContent = weight === count
        ? `${count} of ${rule.threshold}`
        : `${count}, weight ${weight} of ${rule.threshold}`;
      adminTxSignersEl.replaceChildren(...signerStatus(rule, xdr, state.networkPassphrase).map(({ key, signed }) =>
        signerItem(key, signed, signed === false && weight < rule.threshold)));
      submitAdminTxBtn.disabled = state.busy || weight < rule.threshold;
    }, (err) => {
      if (current()) adminTxNoticeEl.textContent = [adminTxNoticeEl.textContent, `The admin account could not be read: ${err.message}`].filter(Boolean).join(' ');
    });
  } catch (err) {
    adminTxSignaturesLineEl.classList.add('hidden');
    copyAdminTxLinkBtn.disabled = true;
    adminTxNoticeEl.textContent = `Not an admin call: ${err.message}`;
  }
}

function setBusy(busy) {
  state.busy = busy;
  adminTxSignersEl.querySelectorAll('.sign-as-btn').forEach((button) => {
    button.disabled = busy;
  });
}

function refuseWhileBusy() {
  if (state.busy) showToast('Finish the admin call in progress first.', 'info');
  return state.busy;
}

function signerItem(key, signed, canSign) {
  const item = signerTemplate.content.cloneNode(true).firstElementChild;
  item.querySelector('.signer-key').textContent = key;
  const status = item.querySelector('.signer-status');
  status.textContent = SIGNED_LABELS.get(signed);
  status.classList.add(signed ? 'text-emerald-300' : 'text-slate-500');
  const button = item.querySelector('.sign-as-btn');
  if (canSign) {
    button.disabled = state.busy;
    button.addEventListener('click', () => signAdminTx(key, button));
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
  if (state.busy) throw new Error('Another admin call is in progress. Wait for it to finish.');
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
    const { source } = describeAdminCall(envelope, state.networkPassphrase);
    const rule = signingRule(await rpcServer(state.rpcUrl).getAccountEntry(source));
    const refusal = signRefusal(rule, envelope, state.networkPassphrase, signer);
    if (refusal) throw new Error(refusal);
    const signedTxXdr = await walletSign(envelope, signer);
    if (adminTxXdrInput.value.trim() !== envelope) throw new Error('The card changed while Freighter was signing. Sign again.');
    loadAdminTx(signedTxXdr, state.adminTxKind);
    showToast('Signed. Press Copy link and send the new link to the next signer, or submit it.', 'success');
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
  if (state.busy) return;
  setBusy(true);
  submitAdminTxBtn.disabled = true;
  submitAdminTxBtn.textContent = 'Submitting...';
  adminTxXdrInput.readOnly = true;
  let method;
  try {
    ensureWalletConnected();
    const envelope = adminTxXdrInput.value.trim();
    ({ method } = describeAdminCall(envelope, state.networkPassphrase));
    setStatus('Submitting the admin transaction...', 'info');
    await submitAdminCall({ rpcUrl: state.rpcUrl, networkPassphrase: state.networkPassphrase, xdr: envelope });
  } catch (err) {
    const reason = explainFailure(err, state.adminTxKind);
    setStatus('Admin transaction failed', 'error');
    showToast('Admin transaction failed. The card shows why.', 'error');
    renderAdminTx(state.adminTxKind);
    adminTxNoticeEl.textContent = `Last submit: ${reason}`;
    return;
  } finally {
    setBusy(false);
    submitAdminTxBtn.textContent = 'Submit';
    adminTxXdrInput.readOnly = false;
  }
  setStatus('Admin transaction succeeded', 'ok');
  showToast(`${method} succeeded`, 'success');
  loadAdminTx('');
  await refreshState();
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

// Reports whether to write to `blocklist`: yes if a listed pool reads it,
// otherwise only if the operator accepts the warning.
function confirmBlocklistWrite(blocklist) {
  const warning = unreadBlocklistWarning(blocklist, [...state.poolBlocklists.values()]);
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
    if (!confirmBlocklistWrite(contractId)) return;

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
    if (!confirmBlocklistWrite(contractId)) return;

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

// Lists every pool the manifest names, disabled ones too since they still take
// deposits, with its trees and deposit flag.
function refreshPools() {
  resetRepoint();
  state.poolBlocklists = new Map();
  return fillTable(poolRowsEl, poolsNoticeEl, 'pools', ({ pools }) => {
    state.pools = pools.map(({ poolContractId }) => poolContractId);
    [repointPoolSelect, pauseAuthPoolSelect].forEach((select) => select.replaceChildren(...state.pools.map((contractId) => new Option(shortAddress(contractId), contractId))));
    return state.pools.map((contractId) => poolRow(contractId));
  });
}

// A pool without `deposits_paused` cannot be paused, and an unreadable pool
// shows its error; neither row gets buttons.
async function poolRow(contractId) {
  const row = poolRowTemplate.content.cloneNode(true).firstElementChild;
  showAddress(row.querySelector('.pool-id'), contractId);
  const depositsEl = row.querySelector('.pool-deposits');
  try {
    const [pool, { stored }] = await Promise.all([readClient(contractId), readInstance(rpcServer(state.rpcUrl), contractId)]);
    state.poolBlocklists.set(contractId, stored.get('ASPNonMembership'));
    row.querySelector('.pool-trees').replaceChildren(...[['Allowlist', 'ASPMembership'], ['Blocklist', 'ASPNonMembership']].map(([label, key]) => {
      const line = document.createElement('div');
      showAddress(line, stored.get(key));
      line.prepend(`${label} `);
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
    setStatus(`Building ${call.method}...`, 'info');
    await prepareAdminCall(kind, call);
  } catch (err) {
    setStatus(`Building ${call.method} failed`, 'error');
    showToast(`Building ${call.method} failed: ${explainFailure(err, kind)}`, 'error');
  } finally {
    Object.assign(button, { disabled, textContent });
    button.style.minWidth = '';
  }
}

// -----------------------------
// Re-point
// -----------------------------
// Draws the last re-point check. An outside admin's line passes once the
// operator confirms it; Build waits for every line.
function renderRepoint() {
  const lines = state.repoint?.lines ?? [];
  const passes = ({ ok, confirm }) => ok || (Boolean(confirm) && repointConfirmBox.checked);
  repointChecksEl.replaceChildren(...lines.map((line) => Object.assign(document.createElement('li'), {
    className: passes(line) ? 'text-emerald-300' : 'text-rose-300',
    textContent: `${passes(line) ? 'ok' : 'FAIL'} ${line.label}: ${line.text}`,
  })));
  const confirm = lines.find((line) => line.confirm)?.confirm;
  repointConfirmEl.classList.toggle('hidden', !confirm);
  repointConfirmTextEl.textContent = confirm ? `Let the pool use a contract that ${confirm} runs, not the pool's admin` : '';
  buildRepointBtn.disabled = lines.length === 0 || !lines.every(passes);
}

function resetRepoint() {
  state.repoint = null;
  repointConfirmBox.checked = false;
  renderRepoint();
}

// Checks a tree before a re-point, one line per check. The pool already
// refuses other code; the rest covers depth, admin, client indexing, and
// entries.
async function checkRepoint() {
  resetRepoint();
  // A field that changes while the check runs resets it, and its result is dropped.
  const check = {};
  state.repoint = check;
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
    const checks = [
      ['Code', async () => {
        const client = await readClient(pool);
        if (!client.get_asp_wasm_hashes) {
          throw new Error('the pool has no get_asp_wasm_hashes entry point, so it accepts a contract running any code');
        }
        return codeLine((await client.get_asp_wasm_hashes()).result.unwrap(), treeInstance.wasmHash, allowlist);
      }],
      allowlist && ['Levels', async () => {
        const current = poolInstance.stored.get('ASPMembership');
        const levels = (await readInstance(server, current)).stored.get('Levels');
        return levelsLine(current, levels, treeInstance.stored.get('Levels'));
      }],
      ['Admin', async () => {
        const client = await readClient(tree);
        if (!client.get_admin) throw new Error('the contract has no get_admin entry point');
        return adminLine((await client.get_admin()).result.unwrap(), admin);
      }],
      allowlist && ['Manifest', async () => manifestLine(manifest, tree)],
      ['Entries', async () => {
        const [file] = repointRecordsInput.files;
        if (!file) throw new Error('choose the records file');
        // Blocklist records and reported keys are note public keys in Blocklist
        // tab form, so a key loaded in the wrong byte order fails.
        const records = (allowlist ? parseRecords : parseBlocklistKeys)(await file.text());
        let onChain;
        if (allowlist) {
          const [events, nextIndex] = await Promise.all([
            eventsSince(server, tree, historyStart({ tree, manifest })),
            server.getContractData(tree, xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('NextIndex')]))
              .then(({ val }) => scValToNative(val.contractData.val)),
          ]);
          onChain = allowlistLeavesFromEvents(events, nextIndex);
        } else {
          onChain = await blocklistKeys(server, tree, treeInstance.stored.get('Root'));
        }
        const { missing, unexpected } = compareEntries(onChain, records);
        const shown = allowlist ? (value) => `0x${value.toString(16)}` : blocklistKeyToNoteKey;
        const listed = (values) => values.map(shown).join(', ');
        const problems = [
          missing.length > 0 && `missing from the contract: ${listed(missing)}`,
          unexpected.length > 0 && `not in the records: ${listed(unexpected)}`,
        ].filter(Boolean);
        if (problems.length > 0) throw new Error(problems.join('; '));
        return `${onChain.length} on chain, as in the records`;
      }],
    ].filter(Boolean);
    const lines = await Promise.all(checks.map(([label, run]) => run().then(
      (text) => ({ label, ok: true, text }),
      (err) => ({ label, ok: false, text: err.message, confirm: err.confirm }),
    )));
    if (state.repoint !== check) return;
    setStatus('Contract checked', 'info');
    Object.assign(check, {
      lines,
      call: {
        source: admin,
        contractId: pool,
        method: allowlist ? 'update_asp_membership' : 'update_asp_non_membership',
        args: allowlist ? { new_asp_membership: tree } : { new_asp_non_membership: tree },
      },
    });
    renderRepoint();
  } catch (err) {
    setStatus('Contract check failed', 'error');
    showToast(`Contract check failed: ${err.message}`, 'error');
  } finally {
    if (state.address) checkRepointBtn.disabled = false;
    checkRepointBtn.textContent = originalText;
  }
}

// -----------------------------
// Pause authorizations
// -----------------------------
// Offers `text` to the browser as a file to save under `name`.
function offerFile(name, text) {
  Object.assign(document.createElement('a'), {
    href: `data:application/json;charset=utf-8,${encodeURIComponent(text)}`,
    download: name,
  }).click();
}

function reportPause(text) {
  pauseAuthResultsEl.append(Object.assign(document.createElement('li'), { textContent: text }));
}

// Builds an unsigned pause authorization with a random nonce and offers it as a
// file.
async function buildPauseAuthorizationFile() {
  try {
    ensureWalletConnected();
    const pool = pauseAuthPoolSelect.value;
    if (!pool) throw new Error('Choose a pool');
    buildPauseAuthBtn.disabled = true;
    const server = rpcServer(state.rpcUrl);
    const [admin, { sequence }, ttl] = await Promise.all([storedAdmin(pool), server.getLatestLedger(), maxEntryTtl(server)]);
    // Non-negative, so the file name carries no minus sign.
    const nonce = crypto.getRandomValues(new BigUint64Array(1))[0] >> 1n;
    const entry = buildPauseAuthorization({ admin, pool, nonce, latestLedger: sequence, maxEntryTtl: ttl });
    offerFile(`pause-${pool}-${nonce}.json`, encodeAuthorization(entry));
    setStatus('Pause authorization built. Each signer signs the file, then hand it to whoever will pause deposits.', 'ok');
  } catch (err) {
    showToast(`Building the pause authorization failed: ${err.message}`, 'error');
  } finally {
    if (state.address) buildPauseAuthBtn.disabled = false;
  }
}

// Adds the connected signer's signature to one chosen file and offers it again.
async function signPauseAuthorization() {
  try {
    ensureWalletConnected();
    const [file, ...others] = pauseAuthFilesInput.files;
    if (!file || others.length > 0) throw new Error('Choose one authorization file to sign');
    signPauseAuthBtn.disabled = true;
    const { pool, admin, nonce, expirationLedger, signers, entry } = decodeAuthorization(await file.text());
    // Files can come from anyone: show what this one authorizes before
    // Freighter asks.
    pauseAuthResultsEl.replaceChildren();
    Object.entries({
      Pool: pool,
      Admin: admin,
      Nonce: nonce,
      'Expiration ledger': expirationLedger,
      Signers: signers.join(', ') || 'none',
    }).forEach(([label, value]) => reportPause(`${label}: ${value}`));
    // A non-signer's signature would fail the pause and cannot be removed.
    const { threshold, weights } = signingRule(await rpcServer(state.rpcUrl).getAccountEntry(admin));
    if (!(weights.get(state.address) > 0)) {
      throw new Error(`The connected account does not sign for ${admin}`);
    }
    const { signedAuthEntry } = await signWalletAuthEntry(authorizationPreimage(entry, state.networkPassphrase), {
      networkPassphrase: state.networkPassphrase,
      address: state.address,
    });
    offerFile(file.name, encodeAuthorization(addSignature(entry, state.address, walletSignature(signedAuthEntry), state.networkPassphrase)));
    showToast(`Signed: ${signers.length + 1} of ${threshold} signatures. Pass the file to the next signer, or to whoever will pause deposits.`, 'success');
  } catch (err) {
    showToast(`Signing failed: ${err.message}`, 'error');
  } finally {
    if (state.address) signPauseAuthBtn.disabled = false;
  }
}

// Sends each chosen file's pause from the connected account in turn and
// reports each on its own line, so one failure stops no other file. A second
// file for a pool an earlier one paused is held back unspent.
async function submitPauseAuthorizations() {
  pauseAuthResultsEl.replaceChildren();
  try {
    ensureWalletConnected();
    const files = [...pauseAuthFilesInput.files];
    if (files.length === 0) throw new Error('Choose the authorization files to submit');
    submitPauseAuthBtn.disabled = true;
    setStatus('Submitting the pauses...', 'info');
    const network = { rpcUrl: state.rpcUrl, networkPassphrase: state.networkPassphrase };
    let failed = 0;
    for (const file of files) {
      // A line names the file until the file names its pool.
      let label = file.name;
      try {
        const authorization = decodeAuthorization(await file.text());
        label = authorization.pool;
        const built = await pauseTransaction({ ...network, source: state.address, authorization });
        if (built.paused) {
          reportPause(`${label}: already paused, so the file was not sent and its nonce is unspent`);
          continue;
        }
        const { signedTxXdr } = await signWalletTransaction(built.xdr, { networkPassphrase: state.networkPassphrase, address: state.address });
        await submitAdminCall({ ...network, xdr: signedTxXdr });
        reportPause(`${label}: paused`);
      } catch (err) {
        failed += 1;
        reportPause(`${label}: failed: ${explainFailure(err, 'pool')}`);
      }
    }
    setStatus(failed > 0 ? `${failed} of ${files.length} pauses failed` : 'Pauses submitted', failed > 0 ? 'error' : 'ok');
  } catch (err) {
    setStatus('Pause submission failed', 'error');
    showToast(`Pause submission failed: ${err.message}`, 'error');
  } finally {
    if (state.address) submitPauseAuthBtn.disabled = false;
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
      showToast(`The new admin has to be an existing account: ${err.message}`, 'error');
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
repointConfirmBox.addEventListener('change', renderRepoint);
checkRepointBtn.addEventListener('click', checkRepoint);
buildRepointBtn.addEventListener('click', () => buildRowCall(buildRepointBtn, 'pool', state.repoint.call));

buildPauseAuthBtn.addEventListener('click', buildPauseAuthorizationFile);
signPauseAuthBtn.addEventListener('click', signPauseAuthorization);
submitPauseAuthBtn.addEventListener('click', submitPauseAuthorizations);

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
