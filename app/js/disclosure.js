import { initializeWasm, getHandle } from './wasm-facade.js';
import {
  connectWallet,
  getConnectedAddress,
  getWalletNetwork,
  deriveKeysFromWallet,
} from './wallet.js';
import { isDbLockedError, showDbLockedModal } from './db-locked.js';

// ---------------------------------------------------------------------------
// Canonical constants
// ---------------------------------------------------------------------------

const CANONICAL_SELECTIVE_DISCLOSURE_1_VK_HASH =
  '0xe8c9879c1239deeaab3cda366419e3536a6f66502f88c3eec09da1e52843e5af';

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

const BN254_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const state = {
  address: null,
  networkPassphrase: null,
  derivedKeys: null,
  notes: [],
  pools: [],
  selectedNote: null,
  notesLoading: false,
  notesError: null,
  generating: false,
  generateError: null,
  generateStage: null,
  generateStageMessage: null,
  lastReceipt: null,
};

// ---------------------------------------------------------------------------
// DOM refs (set during init)
// ---------------------------------------------------------------------------

let networkChip;
let walletChip;
let connectBtn;
let toastContainer;
let toastTemplate;

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function shortAddress(address) {
  if (!address) return 'Disconnected';
  return `${address.slice(0, 6)}...${address.slice(-4)}`;
}

// DOM builders (used instead of innerHTML).
const SVG_NS = 'http://www.w3.org/2000/svg';
function svgEl(tag, attrs = {}, children = []) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  for (const c of children) node.appendChild(c);
  return node;
}
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
}
function spinnerEl() {
  return el('span', 'w-4 h-4 border-2 border-brand-500 border-t-transparent rounded-full animate-spin');
}
function checkCircleIcon(cls) {
  return svgEl('svg', { class: cls, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '2' }, [
    svgEl('path', { d: 'M22 11.08V12a10 10 0 1 1-5.93-9.14' }),
    svgEl('polyline', { points: '22 4 12 14.01 9 11.01' }),
  ]);
}
function xCircleIcon(cls) {
  return svgEl('svg', { class: cls, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '2' }, [
    svgEl('circle', { cx: '12', cy: '12', r: '10' }),
    svgEl('line', { x1: '15', y1: '9', x2: '9', y2: '15' }),
    svgEl('line', { x1: '9', y1: '9', x2: '15', y2: '15' }),
  ]);
}
function shieldIcon(cls) {
  return svgEl('svg', { class: cls, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '2' }, [
    svgEl('path', { d: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z' }),
    svgEl('polyline', { points: '22 4 12 14.01 9 11.01' }),
  ]);
}

function showToast(message, type = 'success', duration = 4000) {
  if (!toastContainer || !toastTemplate) return;
  const toast = toastTemplate.content.cloneNode(true).firstElementChild;

  toast.querySelector('.toast-message').textContent = message;

  const isSuccess = type === 'success';
  toast.querySelector('.toast-icon-success').classList.toggle('hidden', !isSuccess);
  toast.querySelector('.toast-icon-error').classList.toggle('hidden', isSuccess);
  toast.classList.add(isSuccess ? 'border-emerald-500/50' : 'border-red-500/50');

  toast.querySelector('.toast-close').addEventListener('click', () => toast.remove());

  toastContainer.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    setTimeout(() => toast.remove(), 200);
  }, duration);
}

// ---------------------------------------------------------------------------
// Wallet
// ---------------------------------------------------------------------------

async function loadNotes() {
  if (!state.address) return;
  state.notesLoading = true;
  state.notesError = null;

  const generateContainer = document.getElementById('disclosure-generate');
  if (generateContainer) mountGenerate(generateContainer);

  try {
    const LIMIT = 200;
    const config = await getHandle().webClient.contractConfig();
    state.pools = Array.isArray(config?.pools) ? config.pools : [];
    const list = await getHandle().webClient.getUserNotes(state.address, LIMIT);
    const notes = Array.isArray(list) ? list : [];

    state.notes = notes.map((n) => ({
      id: n.id,
      poolContractId: n.poolContractId,
      amount: n.amount,
      spent: !!n.spent,
      leafIndex: n.leafIndex ?? 0,
      createdAtLedger: n.createdAtLedger ?? 0,
    }));

    // Apply query-param preselection if present
    const query = parseQueryParams();
    if (query.commitment) {
      const target = normalizeCommitment(query.commitment);
      const match = state.notes.find(
        (n) =>
          normalizeCommitment(n.id) === target &&
          !n.spent
      );
      if (match) {
        state.selectedNote = match;
      } else {
        state.notesError =
          'Note not found, already spent, or not owned by this account.';
      }
    }
  } catch (e) {
    console.warn('[Disclosure] loadNotes failed:', e);
    state.notesError = 'Failed to load notes. The indexer may still be syncing.';
  } finally {
    state.notesLoading = false;
    const generateContainer = document.getElementById('disclosure-generate');
    if (generateContainer) mountGenerate(generateContainer);
  }
}

async function connect() {
  try {
    const address = await connectWallet();
    const net = await getWalletNetwork();

    // This page is testnet-only. Refuse connection from wallets on other networks.
    const TESTNET_PASSPHRASE = 'Test SDF Network ; September 2015';
    if (net.networkPassphrase !== TESTNET_PASSPHRASE) {
      showToast(
        `Network mismatch: expected Testnet, got ${net.network || 'unknown network'}. Please switch your wallet to Testnet.`,
        'error',
        8000
      );
      return;
    }

    state.address = address;
    state.networkPassphrase = net.networkPassphrase;

    walletChip.textContent = shortAddress(address);
    networkChip.textContent = net.network || 'Testnet';

    showToast(`Connected: ${shortAddress(address)}`, 'success');

    // Derive keys (cached keys load instantly)
    await deriveKeys();

    // Load notes and render generate section
    await loadNotes();
  } catch (err) {
    if (err.code === 'USER_REJECTED') {
      showToast('Connection cancelled', 'info');
    } else {
      showToast(err.message || 'Wallet connection failed', 'error');
    }
  }
}

async function deriveKeys() {
  try {
    const result = await deriveKeysFromWallet(state.address, {
      onStatus: (msg) => console.log('[Disclosure]', msg),
      signDelay: 300,
      skipCacheCheck: false,
    });
    state.derivedKeys = result;
    showToast('Privacy keys ready', 'success');
  } catch (err) {
    showToast(err.message || 'Key derivation failed', 'error');
    throw err;
  }
}

// ---------------------------------------------------------------------------
// Query params
// ---------------------------------------------------------------------------

function parseQueryParams() {
  const params = new URLSearchParams(window.location.search);
  return {
    commitment: params.get('commitment') || null,
    verify: params.get('verify') === '1' || params.get('verify') === 'true',
  };
}

// ---------------------------------------------------------------------------
// Mount: Generate (wallet-gated)
// ---------------------------------------------------------------------------

function formatAmount(stroops, symbol = 'XLM') {
  try {
    let v = BigInt(stroops);
    const negative = v < 0n;
    if (negative) v = -v;
    const abs = v.toString().padStart(8, '0');
    const intPart = abs.slice(0, -7);
    const frac = abs.slice(-7).replace(/0+$/, '');
    const out = frac ? `${intPart}.${frac}` : intPart;
    return `${negative ? '-' : ''}${out} ${symbol}`;
  } catch {
    return String(stroops);
  }
}

// Token symbol for a pool, derived from the deployment config's asset descriptor.
function tokenLabelForPool(poolContractId) {
  const pool = (state.pools || []).find((p) => p.poolContractId === poolContractId);
  const asset = pool?.asset || {};
  if (asset.kind === 'native') return 'XLM';
  if (asset.kind === 'classic') return asset.code || 'Asset';
  if (asset.kind === 'contract') return asset.symbol || 'Token';
  return 'Token';
}

function shortCommitment(hex) {
  if (!hex || hex.length < 10) return hex || '--';
  return `${hex.slice(0, 8)}…${hex.slice(-4)}`;
}

function normalizeCommitment(s) {
  if (!s) return '';
  let t = s.toLowerCase().trim();
  if (t.startsWith('0x')) t = t.slice(2);
  // strip leading zeros so "0x01" and "0x1" and "1" match
  t = t.replace(/^0+/, '');
  return t;
}

export function mountGenerate(container) {
  container.replaceChildren();

  const heading = document.createElement('h2');
  heading.id = 'generate-heading';
  heading.className = 'text-sm uppercase tracking-[0.25em] text-brand-400 mb-4';
  heading.textContent = 'Generate Disclosure Receipt';
  container.appendChild(heading);

  if (!state.address || !state.derivedKeys) {
    const msg = document.createElement('div');
    msg.className = 'text-sm text-dark-400';
    msg.textContent =
      'Connect your Freighter wallet to generate disclosure receipts for your unspent notes.';
    container.appendChild(msg);
    return;
  }

  // Wallet status line
  const statusLine = el('div', 'text-xs text-dark-500 mb-4');
  statusLine.append('Connected: ', el('span', 'font-mono text-dark-300', shortAddress(state.address)));
  container.appendChild(statusLine);

  if (state.notesLoading) {
    const spinner = el('div', 'text-sm text-dark-400 flex items-center gap-2');
    spinner.append(spinnerEl(), 'Loading notes…');
    container.appendChild(spinner);
    return;
  }

  if (state.notesError) {
    const err = document.createElement('div');
    err.className = 'text-sm text-rose-300 bg-rose-500/10 border border-rose-500/40 rounded-lg p-3';
    err.textContent = state.notesError;
    container.appendChild(err);
    return;
  }

  const unspent = state.notes.filter((n) => !n.spent);

  if (unspent.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'text-sm text-dark-400';
    empty.textContent = 'No unspent notes found for this account.';
    container.appendChild(empty);
    return;
  }

  // Note picker
  const pickerLabel = document.createElement('label');
  pickerLabel.className = 'block text-xs font-medium text-dark-400 uppercase tracking-wide mb-2';
  pickerLabel.textContent = `Select an unspent note (${unspent.length})`;
  container.appendChild(pickerLabel);

  const list = document.createElement('div');
  list.className = 'space-y-2 mb-4';
  list.setAttribute('role', 'radiogroup');
  list.setAttribute('aria-label', 'Unspent notes');

  unspent.forEach((note) => {
    const isSelected = state.selectedNote && state.selectedNote.id === note.id;

    const row = document.createElement('button');
    row.type = 'button';
    row.className = `w-full text-left p-3 rounded-lg border transition-all duration-200 flex items-center justify-between gap-3 ${
      isSelected
        ? 'bg-brand-500/10 border-brand-500/40 text-brand-300'
        : 'bg-dark-800 border-dark-700 hover:border-dark-600 text-dark-200'
    }`;
    row.setAttribute('role', 'radio');
    row.setAttribute('aria-checked', String(isSelected));

    const noteLabel = tokenLabelForPool(note.poolContractId);
    const rowInfo = el('div', 'min-w-0');
    rowInfo.append(
      el('div', 'font-mono text-xs truncate', shortCommitment(note.id)),
      el('div', 'text-[10px] text-dark-500 mt-0.5', `${noteLabel} · Leaf ${note.leafIndex} · Ledger ${note.createdAtLedger}`),
    );
    row.append(
      rowInfo,
      el('div', `text-xs font-medium whitespace-nowrap ${isSelected ? 'text-brand-300' : 'text-dark-300'}`, formatAmount(note.amount, noteLabel)),
    );

    row.addEventListener('click', () => {
      state.selectedNote = note;
      mountGenerate(container);
    });

    list.appendChild(row);
  });

  container.appendChild(list);

  if (state.selectedNote) {
    const selectedChip = el('div', 'text-xs text-brand-400 mb-4');
    selectedChip.append(
      'Selected: ',
      el('span', 'font-mono', shortCommitment(state.selectedNote.id)),
      ' ',
      el('span', 'text-dark-500', `· ${formatAmount(state.selectedNote.amount, tokenLabelForPool(state.selectedNote.poolContractId))}`),
    );
    container.appendChild(selectedChip);
  }

  // -------------------------------------------------------------------------
  // Context form
  // -------------------------------------------------------------------------
  const formWrap = document.createElement('div');
  formWrap.className = 'border-t border-dark-800 pt-4 mt-2 space-y-4';

  // Helper to build a labeled input
  const makeField = (id, labelText, opts = {}) => {
    const wrap = document.createElement('div');
    wrap.className = 'space-y-1';

    const label = document.createElement('label');
    label.htmlFor = id;
    label.className = 'block text-xs font-medium text-dark-400 uppercase tracking-wide';
    label.textContent = labelText;
    wrap.appendChild(label);

    const inputWrap = document.createElement('div');
    inputWrap.className = 'flex gap-2';

    const input = document.createElement('input');
    input.id = id;
    input.type = opts.type || 'text';
    input.className =
      'flex-1 px-3 py-2 bg-dark-800 border border-dark-700 rounded-lg text-xs font-mono focus:outline-none focus:border-brand-500 focus:ring-1 focus:ring-brand-500';
    if (opts.placeholder) input.placeholder = opts.placeholder;
    if (opts.value) input.value = opts.value;
    inputWrap.appendChild(input);

    if (opts.button) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className =
        'px-3 py-2 bg-dark-700 border border-dark-600 rounded-lg text-xs font-medium hover:border-brand-500 hover:text-brand-400 transition';
      btn.textContent = opts.button.label;
      btn.addEventListener('click', opts.button.onClick);
      inputWrap.appendChild(btn);
    }

    wrap.appendChild(inputWrap);

    const errorEl = document.createElement('div');
    errorEl.id = `${id}-error`;
    errorEl.className = 'text-xs text-rose-400 hidden';
    wrap.appendChild(errorEl);

    return { wrap, input, errorEl };
  };

  const authorityField = makeField('authority-label', 'Authority label', {
    placeholder: 'e.g. KYC Provider',
  });
  formWrap.appendChild(authorityField.wrap);

  const payloadField = makeField('authority-payload', 'Authority identity payload (hex)', {
    placeholder: '0x...',
  });
  formWrap.appendChild(payloadField.wrap);

  const purposeField = makeField('purpose', 'Purpose', {
    placeholder: 'e.g. identity-verification',
  });
  formWrap.appendChild(purposeField.wrap);

  const generateRandomNonce = () => {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    let hex = '';
    for (const b of bytes) hex += b.toString(16).padStart(2, '0');
    const val = BigInt('0x' + hex) % BN254_PRIME;
    return '0x' + val.toString(16).padStart(64, '0');
  };

  const nonceField = makeField('context-nonce', 'Context nonce', {
    placeholder: '0x...',
    button: {
      label: 'Random',
      onClick: () => {
        nonceField.input.value = generateRandomNonce();
        nonceField.errorEl.classList.add('hidden');
      },
    },
  });
  // Default to a random nonce
  nonceField.input.value = generateRandomNonce();
  formWrap.appendChild(nonceField.wrap);

  // Validation helpers matching DisclosureContext::validate
  const validateHex = (value, label) => {
    if (!value.startsWith('0x')) return `${label}: must start with 0x`;
    const payload = value.slice(2);
    if (payload.length === 0) return `${label}: hex payload cannot be empty`;
    if (payload.length % 2 !== 0) return `${label}: hex must have even length`;
    if (/[A-F]/.test(payload)) return `${label}: use lowercase hex digits only`;
    if (!/^[0-9a-f]*$/.test(payload)) return `${label}: invalid hex characters`;
    return null;
  };

  const validateForm = () => {
    let ok = true;

    const setErr = (field, msg) => {
      field.errorEl.textContent = msg || '';
      field.errorEl.classList.toggle('hidden', !msg);
      if (msg) ok = false;
    };

    const authority = authorityField.input.value.trim();
    setErr(authorityField, authority ? null : 'Authority label is required');

    const payload = payloadField.input.value.trim();
    setErr(payloadField, payload ? validateHex(payload, 'Identity payload') : 'Identity payload is required');

    const purpose = purposeField.input.value.trim();
    setErr(purposeField, purpose ? null : 'Purpose is required');

    const nonce = nonceField.input.value.trim();
    setErr(nonceField, nonce ? validateHex(nonce, 'Nonce') : 'Nonce is required');

    return ok
      ? { authority, payload, purpose, nonce }
      : null;
  };

  // Progress / result area
  const progressArea = document.createElement('div');
  progressArea.id = 'generate-progress';
  progressArea.className = 'hidden';
  formWrap.appendChild(progressArea);

  const resultArea = document.createElement('div');
  resultArea.id = 'generate-result';
  resultArea.className = 'hidden';
  formWrap.appendChild(resultArea);

  const setGenerateState = (stage, message, error = null) => {
    state.generateStage = stage;
    state.generateStageMessage = message;
    state.generateError = error;

    if (stage) {
      progressArea.classList.remove('hidden');
      const isError = !!error;
      const wrap = document.createElement('div');
      wrap.className = `flex items-center gap-2 text-sm ${isError ? 'text-rose-300' : 'text-dark-300'}`;
      if (!isError) {
        const spinner = document.createElement('span');
        spinner.className = 'w-4 h-4 border-2 border-brand-500 border-t-transparent rounded-full animate-spin';
        wrap.appendChild(spinner);
      }
      const msg = document.createElement('span');
      msg.textContent = message;
      wrap.appendChild(msg);
      progressArea.replaceChildren(wrap);
    } else {
      progressArea.classList.add('hidden');
      progressArea.replaceChildren();
    }
  };

  const showResult = (receipt) => {
    state.lastReceipt = receipt;
    resultArea.classList.remove('hidden');
    const json = JSON.stringify(receipt, null, 2);
    const commitmentPrefix = state.selectedNote ? shortCommitment(state.selectedNote.id).replace('…', '-') : 'receipt';
    const date = new Date().toISOString().slice(0, 10);
    const filename = `disclosure-receipt-${commitmentPrefix}-${date}.json`;

    const box = el('div', 'space-y-3');
    box.appendChild(el('div', 'text-sm text-emerald-300 bg-emerald-500/10 border border-emerald-500/40 rounded-lg p-3', 'Disclosure receipt generated successfully.'));
    box.appendChild(el('pre', 'p-3 bg-dark-950 border border-dark-800 rounded-lg text-xs font-mono text-dark-200 overflow-auto max-h-64', json));
    const actions = el('div', 'flex gap-2');
    const dlBtn = el('button', 'px-4 py-2 bg-brand-500 text-dark-950 rounded-lg text-sm font-semibold hover:bg-brand-400 transition', 'Download JSON');
    dlBtn.type = 'button';
    dlBtn.id = 'btn-download-receipt';
    const copyBtn = el('button', 'px-4 py-2 bg-dark-800 border border-dark-700 rounded-lg text-sm font-medium hover:border-brand-500 hover:text-brand-400 transition', 'Copy to clipboard');
    copyBtn.type = 'button';
    copyBtn.id = 'btn-copy-receipt';
    const resetBtn = el('button', 'px-4 py-2 bg-dark-800 border border-dark-700 rounded-lg text-sm font-medium hover:border-brand-500 hover:text-brand-400 transition', 'Generate another');
    resetBtn.type = 'button';
    resetBtn.id = 'btn-reset-generate';
    actions.append(dlBtn, copyBtn, resetBtn);
    box.appendChild(actions);
    resultArea.replaceChildren(box);

    document.getElementById('btn-download-receipt')?.addEventListener('click', () => {
      const blob = new Blob([json], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
      showToast('Receipt downloaded', 'success');
    });

    document.getElementById('btn-copy-receipt')?.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(json);
        showToast('Copied to clipboard', 'success');
      } catch {
        showToast('Failed to copy', 'error');
      }
    });

    document.getElementById('btn-reset-generate')?.addEventListener('click', () => {
      state.lastReceipt = null;
      state.generateError = null;
      state.generateStage = null;
      resultArea.classList.add('hidden');
      resultArea.replaceChildren();
      progressArea.classList.add('hidden');
      progressArea.replaceChildren();
      // Re-enable form
      generateBtn.disabled = false;
      generateBtn.textContent = 'Generate Disclosure Receipt';
    });
  };

  const showGenerateError = (message) => {
    setGenerateState('error', message, true);
    generateBtn.disabled = false;
    generateBtn.textContent = 'Retry';
  };

  // Generate button
  const generateBtn = document.createElement('button');
  generateBtn.type = 'button';
  generateBtn.className =
    'w-full px-4 py-2 bg-brand-500 text-dark-950 rounded-lg text-sm font-semibold shadow-lg shadow-brand-500/20 hover:bg-brand-400 transition disabled:opacity-50 disabled:cursor-not-allowed';
  generateBtn.textContent = 'Generate Disclosure Receipt';
  generateBtn.disabled = !state.selectedNote;
  formWrap.appendChild(generateBtn);

  generateBtn.addEventListener('click', async () => {
    if (!state.selectedNote) {
      showToast('Please select a note first', 'error');
      return;
    }

    const form = validateForm();
    if (!form) return;

    generateBtn.disabled = true;
    generateBtn.textContent = 'Generating…';
    resultArea.classList.add('hidden');
    state.lastReceipt = null;

    try {
      const receipt = await generateReceipt(form);
      if (receipt) {
        setGenerateState(null);
        showResult(receipt);
        generateBtn.textContent = 'Generated';
      } else {
        // RegisterAtASP path — receipt is null
        showGenerateError(
          'Account not registered with the ASP. Please use the main app to deposit or register your public key before generating a disclosure receipt.'
        );
      }
    } catch (err) {
      console.error('Generate failed:', err);
      showGenerateError(err.message || 'Generation failed');
    }
  });

  container.appendChild(formWrap);
}

function getActivePoolContractId(config) {
  const pools = Array.isArray(config?.pools) ? config.pools : [];
  const selected = pools.find((p) => p?.enabled) || pools[0];
  const poolContractId = selected?.poolContractId;
  if (!poolContractId) throw new Error('Pool contract ID not available');
  return poolContractId;
}

async function generateReceipt(form) {
  const onStatus = (obj) => {
    const stage = obj?.stage || '';
    const message = obj?.message || '';
    const progressArea = document.getElementById('generate-progress');
    if (progressArea) {
      progressArea.classList.remove('hidden');
      const wrap = document.createElement('div');
      wrap.className = 'flex items-center gap-2 text-sm text-dark-300';
      const spinner = document.createElement('span');
      spinner.className = 'w-4 h-4 border-2 border-brand-500 border-t-transparent rounded-full animate-spin';
      wrap.appendChild(spinner);
      const msg = document.createElement('span');
      msg.textContent = message;
      wrap.appendChild(msg);
      progressArea.replaceChildren(wrap);
    }
  };

  // Disclose against the pool the selected note actually belongs to (there can
  // be multiple pools); falling back to the first enabled pool only if unknown.
  const config = await getHandle().webClient.contractConfig();
  const poolContractId = state.selectedNote.poolContractId || getActivePoolContractId(config);

  const receipt = await getHandle().webClient.generateSelectiveDisclosure(
    poolContractId,
    state.address,
    state.selectedNote.id,
    form.authority,
    form.payload,
    form.purpose,
    BigInt(form.nonce),
    onStatus
  );

  // receipt is a JS object (already deserialized by wasm_bindgen) or null
  return receipt || null;
}

// ---------------------------------------------------------------------------
// Mount: Verify (walletless)
// ---------------------------------------------------------------------------

export function mountVerify(container) {
  container.replaceChildren();

  const heading = document.createElement('h2');
  heading.id = 'verify-heading';
  heading.className = 'text-sm uppercase tracking-[0.25em] text-brand-400 mb-4';
  heading.textContent = 'Verify Disclosure Receipt';
  container.appendChild(heading);

  let receipt = null;
  let receiptError = null;

  // -------------------------------------------------------------------------
  // Import area
  // -------------------------------------------------------------------------
  const importWrap = document.createElement('div');
  importWrap.className = 'space-y-3 mb-4';

  // File picker
  const fileWrap = document.createElement('div');
  fileWrap.className = 'space-y-1';
  const fileLabel = document.createElement('label');
  fileLabel.className = 'block text-xs font-medium text-dark-400 uppercase tracking-wide';
  fileLabel.textContent = 'Import from file';
  fileWrap.appendChild(fileLabel);

  const fileInput = document.createElement('input');
  fileInput.type = 'file';
  fileInput.accept = '.json';
  fileInput.className =
    'block w-full text-xs text-dark-300 file:mr-3 file:px-3 file:py-1.5 file:bg-dark-800 file:border file:border-dark-700 file:rounded-lg file:text-dark-200 file:hover:border-brand-500 file:transition';
  fileWrap.appendChild(fileInput);
  importWrap.appendChild(fileWrap);

  // Paste textarea
  const pasteWrap = document.createElement('div');
  pasteWrap.className = 'space-y-1';
  const pasteLabel = document.createElement('label');
  pasteLabel.className = 'block text-xs font-medium text-dark-400 uppercase tracking-wide';
  pasteLabel.textContent = 'Or paste receipt JSON';
  pasteWrap.appendChild(pasteLabel);

  const pasteArea = document.createElement('textarea');
  pasteArea.rows = 4;
  pasteArea.className =
    'w-full px-3 py-2 bg-dark-800 border border-dark-700 rounded-lg text-xs font-mono focus:outline-none focus:border-brand-500 focus:ring-1 focus:ring-brand-500 resize-y';
  pasteArea.placeholder = '{ "version": 1, ... }';
  pasteWrap.appendChild(pasteArea);
  importWrap.appendChild(pasteWrap);

  // Load button
  const loadBtn = document.createElement('button');
  loadBtn.type = 'button';
  loadBtn.className =
    'px-4 py-2 bg-dark-800 border border-dark-700 rounded-lg text-sm font-medium hover:border-brand-500 hover:text-brand-400 transition';
  loadBtn.textContent = 'Load Receipt';
  importWrap.appendChild(loadBtn);

  // Receipt error display
  const importErrorEl = document.createElement('div');
  importErrorEl.className = 'text-sm text-rose-300 bg-rose-500/10 border border-rose-500/40 rounded-lg p-3 hidden';
  importWrap.appendChild(importErrorEl);

  container.appendChild(importWrap);

  // -------------------------------------------------------------------------
  // Receipt summary + VK hash (shown after successful import)
  // -------------------------------------------------------------------------
  const summaryWrap = document.createElement('div');
  summaryWrap.className = 'hidden space-y-4 mb-4';

  const summaryHeading = document.createElement('h3');
  summaryHeading.className = 'text-xs font-medium text-dark-400 uppercase tracking-wide';
  summaryHeading.textContent = 'Receipt Context';
  summaryWrap.appendChild(summaryHeading);

  const summaryGrid = document.createElement('div');
  summaryGrid.className = 'grid grid-cols-1 sm:grid-cols-2 gap-3';
  summaryWrap.appendChild(summaryGrid);

  // VK hash field (canonical default, editable override)
  const vkWrap = document.createElement('div');
  vkWrap.className = 'space-y-1';
  const vkLabel = document.createElement('label');
  vkLabel.className = 'block text-xs font-medium text-dark-400 uppercase tracking-wide';
  vkLabel.textContent = 'Expected VK hash';
  vkWrap.appendChild(vkLabel);

  const vkInputWrap = document.createElement('div');
  vkInputWrap.className = 'flex gap-2';

  const vkInput = document.createElement('input');
  vkInput.type = 'text';
  vkInput.value = CANONICAL_SELECTIVE_DISCLOSURE_1_VK_HASH;
  vkInput.readOnly = true;
  vkInput.className =
    'flex-1 px-3 py-2 bg-dark-800 border border-dark-700 rounded-lg text-xs font-mono focus:outline-none focus:border-brand-500 focus:ring-1 focus:ring-brand-500 disabled:opacity-60';
  vkInputWrap.appendChild(vkInput);

  const vkOverrideBtn = document.createElement('button');
  vkOverrideBtn.type = 'button';
  vkOverrideBtn.className =
    'px-3 py-2 bg-dark-700 border border-dark-600 rounded-lg text-xs font-medium hover:border-brand-500 hover:text-brand-400 transition';
  vkOverrideBtn.textContent = 'Override';
  vkOverrideBtn.addEventListener('click', () => {
    vkInput.readOnly = !vkInput.readOnly;
    vkOverrideBtn.textContent = vkInput.readOnly ? 'Override' : 'Lock';
    if (!vkInput.readOnly) vkInput.focus();
  });
  vkInputWrap.appendChild(vkOverrideBtn);

  vkWrap.appendChild(vkInputWrap);

  const vkErrorEl = document.createElement('div');
  vkErrorEl.className = 'text-xs text-rose-400 hidden';
  vkWrap.appendChild(vkErrorEl);
  summaryWrap.appendChild(vkWrap);

  // Verify button
  const verifyBtn = document.createElement('button');
  verifyBtn.type = 'button';
  verifyBtn.className =
    'w-full px-4 py-2 bg-brand-500 text-dark-950 rounded-lg text-sm font-semibold shadow-lg shadow-brand-500/20 hover:bg-brand-400 transition disabled:opacity-50 disabled:cursor-not-allowed';
  verifyBtn.textContent = 'Verify Receipt';
  summaryWrap.appendChild(verifyBtn);

  container.appendChild(summaryWrap);

  // -------------------------------------------------------------------------
  // Results area
  // -------------------------------------------------------------------------
  const resultsWrap = document.createElement('div');
  resultsWrap.className = 'hidden space-y-3';
  container.appendChild(resultsWrap);

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------
  const showImportError = (msg) => {
    importErrorEl.textContent = msg;
    importErrorEl.classList.remove('hidden');
    summaryWrap.classList.add('hidden');
    resultsWrap.classList.add('hidden');
  };

  const clearImportError = () => {
    importErrorEl.classList.add('hidden');
    importErrorEl.textContent = '';
  };

  const validateReceiptShape = (r) => {
    if (typeof r.version !== 'number') return 'Missing or invalid receipt version';
    if (r.version !== 1) return `Unsupported disclosure receipt version: expected 1, got ${r.version}`;

    if (!r.circuit || typeof r.circuit !== 'object') return 'Missing circuit metadata';
    if (!r.circuit.name) return 'Missing or empty circuit name';
    if (!r.circuit.vkHash || typeof r.circuit.vkHash !== 'string')
      return 'Missing or invalid vkHash';
    const vkHex = r.circuit.vkHash;
    if (!vkHex.startsWith('0x') || vkHex.length !== 66 || !/^[0-9a-f]+$/.test(vkHex.slice(2)))
      return 'Invalid vkHash: expected 0x-prefixed 32-byte lowercase hex';

    if (!r.proofCompressedHex || typeof r.proofCompressedHex !== 'string')
      return 'Missing proofCompressedHex';
    const proofHex = r.proofCompressedHex;
    if (!proofHex.startsWith('0x') || proofHex.length !== 258 || !/^[0-9a-f]+$/.test(proofHex.slice(2)))
      return 'Invalid proof: expected 0x-prefixed 128-byte lowercase hex';

    if (!r.context || typeof r.context !== 'object') return 'Missing receipt context';
    if (!r.publicInputs || typeof r.publicInputs !== 'object') return 'Missing public inputs';

    return null;
  };

  const renderSummary = (r) => {
    summaryGrid.replaceChildren();
    const items = [
      { label: 'Network', value: r.context.network },
      { label: 'Pool address', value: r.context.poolAddress },
      { label: 'Authority', value: r.context.authorityLabel },
      { label: 'Purpose', value: r.context.purpose },
      { label: 'Nonce', value: r.context.contextNonce },
      { label: 'Issued at', value: r.issuedAt },
      { label: 'Circuit', value: r.circuit.name },
      { label: 'Receipt VK hash', value: shortCommitment(r.circuit.vkHash) },
    ];
    items.forEach((item) => {
      const cell = el('div', 'p-2 bg-dark-800 border border-dark-700 rounded-lg');
      cell.append(
        el('div', 'text-[10px] uppercase tracking-wide text-dark-500', item.label),
        el('div', 'text-xs font-mono text-dark-200 break-all', String(item.value)),
      );
      summaryGrid.appendChild(cell);
    });
  };

  const loadReceipt = (raw) => {
    clearImportError();
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (e) {
      showImportError(`Invalid JSON: ${e.message}`);
      return;
    }

    const shapeErr = validateReceiptShape(parsed);
    if (shapeErr) {
      showImportError(shapeErr);
      return;
    }

    receipt = parsed;
    receiptError = null;
    renderSummary(receipt);
    summaryWrap.classList.remove('hidden');
    resultsWrap.classList.add('hidden');
  };

  fileInput.addEventListener('change', (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => loadReceipt(ev.target.result);
    reader.onerror = () => showImportError('Failed to read file');
    reader.readAsText(file);
  });

  loadBtn.addEventListener('click', () => {
    loadReceipt(pasteArea.value.trim());
  });

  // -------------------------------------------------------------------------
  // Verification (Step 4.2)
  // -------------------------------------------------------------------------
  verifyBtn.addEventListener('click', async () => {
    if (!receipt) {
      showToast('Load a receipt first', 'error');
      return;
    }

    const expectedVkHash = vkInput.value.trim();
    if (!expectedVkHash) {
      vkErrorEl.textContent = 'Expected VK hash is required';
      vkErrorEl.classList.remove('hidden');
      return;
    }
    if (
      !expectedVkHash.startsWith('0x') ||
      expectedVkHash.length !== 66 ||
      !/^[0-9a-f]+$/.test(expectedVkHash.slice(2))
    ) {
      vkErrorEl.textContent = 'Invalid VK hash: expected 0x-prefixed 32-byte lowercase hex';
      vkErrorEl.classList.remove('hidden');
      return;
    }
    vkErrorEl.classList.add('hidden');

    verifyBtn.disabled = true;
    verifyBtn.textContent = 'Verifying…';
    resultsWrap.classList.remove('hidden');
    const verifyingRow = el('div', 'flex items-center gap-2 text-sm text-dark-300');
    verifyingRow.append(spinnerEl(), el('span', null, 'Running verification checks…'));
    resultsWrap.replaceChildren(verifyingRow);

    try {
      const report = await getHandle().webClient.verifySelectiveDisclosure(
        JSON.stringify(receipt),
        expectedVkHash
      );

      const proofOk = !!report.proofVerified;
      const contextOk = !!report.contextVerified;
      const rootOk = !!report.knownRootStatus;
      const fullyVerified = proofOk && contextOk && rootOk;

      resultsWrap.replaceChildren();

      const list = document.createElement('ul');
      list.className = 'space-y-2';
      list.setAttribute('role', 'list');
      list.setAttribute('aria-label', 'Verification results');

      const makeCheck = (label, pass, failText, passText) => {
        const li = el('li', `flex items-start gap-3 p-3 rounded-lg border ${
          pass
            ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-300'
            : 'bg-rose-500/10 border-rose-500/40 text-rose-300'
        }`);
        const iconWrap = el('div', 'mt-0.5 w-4 h-4 flex-shrink-0');
        iconWrap.appendChild(pass ? checkCircleIcon('w-4 h-4') : xCircleIcon('w-4 h-4'));
        const textWrap = el('div');
        textWrap.append(
          el('div', 'text-sm font-medium', pass ? passText[0] : passText[1]),
          el('div', 'text-xs opacity-80 mt-0.5', pass ? passText[2] : failText),
        );
        li.append(iconWrap, textWrap);
        return li;
      };

      list.appendChild(
        makeCheck(
          'proof',
          proofOk,
          'The proof does not verify. The receipt may be forged or the verifying key does not match.',
          ['Proof valid', 'Proof invalid', 'The cryptographic proof verifies against the registered circuit\'s verifying key.']
        )
      );
      list.appendChild(
        makeCheck(
          'context',
          contextOk,
          'The receipt context was altered or re-bound after the proof was created.',
          ['Context valid', 'Context mismatch', 'The declared authority/purpose/nonce context re-derives to the hash the proof committed to.']
        )
      );
      list.appendChild(
        makeCheck(
          'root',
          rootOk,
          'At least one Merkle root is no longer in the pool\'s known-root history. The receipt may be old or refer to a different pool.',
          ['Root fresh', 'Root stale or unknown', 'Every root in the receipt is still in the pool\'s on-chain root history.']
        )
      );

      resultsWrap.appendChild(list);

      if (fullyVerified) {
        const badge = el('div', 'mt-3 p-3 bg-emerald-500/10 border border-emerald-500/40 rounded-lg text-emerald-300 text-sm font-medium flex items-center gap-2');
        badge.setAttribute('role', 'status');
        badge.append(shieldIcon('w-5 h-5'), el('span', null, 'Fully verified — this receipt is trustworthy.'));
        resultsWrap.appendChild(badge);
      }
    } catch (err) {
      console.error('Verification failed:', err);
      resultsWrap.replaceChildren(
        el('div', 'text-sm text-rose-300 bg-rose-500/10 border border-rose-500/40 rounded-lg p-3',
          `Verification could not be completed: ${err.message || 'Unknown error'}`),
      );
    } finally {
      verifyBtn.disabled = false;
      verifyBtn.textContent = 'Verify Receipt';
    }
  });
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

async function init() {
  networkChip = document.getElementById('networkChip');
  walletChip = document.getElementById('walletChip');
  connectBtn = document.getElementById('connectBtn');
  toastContainer = document.getElementById('toast-container');
  toastTemplate = document.getElementById('tpl-toast');

  connectBtn?.addEventListener('click', () => connect());

  // Initialize wasm eagerly with a testnet RPC so the walletless verify
  // section works immediately. Wallet connect is gated on Testnet (see
  // connect()), so the default RPC is always correct for this page.
  try {
    await initializeWasm('https://soroban-testnet.stellar.org');
    networkChip.textContent = 'TESTNET';
  } catch (e) {
    console.error('WASM init failed:', e);
    if (isDbLockedError(e?.message)) {
      showDbLockedModal(e.message);
      return;
    }
    showToast('Failed to initialize cryptography', 'error', 8000);
  }

  const query = parseQueryParams();

  const generateContainer = document.getElementById('disclosure-generate');
  const verifyContainer = document.getElementById('disclosure-verify');

  if (generateContainer) mountGenerate(generateContainer);
  if (verifyContainer) mountVerify(verifyContainer);

  if (query.verify && verifyContainer) {
    verifyContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  // If a wallet is already connected/allowed for this origin (e.g. connected on
  // the main app page), restore the session automatically without a popup.
  const existingAddress = await getConnectedAddress();
  if (existingAddress) {
    await connect();
  }
}

init().catch((err) => {
  console.error('Init failed:', err);
  showToast('Page initialization failed', 'error', 8000);
});
