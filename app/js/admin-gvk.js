/**
 * Global View admin tab — pool decrypt cursor with paginated tx rows.
 */

import { axisBottom } from 'd3-axis';
import { brushX } from 'd3-brush';
import { format } from 'd3-format';
import { scaleLinear } from 'd3-scale';
import { select } from 'd3-selection';
import { symbol, symbolCircle } from 'd3-shape';
import { rpc } from '@stellar/stellar-sdk';
import { client, getCurrentRpcUrl } from './wasm-facade.js';
import { friendlyErrorMessage } from './facade-errors.js';
import { el, formatAmount as formatTokenAmount } from './ui/notes-view.js';

const BATCH_SIZE = 20;

const poolSelectEl = document.getElementById('gvkPoolSelect');
const privateKeyEl = document.getElementById('gvkPrivateKey');
const keyHintEl = document.getElementById('gvkKeyHint');
const auditBtnEl = document.getElementById('gvkAuditBtn');
const loadMoreBtnEl = document.getElementById('gvkLoadMoreBtn');
const viewTxBtnEl = document.getElementById('gvkViewTxBtn');
const viewNoteBtnEl = document.getElementById('gvkViewNoteBtn');
const viewGraphBtnEl = document.getElementById('gvkViewGraphBtn');
const viewPkGraphBtnEl = document.getElementById('gvkViewPkGraphBtn');
const exportBtnEl = document.getElementById('gvkExportBtn');
const statusEl = document.getElementById('gvkAuditStatus');
const emptyEl = document.getElementById('gvkAuditEmpty');
const resultsEl = document.getElementById('gvkAuditResults');
const filterAmountMinEl = document.getElementById('gvkFilterAmountMin');
const filterAmountMaxEl = document.getElementById('gvkFilterAmountMax');
const filterLedgerFromEl = document.getElementById('gvkFilterLedgerFrom');
const filterLedgerToEl = document.getElementById('gvkFilterLedgerTo');
const filterPkEl = document.getElementById('gvkFilterPk');
const filterTimeFromEl = document.getElementById('gvkFilterTimeFrom');
const filterTimeToEl = document.getElementById('gvkFilterTimeTo');
const filterTimeHintEl = document.getElementById('gvkFilterTimeHint');
const filtersClearBtnEl = document.getElementById('gvkFiltersClearBtn');

const state = {
  pools: [],
  audit: null,
  auditedPoolContractId: null,
  rows: [],
  poolGvkMode: null,
  txCounter: 0,
  exhausted: false,
  noteLinks: new Map(),
  filteredVisibleCount: BATCH_SIZE,
  view: 'tx',
  selectedNoteId: null,
  graphNotes: null,
  selectedPk: null,
  selectedFlow: null,
  selectedDot: null,
  pkGraphNodes: null,
  ledgerTimeBounds: null,
  timeFilterLedgers: { from: null, to: null },
};

const LEDGER_TIME_BOUNDS_TTL_MS = 60_000;
const TIME_FILTER_HINT_DEFAULT = 'Approximated from ledger close times.';

// getLatestLedger's closeTime and getEvents' oldestLedgerCloseTime are
// Unix-epoch-second strings, unlike each event's own ledgerClosedAt
// (RFC3339) — Date.parse can't read the former.
function parseRpcTimestamp(value) {
  const trimmed = String(value ?? '').trim();
  if (/^\d+$/.test(trimmed)) return Number(trimmed);
  const ms = Date.parse(trimmed);
  return Number.isFinite(ms) ? ms / 1000 : NaN;
}

async function fetchLedgerTimeBounds() {
  if (state.ledgerTimeBounds && Date.now() - state.ledgerTimeBounds.fetchedAt < LEDGER_TIME_BOUNDS_TTL_MS) {
    return state.ledgerTimeBounds;
  }

  const rpcUrl = getCurrentRpcUrl();
  if (!rpcUrl) throw new Error('RPC not ready yet');
  const poolContractId = poolSelectEl?.value?.trim();
  if (!poolContractId) throw new Error('Select a pool first');

  const server = new rpc.Server(rpcUrl);
  const latest = await server.getLatestLedger();
  const startLedger = Math.max(1, latest.sequence - 1);
  const events = await server.getEvents({
    startLedger,
    filters: [{ type: 'contract', contractIds: [poolContractId], topics: [['**']] }],
    limit: 1,
  });

  const bounds = {
    oldest: { ledger: events.oldestLedger, unixTime: parseRpcTimestamp(events.oldestLedgerCloseTime) },
    latest: { ledger: latest.sequence, unixTime: parseRpcTimestamp(latest.closeTime) },
    fetchedAt: Date.now(),
  };
  if (!Number.isFinite(bounds.oldest.unixTime) || !Number.isFinite(bounds.latest.unixTime)) {
    throw new Error('RPC returned an unparsable ledger close time');
  }
  state.ledgerTimeBounds = bounds;
  return bounds;
}

function secondsPerLedger(bounds) {
  const ledgers = Math.max(1, bounds.latest.ledger - bounds.oldest.ledger);
  const seconds = Math.max(1, bounds.latest.unixTime - bounds.oldest.unixTime);
  return seconds / ledgers;
}

function ledgerForTime(bounds, unixTime) {
  const period = secondsPerLedger(bounds);
  const estimated = bounds.latest.ledger + (unixTime - bounds.latest.unixTime) / period;
  return Math.round(Math.min(bounds.latest.ledger, Math.max(bounds.oldest.ledger, estimated)));
}

function timeForLedger(bounds, ledger) {
  return bounds.latest.unixTime + (ledger - bounds.latest.ledger) * secondsPerLedger(bounds);
}

function parseUtcDatetimeLocal(value) {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/.exec(value || '');
  if (!match) return null;
  const [, y, mo, d, h, mi, s] = match;
  return Date.UTC(+y, mo - 1, +d, +h, +mi, +(s || 0)) / 1000;
}

function formatUtcDatetimeLocal(unixTime) {
  const d = new Date(unixTime * 1000);
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}T${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}

async function updateTimeFilterLedgers() {
  const fromUnix = parseUtcDatetimeLocal(filterTimeFromEl?.value);
  const toUnix = parseUtcDatetimeLocal(filterTimeToEl?.value);

  if (fromUnix == null && toUnix == null) {
    state.timeFilterLedgers = { from: null, to: null };
    if (filterTimeHintEl) filterTimeHintEl.textContent = TIME_FILTER_HINT_DEFAULT;
    return;
  }

  try {
    const bounds = await fetchLedgerTimeBounds();
    const from = fromUnix != null ? ledgerForTime(bounds, fromUnix) : null;
    const to = toUnix != null ? ledgerForTime(bounds, toUnix) : null;
    state.timeFilterLedgers = { from, to };
    if (filterTimeHintEl) {
      filterTimeHintEl.textContent =
        `≈ ledger ${from ?? bounds.oldest.ledger}–${to ?? bounds.latest.ledger} (~${secondsPerLedger(bounds).toFixed(2)}s/ledger)`;
    }
  } catch (err) {
    state.timeFilterLedgers = { from: null, to: null };
    if (filterTimeHintEl) filterTimeHintEl.textContent = friendlyErrorMessage(err?.message || String(err));
  }
}

function combineBound(a, b, pick) {
  if (a == null) return b;
  if (b == null) return a;
  return pick(a, b);
}

function noteRowId(txIndex, side, slotIndex) {
  return `${txIndex}:${side}:${slotIndex}`;
}

function truncateHex(value) {
  const s = String(value ?? '').trim();
  if (!s) return { display: '—', full: null };
  if (s.length <= 18) return { display: s, full: null };
  return { display: `${s.slice(0, 18)}…`, full: s };
}

/** Short PK label for narrow, fixed-width spots (e.g. the PK graph's lane column): "0x" + 13 hex chars. */
function shortPkLabel(pk) {
  const s = String(pk ?? '').trim();
  if (!s) return '—';
  const hex = s.startsWith('0x') ? s.slice(2) : s;
  return `0x${hex.slice(0, 13)}`;
}

function asCell(value) {
  if (value == null) return { display: '—', full: null };
  if (typeof value === 'string') return { display: value, full: null };
  return value;
}

function normalizeFieldKey(value) {
  const raw = String(value ?? '').trim().toLowerCase();
  return raw || null;
}

function pkCell(value) {
  const raw = String(value ?? '').trim();
  const truncated = truncateHex(raw);
  if (!raw) return truncated;
  return { ...truncated, matchPk: normalizeFieldKey(raw) };
}

function copyToClipboard(cell, text) {
  navigator.clipboard?.writeText(text).then(() => {
    const original = cell.textContent;
    cell.textContent = 'Copied!';
    cell.classList.add('!text-emerald-300');
    setTimeout(() => {
      cell.textContent = original;
      cell.classList.remove('!text-emerald-300');
    }, 900);
  }).catch(() => {});
}

function appendGridCell(grid, value, noteId) {
  const { display, full, matchPk } = asCell(value);
  const cell = el(
    'div',
    'bg-ink-950/70 px-2 py-1.5 font-mono text-slate-300 whitespace-nowrap overflow-hidden text-ellipsis transition-colors',
    display,
  );
  if (full) {
    cell.title = `${full} (click to copy)`;
    cell.classList.add('cursor-pointer', 'hover:!text-white');
    cell.addEventListener('click', () => copyToClipboard(cell, full));
  }
  if (matchPk) cell.dataset.gvkPk = matchPk;
  if (noteId) cell.dataset.gvkNoteId = noteId;
  grid.appendChild(cell);
}

const PK_HIGHLIGHT_CLASSES = ['!bg-cyan-500/20', '!text-cyan-50'];
const NOTE_HIGHLIGHT_CLASSES = ['!bg-amber-500/20', '!text-amber-50'];
let activePkHighlight = null;
/** @type {HTMLElement[]} */
let activeNoteCells = [];
let activeNoteSource = null;

function toggleCellHighlight(cells, classes, enabled) {
  for (const cell of cells) {
    // Tailwind's bg-/text-color utilities don't affect SVG fill/stroke, so
    // graph marks (circles/lines) get a filter-based highlight instead.
    if (cell instanceof SVGElement) {
      cell.style.filter = enabled ? 'brightness(1.6) drop-shadow(0 0 3px rgba(255,255,255,0.7))' : '';
      continue;
    }
    for (const className of classes) {
      cell.classList.toggle(className, enabled);
    }
  }
}

function queryNoteCells(noteId) {
  if (!resultsEl || !noteId) return [];
  return [...resultsEl.querySelectorAll(`[data-gvk-note-id="${CSS.escape(noteId)}"]`)];
}

function setPkHighlight(pk, enabled) {
  if (!resultsEl || !pk) return;
  toggleCellHighlight(
    [...resultsEl.querySelectorAll(`[data-gvk-pk="${CSS.escape(pk)}"]`)],
    PK_HIGHLIGHT_CLASSES,
    enabled,
  );
}

function clearPkHighlight() {
  if (!activePkHighlight) return;
  setPkHighlight(activePkHighlight, false);
  activePkHighlight = null;
}

/**
 * Graph-only: when hovering a note, reveals the pre-drawn (normally
 * invisible, pointer-events:none) squares for every note touched by the ONE
 * relevant tx — both its sibling outputs *and* the inputs it consumed, since
 * a tx's inputs and outputs share a single ledger. Keyed by exact tx index,
 * not x-position, since two different txs can share a ledger. Purely a
 * visual reveal; never intercepts hover itself, so it never competes with
 * the pk/note-link highlighting above.
 */
let activeTxSquareIndices = [];

function txSquareSelector(txIndex) {
  const escaped = CSS.escape(String(txIndex));
  return `rect[data-gvk-tx-created="${escaped}"], rect[data-gvk-tx-spent="${escaped}"]`;
}

function setTxSquaresVisible(txIndex, visible) {
  if (!resultsEl || txIndex == null) return;
  for (const square of resultsEl.querySelectorAll(txSquareSelector(txIndex))) {
    square.style.opacity = visible ? '1' : '0';
  }
}

function clearTxSquares() {
  for (const txIndex of activeTxSquareIndices) setTxSquaresVisible(txIndex, false);
  activeTxSquareIndices = [];
}

function showTxSquares(txIndices) {
  clearTxSquares();
  activeTxSquareIndices = txIndices.filter((v) => v != null);
  for (const txIndex of activeTxSquareIndices) setTxSquaresVisible(txIndex, true);
}

function syncTxSquaresForElement(el) {
  if (!el) return clearTxSquares();
  // Whichever side this specific dot represents (see the tagging rules in
  // renderGraph) — never both, so we never mix in an unrelated transaction.
  showTxSquares([el.dataset?.gvkTxCreated ?? el.dataset?.gvkTxSpent]);
}

function applyNoteHighlight(cells) {
  clearNoteHighlight();
  activeNoteCells = cells;
  toggleCellHighlight(activeNoteCells, NOTE_HIGHLIGHT_CLASSES, true);
}

function clearNoteHighlight() {
  if (activeNoteCells.length === 0) return;
  toggleCellHighlight(activeNoteCells, NOTE_HIGHLIGHT_CLASSES, false);
  activeNoteCells = [];
}

function clearAllHighlights() {
  clearPkHighlight();
  clearNoteHighlight();
  clearTxSquares();
  activeNoteSource = null;
}

/** Re-highlights the clicked graph note (and its same-tx siblings), so it stays lit outside of hover. */
function applySelectionHighlight() {
  if (state.view !== 'graph' || !state.selectedNoteId) return;
  const noteId = state.selectedNoteId;
  const note = state.graphNotes?.find((n) => n.noteId === noteId);
  if (!note) return;
  activeNoteSource = noteId;
  applyNoteHighlight(noteHighlightFor(noteId));
  showTxSquares([note.createdTxIndex, note.spentTxIndex]);
}

function restoreBaseHighlight() {
  clearAllHighlights();
  applySelectionHighlight();
}

function noteHighlightFor(noteId) {
  const cells = queryNoteCells(noteId);
  const linkedId = state.noteLinks.get(noteId);
  if (linkedId) cells.push(...queryNoteCells(linkedId));
  return cells;
}

function linkNotes(a, b) {
  state.noteLinks.set(a, b);
  state.noteLinks.set(b, a);
}

function rebuildNoteLinks() {
  state.noteLinks = new Map();

  /** @type {Map<string, string>} */
  const commitmentToOutputNote = new Map();

  for (const { tx, index: txIndex } of state.rows) {
    for (const slot of normalizedOutputs(tx)) {
      const key = normalizeFieldKey(slot.audited?.commitment ?? slot.commitment);
      if (key) commitmentToOutputNote.set(key, noteRowId(txIndex, 'output', slot.index));
    }
  }

  for (const { tx, index: txIndex } of state.rows) {
    for (const slot of normalizedInputs(tx)) {
      const commitmentKey = normalizeFieldKey(slot.audited?.commitment);
      if (!commitmentKey || !slot.nullifier) continue;

      const outputNoteId = commitmentToOutputNote.get(commitmentKey);
      if (outputNoteId) {
        linkNotes(outputNoteId, noteRowId(txIndex, 'input', slot.index));
      }
    }
  }
}

function bindResultHighlights() {
  if (!resultsEl || resultsEl.dataset.gvkHighlightBound === '1') return;
  resultsEl.dataset.gvkHighlightBound = '1';

  resultsEl.addEventListener('mouseover', (event) => {
    const pkEl = event.target.closest('[data-gvk-pk]');
    if (pkEl && resultsEl.contains(pkEl)) {
      const pk = pkEl.dataset.gvkPk;
      if (pk && pk !== activePkHighlight) {
        clearAllHighlights();
        activePkHighlight = pk;
        setPkHighlight(pk, true);
      }
      syncTxSquaresForElement(pkEl);
      return;
    }

    const noteCell = event.target.closest('[data-gvk-note-id]');
    if (noteCell && resultsEl.contains(noteCell)) {
      const noteId = noteCell.dataset.gvkNoteId;
      if (noteId && noteId !== activeNoteSource) {
        clearAllHighlights();
        activeNoteSource = noteId;
        applyNoteHighlight(noteHighlightFor(noteId));
      }
      syncTxSquaresForElement(noteCell);
      return;
    }

    restoreBaseHighlight();
  });

  resultsEl.addEventListener('mouseleave', () => {
    restoreBaseHighlight();
  });
}

function parseFieldAmount(hex) {
  const s = String(hex ?? '').trim();
  if (!s.startsWith('0x')) return 0n;
  try {
    return BigInt(s);
  } catch {
    return 0n;
  }
}

const STROOPS_PER_XLM = 10_000_000n;

function formatAmount(hex) {
  return hex ? formatTokenAmount(parseFieldAmount(hex)) : '—';
}

/** @returns {import('stellar-private-payments/types/gvk').GvkAuditedNote | null} */
function asAuditedNote(value) {
  if (!value) return null;
  if (value.note?.pk != null && value.commitment != null) return value;
  return null;
}

function normalizedOutputs(tx) {
  return (tx.outputs ?? []).map((slot, index) => ({
    index,
    commitment: slot?.commitment ?? null,
    audited: asAuditedNote(slot?.note),
  }));
}

function normalizedInputs(tx) {
  return (tx.inputs ?? []).map((slot, index) => ({
    index,
    nullifier: slot?.nullifier ?? null,
    audited: asAuditedNote(slot?.note),
  }));
}

function sumAuditedAmounts(slots) {
  return slots.reduce(
    (sum, slot) => sum + parseFieldAmount(slot.audited?.note?.amount),
    0n,
  );
}

/** Mirrors classify_tx in sdk/native/examples/gvk-audit.rs. */
function classifyTx(tx) {
  const inputs = normalizedInputs(tx);
  const hasRealInput = inputs.some((slot) => slot.audited);
  if (!hasRealInput) return 'deposit';

  const inputSum = sumAuditedAmounts(inputs);
  const outputSum = sumAuditedAmounts(normalizedOutputs(tx));
  return inputSum > outputSum ? 'withdraw' : 'transfer';
}

function setPanelStatus(message, kind = 'info') {
  if (!statusEl) return;
  if (!message) {
    statusEl.classList.add('hidden');
    statusEl.textContent = '';
    return;
  }
  statusEl.textContent = message;
  statusEl.classList.remove('hidden');
  statusEl.className = 'rounded-xl border px-4 py-3 text-sm ' + (
    kind === 'error'
      ? 'border-rose-500/20 bg-rose-500/10 text-rose-200'
      : kind === 'ok'
        ? 'border-emerald-500/20 bg-emerald-500/10 text-emerald-200'
        : 'border-white/10 bg-ink-900/70 text-slate-300'
  );
}

function noteCells(audited) {
  if (!audited) {
    return { amount: '—', pk: '—', commitment: '—' };
  }
  return {
    amount: formatAmount(audited.note?.amount),
    pk: pkCell(audited.note?.pk),
    commitment: truncateHex(audited.commitment),
  };
}

const COLUMN_WIDTHS = {
  Note: 40,
  Amount: 96,
  PK: 88,
  Commitment: 96,
  Nullifier: 96,
  Created: 130,
  Status: 70,
  Spent: 130,
};

function columnWidth(header) {
  return COLUMN_WIDTHS[header] ?? 96;
}

function renderSlotTable(title, headers, noteRows) {
  const block = el('div', 'min-w-0 flex-1 space-y-1.5');
  block.appendChild(el('div', 'text-[10px] font-medium uppercase tracking-[0.18em] text-slate-500', title));
  const totalWidth = headers.reduce((sum, header) => sum + columnWidth(header), 0);
  block.style.flexGrow = totalWidth;
  block.style.flexBasis = '0%';

  if (noteRows.length === 0) {
    const empty = el('div', 'w-full rounded-lg border border-white/6 bg-ink-950/50 px-2 py-1.5');
    empty.appendChild(el('p', 'font-mono text-[11px] text-slate-500', '—'));
    block.appendChild(empty);
    return block;
  }

  const table = el('div', 'w-full rounded-lg border border-white/6 bg-ink-950/50');
  const grid = el('div', 'grid w-full gap-px bg-white/6 text-[11px]');
  grid.style.gridTemplateColumns = headers.map((header) => `${columnWidth(header)}fr`).join(' ');

  for (const header of headers) {
    grid.appendChild(el(
      'div',
      'bg-ink-950/90 px-2 py-1.5 font-medium uppercase tracking-wide text-slate-500',
      header,
    ));
  }

  for (const { noteId, cells } of noteRows) {
    for (const cell of cells) {
      appendGridCell(grid, cell, noteId);
    }
  }

  table.appendChild(grid);
  block.appendChild(table);
  return block;
}

function readFilters() {
  const toInt = (el) => {
    const raw = el?.value?.trim();
    if (!raw) return null;
    const n = Number(raw);
    return Number.isFinite(n) ? n : null;
  };

  const toStroops = (el) => {
    const raw = el?.value?.trim();
    if (!raw) return null;
    const xlm = Number(raw);
    if (!Number.isFinite(xlm) || xlm < 0) return null;
    return BigInt(Math.round(xlm * Number(STROOPS_PER_XLM)));
  };

  // Comma-separated: matches a note whose PK contains ANY of the given terms.
  const pkTerms = (filterPkEl?.value ?? '')
    .split(',')
    .map((term) => normalizeFieldKey(term))
    .filter(Boolean);

  return {
    amountMin: toStroops(filterAmountMinEl),
    amountMax: toStroops(filterAmountMaxEl),
    ledgerFrom: combineBound(toInt(filterLedgerFromEl), state.timeFilterLedgers.from, Math.max),
    ledgerTo: combineBound(toInt(filterLedgerToEl), state.timeFilterLedgers.to, Math.min),
    pk: pkTerms.length > 0 ? pkTerms : null,
  };
}

function txNotes(tx) {
  return [...normalizedOutputs(tx), ...normalizedInputs(tx)]
    .map((slot) => slot.audited)
    .filter(Boolean);
}

function isFiltersActive(filters) {
  return filters.amountMin != null || filters.amountMax != null
    || filters.ledgerFrom != null || filters.ledgerTo != null || !!filters.pk;
}

function amountMatchesRange(amount, filters) {
  if (filters.amountMin != null && amount < filters.amountMin) return false;
  if (filters.amountMax != null && amount > filters.amountMax) return false;
  return true;
}

function noteMatchesAmount(auditedNote, filters) {
  if (filters.amountMin == null && filters.amountMax == null) return true;
  return amountMatchesRange(parseFieldAmount(auditedNote?.note?.amount), filters);
}

function noteMatchesAmountAndPk(auditedNote, filters) {
  if (filters.pk) {
    const pk = normalizeFieldKey(auditedNote?.note?.pk);
    if (!pk || !filters.pk.some((term) => pk.includes(term))) return false;
  }
  return noteMatchesAmount(auditedNote, filters);
}

function rowMatchesFilters(row, filters) {
  const { tx } = row;

  if (filters.ledgerFrom != null && tx.ledger < filters.ledgerFrom) return false;
  if (filters.ledgerTo != null && tx.ledger > filters.ledgerTo) return false;

  if (filters.amountMin == null && filters.amountMax == null && !filters.pk) return true;

  return txNotes(tx).some((note) => noteMatchesAmountAndPk(note, filters));
}

function computeFilteredRows(filters) {
  return state.rows.filter((row) => rowMatchesFilters(row, filters));
}

/** The tx rows any view/export should use: filtered + paginated, same as the tables. */
function computeVisibleRows(filters) {
  const filteredRows = computeFilteredRows(filters);
  return isFiltersActive(filters) ? filteredRows.slice(0, state.filteredVisibleCount) : state.rows;
}

function renderResults() {
  if (!resultsEl || !emptyEl) return;

  const filters = readFilters();
  const filtersActive = isFiltersActive(filters);
  const visibleRows = computeVisibleRows(filters);

  if (state.rows.length === 0) {
    resultsEl.classList.add('hidden');
    emptyEl.classList.remove('hidden');
    emptyEl.textContent = 'Select a pool, enter the authority key, then run Sync & Audit.';
    return;
  }

  if (visibleRows.length === 0) {
    resultsEl.classList.add('hidden');
    emptyEl.classList.remove('hidden');
    emptyEl.textContent = filtersActive
      ? 'No transactions match the current filters.'
      : 'Select a pool, enter the authority key, then run Sync & Audit.';
    return;
  }

  // Measured before clearing resultsEl below: reading layout (clientWidth) once
  // the container is mid-teardown forces a synchronous reflow while the page
  // is transiently shorter, which makes the browser clamp/jump scroll position.
  const containerWidth = resultsEl.clientWidth;

  emptyEl.classList.add('hidden');
  resultsEl.classList.remove('hidden');
  clearAllHighlights();
  resultsEl.innerHTML = '';

  if (state.view === 'note') {
    renderNoteTable(visibleRows, filters);
  } else if (state.view === 'graph') {
    renderGraph(visibleRows, containerWidth, filters);
  } else if (state.view === 'pkGraph') {
    renderPkGraph(visibleRows, containerWidth, filters);
  } else {
    renderTxCards(visibleRows);
  }

  rebuildNoteLinks();
  applySelectionHighlight();
}

function renderTxCards(rows) {
  for (const row of rows) {
    const { tx, index, kind } = row;
    const outputs = normalizedOutputs(tx);
    const inputs = normalizedInputs(tx);
    const realOutputCount = outputs.filter((slot) => slot.audited).length;
    const realInputCount = inputs.filter((slot) => slot.audited).length;
    const metaParts = [`${realOutputCount} output note(s)`];
    if (state.poolGvkMode === 'traceable') {
      metaParts.push(`${realInputCount} input note(s)`);
    }
    const [outputsMeta, inputsMeta] = metaParts;

    const card = el(
      'article',
      'flex flex-nowrap items-start gap-3 overflow-x-auto rounded-2xl border border-white/8 bg-ink-900/70 px-5 py-4',
    );

    const meta = el('div', 'w-32 shrink-0 space-y-0.5 sm:w-36');
    meta.appendChild(el('div', 'text-sm font-medium text-white', `tx ${index}`));
    if (kind) meta.appendChild(el('div', 'text-sm font-medium text-white', kind));
    meta.appendChild(el('div', 'text-sm font-medium text-white', `ledger ${tx.ledger}`));
    meta.appendChild(el(
      'div',
      'mt-1 font-mono text-xs leading-relaxed text-slate-400',
      outputsMeta,
    ));
    if (inputsMeta) {
      meta.appendChild(el(
        'div',
        'font-mono text-xs leading-relaxed text-slate-400',
        inputsMeta,
      ));
    }
    card.appendChild(meta);

    const details = el('div', 'flex min-w-0 flex-1 flex-nowrap items-start gap-3');

    details.appendChild(renderSlotTable(
      'Input notes',
      ['Note', 'Amount', 'PK', 'Commitment', 'Nullifier'],
      inputs.map((slot) => {
        const cells = noteCells(slot.audited);
        return {
          noteId: noteRowId(index, 'input', slot.index),
          cells: [
            `[${slot.index}]`,
            cells.amount,
            cells.pk,
            slot.audited ? cells.commitment : '—',
            truncateHex(slot.nullifier),
          ],
        };
      }),
    ));

    details.appendChild(renderSlotTable(
      'Output notes',
      ['Note', 'Amount', 'PK', 'Commitment'],
      outputs.map((slot) => {
        const cells = noteCells(slot.audited);
        return {
          noteId: noteRowId(index, 'output', slot.index),
          cells: [
            `[${slot.index}]`,
            cells.amount,
            cells.pk,
            slot.audited ? cells.commitment : truncateHex(slot.commitment),
          ],
        };
      }),
    ));

    card.appendChild(details);
    resultsEl.appendChild(card);
  }
}

/** Flat table of every note across the given tx rows — no tx-card grouping. */
/**
 * Collapses every output/input slot across the given tx rows into one record
 * per distinct note (keyed by commitment), so a note created in one tx and
 * later spent in another shows up exactly once — not once per tx it touches.
 */
function collectNotes(rows) {
  const notes = new Map();
  let fallbackKey = 0;

  for (const { tx, index, kind } of rows) {
    for (const slot of normalizedOutputs(tx)) {
      const commitment = slot.audited?.commitment ?? slot.commitment ?? null;
      const key = normalizeFieldKey(commitment) ?? `~${fallbackKey++}`;
      notes.set(key, {
        commitment,
        audited: slot.audited,
        createdTxIndex: index,
        createdLedger: tx.ledger,
        createdKind: kind,
        spentTxIndex: null,
        spentLedger: null,
        spentKind: null,
        nullifier: null,
        noteId: noteRowId(index, 'output', slot.index),
      });
    }
  }

  for (const { tx, index, kind } of rows) {
    for (const slot of normalizedInputs(tx)) {
      const commitmentKey = normalizeFieldKey(slot.audited?.commitment);
      const existing = commitmentKey ? notes.get(commitmentKey) : null;

      if (existing) {
        existing.spentTxIndex = index;
        existing.spentLedger = tx.ledger;
        existing.spentKind = kind;
        existing.nullifier = slot.nullifier;
        if (!existing.audited && slot.audited) existing.audited = slot.audited;
        continue;
      }

      // Spent, but its creating output isn't in the currently visible set.
      notes.set(commitmentKey ?? `~${fallbackKey++}`, {
        commitment: slot.audited?.commitment ?? null,
        audited: slot.audited,
        createdTxIndex: null,
        createdLedger: null,
        createdKind: null,
        spentTxIndex: index,
        spentLedger: tx.ledger,
        spentKind: kind,
        nullifier: slot.nullifier,
        noteId: noteRowId(index, 'input', slot.index),
      });
    }
  }

  return [...notes.values()].filter((note) => note.audited);
}

let fullPkGraphCache = null;

/** The unfiltered graph over every loaded row — rebuilt only when rows are appended or reset. */
function fullPkGraph() {
  if (fullPkGraphCache?.rows !== state.rows || fullPkGraphCache.count !== state.rows.length) {
    fullPkGraphCache = { rows: state.rows, count: state.rows.length, graph: buildPkGraph(state.rows, NO_FILTERS) };
  }
  return fullPkGraphCache.graph;
}

const NO_FILTERS = { amountMin: null, amountMax: null, ledgerFrom: null, ledgerTo: null, pk: null };

function amountByPk(slots) {
  const totals = new Map();
  for (const slot of slots) {
    const pk = normalizeFieldKey(slot.audited.note.pk);
    if (!pk) continue;
    totals.set(pk, (totals.get(pk) ?? 0n) + parseFieldAmount(slot.audited.note.amount));
  }
  return totals;
}

/**
 * Per input PK: what went in, minus what came back as change or went on to
 * someone else. Computed over the tx's full slot set — hiding one of its notes
 * with the amount filter must not change the withdrawal; the filter applies to
 * the resulting amount instead.
 */
function withdrawnByPk(inputs, outputs, filters) {
  const inputTotals = amountByPk(inputs);
  const spent = new Map();

  for (const slot of outputs) {
    const toPk = normalizeFieldKey(slot.audited.note.pk);
    if (!toPk) continue;
    const amount = parseFieldAmount(slot.audited.note.amount);
    // A multi-sender tx doesn't say whose funds went where.
    const charged = inputTotals.has(toPk) ? [toPk] : inputTotals.keys();
    for (const pk of charged) spent.set(pk, (spent.get(pk) ?? 0n) + amount);
  }

  const withdrawn = new Map();
  for (const [pk, inputTotal] of inputTotals) {
    const amount = inputTotal - (spent.get(pk) ?? 0n);
    if (amount > 0n && amountMatchesRange(amount, filters)) withdrawn.set(pk, amount);
  }
  return withdrawn;
}

/** Builds a PK-node / transfer-edge graph out of the given tx rows. Only a deposit has no counterparty PK. */
function buildPkGraph(rows, filters) {
  const nodes = new Map();
  const edges = new Map();

  const ensureNode = (pk) => {
    let node = nodes.get(pk);
    if (!node) {
      node = {
        pk,
        deposited: 0n, depositCount: 0,
        received: 0n, receivedCount: 0,
        withdrawn: 0n, withdrawCount: 0,
        transferIn: 0n, transferInCount: 0,
        transferOut: 0n, transferOutCount: 0,
      };
      nodes.set(pk, node);
    }
    return node;
  };

  const ensureEdge = (from, to) => {
    const key = `${from}=>${to}`;
    let edge = edges.get(key);
    if (!edge) {
      edge = { from, to, count: 0, amount: 0n };
      edges.set(key, edge);
    }
    return edge;
  };

  // Amount-only; PK visibility is decided after, in filterPkGraphByPk.
  for (const { tx, index, kind } of rows) {
    const allOutputs = normalizedOutputs(tx).filter((slot) => slot.audited);
    const allInputs = normalizedInputs(tx).filter((slot) => slot.audited);
    const outputs = allOutputs.filter((slot) => noteMatchesAmount(slot.audited, filters));
    // View-only pools can't decrypt inputs, so a tx's kind is unknowable
    // there — its notes count as received, never as a classified deposit.
    const effectiveKind = kind ?? (allInputs.length === 0 ? 'unknown' : 'transfer');

    if (effectiveKind === 'deposit' || effectiveKind === 'unknown') {
      const known = effectiveKind === 'deposit';
      for (const slot of outputs) {
        const pk = normalizeFieldKey(slot.audited.note.pk);
        if (!pk) continue;
        const node = ensureNode(pk);
        const amount = parseFieldAmount(slot.audited.note.amount);
        if (known) {
          node.deposited += amount;
          node.depositCount += 1;
        } else {
          node.received += amount;
          node.receivedCount += 1;
        }
      }
      continue;
    }

    // Senders come off the whole tx, not the amount-filtered notes.
    const inputPks = [...new Set(
      allInputs.map((slot) => normalizeFieldKey(slot.audited.note.pk)).filter(Boolean),
    )];

    for (const slot of outputs) {
      const toPk = normalizeFieldKey(slot.audited.note.pk);
      if (!toPk || inputPks.includes(toPk)) continue; // change, not a transfer
      const amount = parseFieldAmount(slot.audited.note.amount);

      for (const fromPk of inputPks) {
        const edge = ensureEdge(fromPk, toPk);
        edge.count += 1;
        edge.amount += amount;

        const fromNode = ensureNode(fromPk);
        fromNode.transferOut += amount;
        fromNode.transferOutCount += 1;
        const toNode = ensureNode(toPk);
        toNode.transferIn += amount;
        toNode.transferInCount += 1;
      }
    }

    // A withdraw tx can still transfer part of its input to someone else.
    if (effectiveKind === 'withdraw') {
      for (const [pk, amount] of withdrawnByPk(allInputs, allOutputs, filters)) {
        const node = ensureNode(pk);
        node.withdrawn += amount;
        node.withdrawCount += 1;
      }
    }
  }

  return { nodes: [...nodes.values()], edges: [...edges.values()] };
}

function pkMatchesTerms(pk, terms) {
  return terms.some((term) => pk.includes(term));
}

/**
 * Applies the PK filter to an already-built (amount-filtered-only) graph:
 * keeps a node if it matches directly, OR if it's the other side of an edge
 * touching a matching PK — so filtering to one PK still shows who it
 * transferred with, instead of only that PK's isolated activity.
 */
function filterPkGraphByPk(nodes, edges, pkTerms) {
  if (!pkTerms) return { nodes, edges };

  const matched = new Set(nodes.filter((n) => pkMatchesTerms(n.pk, pkTerms)).map((n) => n.pk));
  const keptEdges = edges.filter((e) => matched.has(e.from) || matched.has(e.to));

  const visible = new Set(matched);
  for (const e of keptEdges) {
    visible.add(e.from);
    visible.add(e.to);
  }

  return { nodes: nodes.filter((n) => visible.has(n.pk)), edges: keptEdges };
}

/**
 * Per-occurrence view for the PK timeline chart: one "dot" per (PK, tx) pair
 * at that tx's ledger, plus one "flow" per transfer counterparty pair — the
 * two dots a flow connects always share the flow's ledger, i.e. the same x
 * position, so the connecting line is always perfectly vertical.
 */
function buildPkTimelineEvents(rows, filters) {
  const dots = new Map();

  const ensureDot = (pk, txIndex, ledger) => {
    const key = `${pk}|${txIndex}`;
    let dot = dots.get(key);
    if (!dot) {
      dot = { pk, txIndex, ledger, deposited: 0n, received: 0n, withdrawn: 0n, transferIn: 0n, transferOut: 0n };
      dots.set(key, dot);
    }
    return dot;
  };

  const flows = [];

  // Amount-only; PK visibility is decided after, in filterPkTimelineByPk.
  for (const { tx, index, kind } of rows) {
    const allOutputs = normalizedOutputs(tx).filter((slot) => slot.audited);
    const allInputs = normalizedInputs(tx).filter((slot) => slot.audited);
    const outputs = allOutputs.filter((slot) => noteMatchesAmount(slot.audited, filters));
    // See buildPkGraph: a view-only pool's tx kind is unknowable.
    const effectiveKind = kind ?? (allInputs.length === 0 ? 'unknown' : 'transfer');
    const ledger = tx.ledger;

    if (effectiveKind === 'deposit' || effectiveKind === 'unknown') {
      const bucket = effectiveKind === 'deposit' ? 'deposited' : 'received';
      for (const slot of outputs) {
        const pk = normalizeFieldKey(slot.audited.note.pk);
        if (!pk) continue;
        ensureDot(pk, index, ledger)[bucket] += parseFieldAmount(slot.audited.note.amount);
      }
      continue;
    }

    // See buildPkGraph.
    const inputPks = [...new Set(
      allInputs.map((slot) => normalizeFieldKey(slot.audited.note.pk)).filter(Boolean),
    )];

    for (const slot of outputs) {
      const toPk = normalizeFieldKey(slot.audited.note.pk);
      if (!toPk || inputPks.includes(toPk)) continue; // change, not a transfer
      const amount = parseFieldAmount(slot.audited.note.amount);

      for (const fromPk of inputPks) {
        ensureDot(fromPk, index, ledger).transferOut += amount;
        ensureDot(toPk, index, ledger).transferIn += amount;
        flows.push({ txIndex: index, ledger, fromPk, toPk, amount });
      }
    }

    // A withdraw tx can still transfer part of its input to someone else.
    if (effectiveKind === 'withdraw') {
      for (const [pk, amount] of withdrawnByPk(allInputs, allOutputs, filters)) {
        ensureDot(pk, index, ledger).withdrawn += amount;
      }
    }
  }

  return { dots: [...dots.values()], flows };
}

/** Same idea as filterPkGraphByPk, for the timeline's per-occurrence dots/flows. */
function filterPkTimelineByPk(dots, flows, pkTerms) {
  if (!pkTerms) return { dots, flows };

  const allPks = new Set(dots.map((d) => d.pk));
  const matched = new Set([...allPks].filter((pk) => pkMatchesTerms(pk, pkTerms)));
  const keptFlows = flows.filter((f) => matched.has(f.fromPk) || matched.has(f.toPk));

  const visible = new Set(matched);
  for (const f of keptFlows) {
    visible.add(f.fromPk);
    visible.add(f.toPk);
  }

  return { dots: dots.filter((d) => visible.has(d.pk)), flows: keptFlows };
}

function txLabel(txIndex, ledger) {
  return txIndex == null ? '—' : `tx ${txIndex} · ledger ${ledger}`;
}

function renderNoteTable(rows, filters) {
  const notes = collectNotes(rows).filter((note) => noteMatchesAmountAndPk(note.audited, filters));
  const headers = ['Created', 'PK', 'Amount', 'Commitment', 'Status', 'Spent', 'Nullifier'];
  const wrap = el('div', 'overflow-x-auto rounded-2xl border border-white/8 bg-ink-900/70');
  const grid = el('div', 'grid gap-px bg-white/6 text-[11px]');
  grid.style.gridTemplateColumns = headers.map((header) => `${columnWidth(header)}fr`).join(' ');

  for (const header of headers) {
    grid.appendChild(el(
      'div',
      'bg-ink-950/90 px-3 py-2 font-medium uppercase tracking-wide text-slate-500',
      header,
    ));
  }

  for (const note of notes) {
    const cells = noteCells(note.audited);
    const spent = note.spentTxIndex != null;
    for (const value of [
      txLabel(note.createdTxIndex, note.createdLedger),
      cells.pk,
      cells.amount,
      note.commitment ? truncateHex(note.commitment) : '—',
      spent ? 'Spent' : 'Unspent',
      txLabel(note.spentTxIndex, note.spentLedger),
      note.nullifier ? truncateHex(note.nullifier) : '—',
    ]) {
      appendGridCell(grid, value, note.noteId);
    }
  }

  wrap.appendChild(grid);
  resultsEl.appendChild(wrap);
}

function noteSortKey(note) {
  return note.createdLedger ?? note.spentLedger ?? 0;
}

/** Counts notes per tx index (by the given note key, 'createdTxIndex' or 'spentTxIndex'). */
/** Counts total notes touched per tx index — both its outputs and the inputs it consumed. */
function txMemberCounts(notes) {
  const counts = new Map();
  const bump = (txIndex) => {
    if (txIndex == null) return;
    counts.set(txIndex, (counts.get(txIndex) ?? 0) + 1);
  };
  for (const note of notes) {
    bump(note.createdTxIndex);
    bump(note.spentTxIndex);
  }
  return counts;
}

function colorForPk(pk) {
  if (!pk) return '#64748b';
  let hash = 2166136261;
  for (let i = 0; i < pk.length; i += 1) {
    hash ^= pk.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  // Golden-angle step spreads hashes that land close together far apart in hue.
  const hue = ((hash >>> 0) * 137.508) % 360;
  return `hsl(${hue} 70% 60%)`;
}

function colorForNote(note) {
  return colorForPk(normalizeFieldKey(note.audited?.note?.pk));
}

/** Circle for transfer/unknown; rounded triangle (up = withdraw, down = deposit) otherwise. Same shape/style as the Account graph. */
function noteMarkPath(kind, r) {
  if (kind === 'withdraw' || kind === 'deposit') return roundedTrianglePath(r * 1.35, r * 0.6);
  return symbol().type(symbolCircle).size(Math.PI * r * r)();
}

/** Legend swatch matching the actual rounded-triangle node shape (see roundedTrianglePath/noteMarkPath). */
function roundedTriangleLegendIcon(fillClass, pointDown) {
  const outerR = 6;
  const wrap = el('span', 'inline-block h-3 w-3 shrink-0');
  select(wrap).append('svg')
    .attr('viewBox', `${-outerR - 1} ${-outerR - 1} ${2 * (outerR + 1)} ${2 * (outerR + 1)}`)
    .attr('width', 12)
    .attr('height', 12)
    .style('display', 'block')
    .append('path')
    .attr('d', roundedTrianglePath(outerR, outerR * (0.6 / 1.35)))
    .attr('transform', pointDown ? 'rotate(180)' : null)
    .attr('class', fillClass);
  return wrap;
}

function cellDisplay(value) {
  if (value && typeof value === 'object' && 'display' in value) return value.display;
  return value ?? '—';
}

/** Greedily packs notes into the fewest vertical lanes with no horizontal overlap, in x order. */
function assignGraphLanes(notes, xScale, minGapPx) {
  const laneEnds = [];
  const laneOf = new Map();

  for (const note of notes) {
    const xStart = xScale(note.createdLedger ?? note.spentLedger);
    const xEnd = xScale(note.spentLedger ?? note.createdLedger);
    let lane = laneEnds.findIndex((end) => xStart >= end + minGapPx);
    if (lane === -1) {
      lane = laneEnds.length;
      laneEnds.push(xEnd);
    } else {
      laneEnds[lane] = xEnd;
    }
    laneOf.set(note.noteId, lane);
  }

  return laneOf;
}

function selectGraphNote(noteId) {
  state.selectedNoteId = state.selectedNoteId === noteId ? null : noteId;
  renderResults();
}

async function applyGraphBrushRange(fromLedger, toLedger) {
  if (filterLedgerFromEl) filterLedgerFromEl.value = String(fromLedger);
  if (filterLedgerToEl) filterLedgerToEl.value = String(toLedger);
  state.filteredVisibleCount = BATCH_SIZE;
  applyFiltersAndRender();

  try {
    const bounds = await fetchLedgerTimeBounds();
    if (filterTimeFromEl) filterTimeFromEl.value = formatUtcDatetimeLocal(timeForLedger(bounds, fromLedger));
    if (filterTimeToEl) filterTimeToEl.value = formatUtcDatetimeLocal(timeForLedger(bounds, toLedger));
    await updateTimeFilterLedgers();
  } catch {
    // Timestamp fields are best-effort; the ledger filter above already applied.
  }
}

function moveGraphSelection(delta) {
  const notes = state.graphNotes ?? [];
  if (notes.length === 0) return;

  const currentIndex = notes.findIndex((note) => note.noteId === state.selectedNoteId);
  const nextIndex = currentIndex === -1 ? 0 : Math.min(notes.length - 1, Math.max(0, currentIndex + delta));
  state.selectedNoteId = notes[nextIndex].noteId;
  renderResults();
}

function renderGraphDetailPanel(container, notes) {
  const panel = el('div', 'flex w-64 shrink-0 flex-col rounded-2xl border border-white/8 bg-ink-900/70 p-4 text-xs');
  const note = notes.find((n) => n.noteId === state.selectedNoteId);

  if (!note) {
    panel.appendChild(el('p', 'text-slate-500', 'Click a note in the graph to inspect it. Use ← → to step through notes.'));
    container.appendChild(panel);
    return;
  }

  const rows = el('div', 'space-y-3');
  panel.appendChild(rows);

  const cells = noteCells(note.audited);
  const spent = note.spentTxIndex != null;

  const addRow = (label, value, valueClass = 'break-all') => {
    const row = el('div');
    row.appendChild(el('div', 'text-[10px] uppercase tracking-wide text-slate-500', label));
    row.appendChild(el('div', `font-mono text-slate-200 ${valueClass}`, value));
    rows.appendChild(row);
  };

  const addTxRow = (label, txIndex, ledger, kind) => {
    const row = el('div');
    row.appendChild(el('div', 'text-[10px] uppercase tracking-wide text-slate-500', kind ? `${label} (${kind})` : label));
    row.appendChild(el('div', 'font-mono text-slate-200 break-words', txLabel(txIndex, ledger)));
    rows.appendChild(row);
  };

  addRow('PK', cellDisplay(cells.pk));
  addRow('Amount', cellDisplay(cells.amount));
  addRow('Status', spent ? 'Spent' : 'Unspent');
  addRow('Commitment', note.commitment ? cellDisplay(truncateHex(note.commitment)) : '—');
  addTxRow('Created', note.createdTxIndex, note.createdLedger, note.createdKind);
  addTxRow('Spent', note.spentTxIndex, note.spentLedger, note.spentKind);
  addRow('Nullifier', note.nullifier ? cellDisplay(truncateHex(note.nullifier)) : '—');

  const nav = el('div', 'mt-auto flex items-center justify-between gap-2 pt-4');
  const prevBtn = el('button', 'rounded-full border border-white/10 px-3 py-1 text-[11px] text-slate-300 transition hover:border-cyan-300/30 hover:text-cyan-100', '← Prev');
  prevBtn.type = 'button';
  prevBtn.addEventListener('click', () => moveGraphSelection(-1));
  const nextBtn = el('button', 'rounded-full border border-white/10 px-3 py-1 text-[11px] text-slate-300 transition hover:border-cyan-300/30 hover:text-cyan-100', 'Next →');
  nextBtn.type = 'button';
  nextBtn.addEventListener('click', () => moveGraphSelection(1));
  nav.appendChild(prevBtn);
  nav.appendChild(nextBtn);
  panel.appendChild(nav);

  container.appendChild(panel);
}

/** Timeline scatter: x = ledger. Traceable notes get a creation→spend segment; view-only notes are lone points. */
// Detail panel (w-64 + gap-4) plus graphWrap's own p-4 padding and border.
const GRAPH_SIDE_PANEL_ALLOWANCE = 256 + 16 + 32 + 2;
// Shared baseline so the Note graph and Account graph panels don't visibly resize when switching between tabs.
const GRAPH_PANEL_MIN_HEIGHT = 360;
// Fixed height for the Account graph row, so the detail panel scrolls internally instead of growing it.
const PK_GRAPH_PANEL_HEIGHT = GRAPH_PANEL_MIN_HEIGHT + 32 + 5;

function renderGraphLegend() {
  const wrap = el('div', 'group absolute right-3 top-3 z-10');

  const badge = el(
    'div',
    'flex h-6 w-6 cursor-help select-none items-center justify-center rounded-full border border-white/15 bg-ink-950/85 text-[11px] font-semibold text-slate-300',
    'i',
  );
  wrap.appendChild(badge);

  const legend = el(
    'div',
    'pointer-events-none absolute right-0 top-7 hidden w-56 space-y-1.5 rounded-xl border border-white/10 bg-ink-950/95 px-3 py-2 text-[10px] leading-tight text-slate-300 backdrop-blur group-hover:block',
  );
  wrap.appendChild(legend);

  const addItem = (swatch, text) => {
    const row = el('div', 'flex items-center gap-2');
    row.appendChild(swatch);
    row.appendChild(el('span', '', text));
    legend.appendChild(row);
  };

  const dot = (extra) => el('span', `inline-block h-2.5 w-2.5 shrink-0 rounded-full ${extra}`);
  const square = (extra) => el('span', `inline-block h-2.5 w-2.5 shrink-0 rounded-[2px] border border-slate-300 ${extra}`);
  const line = () => el('span', 'inline-block h-px w-2.5 shrink-0 bg-cyan-400/70');

  addItem(dot('bg-cyan-400'), 'Color = note owner (PK)');
  addItem(dot('bg-cyan-400'), 'Note (creation, or only known position)');
  addItem(dot('border border-cyan-400 bg-ink-950'), 'Spend position');
  addItem(roundedTriangleLegendIcon('fill-rose-400', false), 'Triangle up: withdraw');
  addItem(roundedTriangleLegendIcon('fill-emerald-400', true), 'Triangle down: deposit');
  addItem(line(), 'Held between creation & spend');
  addItem(square(''), 'Tx output (created here)');
  addItem(square('rotate-45'), 'Tx input (spent here)');

  return wrap;
}

function renderGraph(rows, containerWidth, filters) {
  const notes = collectNotes(rows)
    .filter((note) => noteMatchesAmountAndPk(note.audited, filters))
    .sort((a, b) => noteSortKey(a) - noteSortKey(b));
  state.graphNotes = notes;

  if (state.selectedNoteId && !notes.some((n) => n.noteId === state.selectedNoteId)) {
    state.selectedNoteId = null;
  }

  const outer = el('div', 'flex items-stretch gap-4');
  const graphWrap = el('div', 'relative min-w-0 flex-1 overflow-x-auto rounded-2xl border border-white/8 bg-ink-900/70 p-4');
  outer.appendChild(graphWrap);
  resultsEl.appendChild(outer);

  if (notes.length === 0) {
    graphWrap.appendChild(el('p', 'text-sm text-slate-500', 'No notes to plot.'));
    renderGraphDetailPanel(outer, notes);
    return;
  }

  graphWrap.appendChild(renderGraphLegend());

  const { minLedger, maxLedger } = notes.reduce((acc, note) => {
    for (const ledger of [note.createdLedger, note.spentLedger]) {
      if (ledger == null) continue;
      if (ledger < acc.minLedger) acc.minLedger = ledger;
      if (ledger > acc.maxLedger) acc.maxLedger = ledger;
    }
    return acc;
  }, { minLedger: Infinity, maxLedger: -Infinity });
  const width = Math.max(640, (containerWidth || 0) - GRAPH_SIDE_PANEL_ALLOWANCE);
  const padding = 32;
  const rowHeight = 22;
  const topPad = 16;
  const bottomAxis = 28;

  const xScale = scaleLinear()
    .domain([minLedger, maxLedger === minLedger ? maxLedger + 1 : maxLedger])
    .range([padding, width - padding])
    .nice();

  const laneOf = assignGraphLanes(notes, xScale, rowHeight);
  const laneCount = Math.max(...laneOf.values()) + 1;
  const contentHeight = laneCount * rowHeight;
  const height = Math.max(GRAPH_PANEL_MIN_HEIGHT, topPad + contentHeight + bottomAxis);

  // Center the plotted lanes vertically within the (possibly taller) canvas,
  // rather than always packing them against the top.
  const plotAreaHeight = height - bottomAxis - topPad;
  const yOffset = topPad + Math.max(0, (plotAreaHeight - contentHeight) / 2);
  const yFor = (note) => yOffset + laneOf.get(note.noteId) * rowHeight + rowHeight / 2;

  const svg = select(graphWrap).append('svg')
    .attr('width', width)
    .attr('height', height)
    .attr('viewBox', `0 0 ${width} ${height}`);

  svg.append('g')
    .attr('transform', `translate(0, ${height - bottomAxis})`)
    .call(axisBottom(xScale).ticks(Math.min(10, maxLedger - minLedger + 1)).tickFormat(format('d')))
    .call((g) => g.select('.domain').attr('stroke', 'rgba(255,255,255,0.15)'))
    .call((g) => g.selectAll('line').attr('stroke', 'rgba(255,255,255,0.15)'))
    .call((g) => g.selectAll('text').attr('fill', '#94a3b8').attr('font-size', 10));

  // Behind the marks (dots keep their own click handler where they overlap
  // the brush's hit area) so drag-to-zoom and click-to-select coexist.
  const brush = brushX()
    .extent([[padding, topPad], [width - padding, height - bottomAxis]])
    .on('end', (event) => {
      if (!event.selection) return;
      const [x0, x1] = event.selection;
      if (x1 - x0 < 4) {
        brushGroup.call(brush.move, null);
        return;
      }
      const fromLedger = Math.round(xScale.invert(x0));
      const toLedger = Math.round(xScale.invert(x1));
      applyGraphBrushRange(Math.min(fromLedger, toLedger), Math.max(fromLedger, toLedger));
    });
  const brushGroup = svg.append('g').attr('class', 'gvk-graph-brush').call(brush);

  const spentNotes = notes.filter((note) => note.createdTxIndex != null && note.spentTxIndex != null);

  svg.append('g')
    .selectAll('line')
    .data(spentNotes)
    .join('line')
    .attr('data-gvk-pk', (d) => normalizeFieldKey(d.audited?.note?.pk))
    .attr('data-gvk-note-id', (d) => d.noteId)
    .attr('x1', (d) => xScale(d.createdLedger))
    .attr('x2', (d) => xScale(d.spentLedger))
    .attr('y1', yFor)
    .attr('y2', yFor)
    .attr('stroke', colorForNote)
    .attr('stroke-width', 1.5)
    .attr('opacity', 0.45);

  // Primary dot: this is the note's creation marker when its creation is
  // known, so it's tagged for the created-tx group only. For an orphan note
  // (creation not in the visible set), this dot sits at the spend position
  // instead, so it's tagged for the spent-tx group instead — never both, so
  // hovering one marker can't pull in a *different* transaction's squares
  // from a different ledger.
  const primaryKind = (d) => (d.createdTxIndex != null ? d.createdKind : d.spentKind);
  const primaryRadius = (d) => (d.noteId === state.selectedNoteId ? 8 : 6);

  svg.append('g')
    .selectAll('path')
    .data(notes)
    .join('path')
    .attr('data-gvk-pk', (d) => normalizeFieldKey(d.audited?.note?.pk))
    .attr('data-gvk-note-id', (d) => d.noteId)
    .attr('data-gvk-tx-created', (d) => (d.createdTxIndex != null ? d.createdTxIndex : null))
    .attr('data-gvk-tx-spent', (d) => (d.createdTxIndex == null && d.spentTxIndex != null ? d.spentTxIndex : null))
    .attr('transform', (d) => {
      const rotate = primaryKind(d) === 'deposit' ? ' rotate(180)' : '';
      return `translate(${xScale(d.createdLedger ?? d.spentLedger)}, ${yFor(d)})${rotate}`;
    })
    .attr('d', (d) => noteMarkPath(primaryKind(d), primaryRadius(d)))
    .attr('fill', colorForNote)
    .attr('stroke', (d) => (d.noteId === state.selectedNoteId ? '#e0f2fe' : '#0b1220'))
    .attr('stroke-width', (d) => (d.noteId === state.selectedNoteId ? 2 : 1))
    .style('cursor', 'pointer')
    .on('click', (_event, d) => selectGraphNote(d.noteId));

  // Secondary (spend) dot only ever represents the spend event at the spend
  // ledger, so it's tagged for the spent-tx group only.
  svg.append('g')
    .selectAll('path')
    .data(spentNotes)
    .join('path')
    .attr('data-gvk-pk', (d) => normalizeFieldKey(d.audited?.note?.pk))
    .attr('data-gvk-note-id', (d) => d.noteId)
    .attr('data-gvk-tx-spent', (d) => d.spentTxIndex)
    .attr('transform', (d) => {
      const rotate = d.spentKind === 'deposit' ? ' rotate(180)' : '';
      return `translate(${xScale(d.spentLedger)}, ${yFor(d)})${rotate}`;
    })
    .attr('d', (d) => noteMarkPath(d.spentKind, 5))
    .attr('fill', '#0b1220')
    .attr('stroke', colorForNote)
    .attr('stroke-width', 1.5)
    .style('cursor', 'pointer')
    .on('click', (_event, d) => selectGraphNote(d.noteId));

  // Marker around each note touched by a tx that touches more than one
  // visible note in total — a square for its outputs, a diamond (the same
  // square, rotated) for the inputs it consumed. Purely decorative
  // (pointer-events:none) — it never intercepts hover/click itself, so it
  // can't shadow the pk/note highlighting on the dots above. It's shown
  // persistently for the tx of the currently selected note, and toggled on
  // for whatever's hovered by syncTxSquaresForElement (see bindResultHighlights).
  const selectedNote = notes.find((n) => n.noteId === state.selectedNoteId);
  const selectedTxIndex = selectedNote?.createdTxIndex ?? selectedNote?.spentTxIndex ?? null;
  const txCounts = txMemberCounts(notes);
  const createdGrouped = notes.filter((n) => n.createdTxIndex != null && txCounts.get(n.createdTxIndex) > 1);
  const spentGrouped = notes.filter((n) => n.spentTxIndex != null && txCounts.get(n.spentTxIndex) > 1);
  const squareSize = 14;

  svg.append('g')
    .selectAll('rect')
    .data(createdGrouped)
    .join('rect')
    .attr('data-gvk-tx-created', (d) => d.createdTxIndex)
    .attr('x', (d) => xScale(d.createdLedger) - squareSize / 2)
    .attr('y', (d) => yFor(d) - squareSize / 2)
    .attr('width', squareSize)
    .attr('height', squareSize)
    .attr('rx', 3)
    .attr('fill', 'transparent')
    .attr('stroke', 'rgba(226,232,240,0.6)')
    .attr('stroke-width', 1)
    .style('pointer-events', 'none')
    .style('opacity', (d) => (selectedTxIndex != null && d.createdTxIndex === selectedTxIndex ? 1 : 0));

  svg.append('g')
    .selectAll('rect')
    .data(spentGrouped)
    .join('rect')
    .attr('data-gvk-tx-spent', (d) => d.spentTxIndex)
    .attr('x', (d) => xScale(d.spentLedger) - squareSize / 2)
    .attr('y', (d) => yFor(d) - squareSize / 2)
    .attr('width', squareSize)
    .attr('height', squareSize)
    .attr('rx', 3)
    .attr('transform', (d) => `rotate(45, ${xScale(d.spentLedger)}, ${yFor(d)})`)
    .attr('fill', 'transparent')
    .attr('stroke', 'rgba(226,232,240,0.6)')
    .attr('stroke-width', 1)
    .style('pointer-events', 'none')
    .style('opacity', (d) => (selectedTxIndex != null && d.spentTxIndex === selectedTxIndex ? 1 : 0));

  renderGraphDetailPanel(outer, notes);
}

function pkGraphNeighborEdges(pk, edges) {
  return edges.filter((edge) => edge.from === pk || edge.to === pk);
}

function selectPkGraphNode(pk) {
  state.selectedFlow = null;
  state.selectedDot = null;
  state.selectedPk = state.selectedPk === pk ? null : pk;
  renderResults();
}

function sameFlow(a, b) {
  return !!a && !!b && a.txIndex === b.txIndex && a.fromPk === b.fromPk && a.toPk === b.toPk;
}

function selectPkGraphFlow(flow) {
  state.selectedPk = null;
  state.selectedDot = null;
  state.selectedFlow = sameFlow(state.selectedFlow, flow) ? null : flow;
  renderResults();
}

function sameDot(a, b) {
  return !!a && !!b && a.pk === b.pk && a.txIndex === b.txIndex;
}

/** Selecting a dot also selects its PK, so the panel shows both the one-off event and the PK's running totals. */
function selectPkGraphDot(dot) {
  state.selectedFlow = null;
  const same = sameDot(state.selectedDot, dot);
  state.selectedDot = same ? null : { pk: dot.pk, txIndex: dot.txIndex };
  state.selectedPk = same ? null : dot.pk;
  renderResults();
}

function movePkGraphSelection(delta) {
  const nodes = state.pkGraphNodes ?? [];
  if (nodes.length === 0) return;

  state.selectedFlow = null;
  state.selectedDot = null;
  const currentIndex = nodes.findIndex((node) => node.pk === state.selectedPk);
  const nextIndex = currentIndex === -1 ? 0 : Math.min(nodes.length - 1, Math.max(0, currentIndex + delta));
  state.selectedPk = nodes[nextIndex].pk;
  renderResults();
}

function renderPkGraphLegend() {
  const wrap = el('div', 'group absolute right-3 top-3 z-10');

  const badge = el(
    'div',
    'flex h-6 w-6 cursor-help select-none items-center justify-center rounded-full border border-white/15 bg-ink-950/85 text-[11px] font-semibold text-slate-300',
    'i',
  );
  wrap.appendChild(badge);

  const legend = el(
    'div',
    'pointer-events-none absolute right-0 top-7 hidden w-64 space-y-1.5 rounded-xl border border-white/10 bg-ink-950/95 px-3 py-2 text-[10px] leading-tight text-slate-300 backdrop-blur group-hover:block',
  );
  wrap.appendChild(legend);

  const addItem = (swatch, text) => {
    const row = el('div', 'flex items-center gap-2');
    row.appendChild(swatch);
    row.appendChild(el('span', '', text));
    legend.appendChild(row);
  };

  const dot = (extra) => el('span', `inline-block h-2.5 w-2.5 shrink-0 rounded-full ${extra}`);
  const bar = (extra) => el('span', `inline-block h-1.5 w-3.5 shrink-0 rounded-sm ${extra}`);
  const line = (extra) => el('span', `inline-block h-2.5 w-0.5 shrink-0 ${extra}`);
  const triangle = roundedTriangleLegendIcon;

  addItem(bar('bg-white/15'), 'Row: a public key (PK); x-axis: ledger (time)');

  if (state.poolGvkMode === 'traceable') {
    addItem(line('bg-cyan-400/70'), 'Vertical arrow: transfer');
    addItem(dot('border border-cyan-400 bg-ink-950'), 'Circle: a transfer with that PK');
    addItem(triangle('fill-rose-400', false), 'Triangle up: withdraw');
    addItem(triangle('fill-emerald-400', true), 'Triangle down: deposit');
  } else {
    addItem(dot('border border-cyan-400 bg-ink-950'), 'Circle: a note received by that PK');
    legend.appendChild(el('div', 'text-slate-500', 'View-only pool: spends and counterparties are not decryptable, so note origins are unknown and no transfers are drawn.'));
  }

  return wrap;
}

function pkGraphDetailAmountRow(label, amount, count) {
  const row = el('div');
  row.appendChild(el('div', 'text-[10px] uppercase tracking-wide text-slate-500', label));
  row.appendChild(el(
    'div',
    'font-mono text-slate-200',
    `${formatTokenAmount(amount)} · ${count} note(s)`,
  ));
  return row;
}

function pkGraphDetailPkRow(label, pk) {
  const row = el('div');
  row.appendChild(el('div', 'text-[10px] uppercase tracking-wide text-slate-500', label));
  const value = el('div', 'cursor-pointer font-mono text-slate-200 break-all hover:!text-white', pk);
  value.title = `${pk} (click to copy)`;
  value.addEventListener('click', () => copyToClipboard(value, pk));
  row.appendChild(value);
  return row;
}

/** Net of every deposit/withdraw/transfer seen for this PK across the loaded audit — i.e. now, not at any one point in its history. */
function pkGraphNodeBalance(node) {
  return node.deposited + node.transferIn - node.withdrawn - node.transferOut;
}

/** A real balance needs spends, which only traceable pools expose; view-only can only total what came in. */
function pkGraphDetailBalanceRow(node) {
  const traceable = state.poolGvkMode === 'traceable';
  const row = el('div');
  row.appendChild(el(
    'div',
    'text-[10px] uppercase tracking-wide text-slate-500',
    traceable ? 'Current balance' : 'Total received',
  ));
  row.appendChild(el(
    'div',
    'font-mono text-sm text-white',
    formatTokenAmount(traceable ? pkGraphNodeBalance(node) : node.received + node.deposited + node.transferIn),
  ));
  return row;
}

/** The one event that was clicked — its own amount(s), not the PK's running total. */
function pkGraphDetailSelectedDotRow(dot) {
  const row = el('div', 'rounded-lg border border-white/10 bg-ink-950/60 p-2 space-y-1');

  if (dot.deposited > 0n) {
    row.appendChild(el('div', 'text-[10px] uppercase tracking-wide text-emerald-400', 'This deposit'));
    row.appendChild(el('div', 'font-mono text-slate-200', formatTokenAmount(dot.deposited)));
  } else if (dot.withdrawn > 0n) {
    row.appendChild(el('div', 'text-[10px] uppercase tracking-wide text-rose-400', 'This withdrawal'));
    row.appendChild(el('div', 'font-mono text-slate-200', formatTokenAmount(dot.withdrawn)));
  } else if (dot.received > 0n) {
    row.appendChild(el('div', 'text-[10px] uppercase tracking-wide text-slate-400', 'This note'));
    row.appendChild(el('div', 'font-mono text-slate-200', formatTokenAmount(dot.received)));
    row.appendChild(el('div', 'text-[10px] text-slate-500', 'Origin unknown — view-only pool'));
  } else if (dot.transferIn > 0n || dot.transferOut > 0n) {
    row.appendChild(el('div', 'text-[10px] uppercase tracking-wide text-cyan-400', 'This transfer'));
    if (dot.transferIn > 0n) row.appendChild(el('div', 'font-mono text-slate-200', `Received ${formatTokenAmount(dot.transferIn)}`));
    if (dot.transferOut > 0n) row.appendChild(el('div', 'font-mono text-slate-200', `Sent ${formatTokenAmount(dot.transferOut)}`));
  } else {
    row.appendChild(el('div', 'text-[10px] uppercase tracking-wide text-slate-400', 'This note'));
    row.appendChild(el('div', 'font-mono text-slate-200', formatTokenAmount(0n)));
  }

  row.appendChild(el('div', 'font-mono text-[10px] text-slate-500', `tx ${dot.txIndex} · ledger ${dot.ledger}`));
  return row;
}

function renderPkGraphFlowDetailPanel(container, flow) {
  const panel = el('div', 'flex w-64 shrink-0 flex-col rounded-2xl border border-white/8 bg-ink-900/70 p-4 text-xs');
  const rows = el('div', 'space-y-3');
  panel.appendChild(rows);

  rows.appendChild(el('div', 'text-[10px] uppercase tracking-wide text-slate-500', 'Transfer'));
  rows.appendChild(pkGraphDetailPkRow('From', flow.fromPk));
  rows.appendChild(pkGraphDetailPkRow('To', flow.toPk));
  rows.appendChild(pkGraphDetailAmountRow('Amount', flow.amount, 1));

  const txRow = el('div');
  txRow.appendChild(el('div', 'text-[10px] uppercase tracking-wide text-slate-500', 'Transaction'));
  txRow.appendChild(el('div', 'font-mono text-slate-200', `tx ${flow.txIndex} · ledger ${flow.ledger}`));
  rows.appendChild(txRow);

  const footer = el('div', 'mt-auto pt-4');
  const closeBtn = el('button', 'rounded-full border border-white/10 px-3 py-1 text-[11px] text-slate-300 transition hover:border-cyan-300/30 hover:text-cyan-100', 'Clear selection');
  closeBtn.type = 'button';
  closeBtn.addEventListener('click', () => selectPkGraphFlow(flow));
  footer.appendChild(closeBtn);
  panel.appendChild(footer);

  container.appendChild(panel);
}

function renderPkGraphDetailPanel(container, nodes, edges, selectedFlow, selectedDot, fullNodeByPk) {
  if (selectedFlow) {
    renderPkGraphFlowDetailPanel(container, selectedFlow);
    return;
  }

  const panel = el('div', 'flex w-64 shrink-0 flex-col rounded-2xl border border-white/8 bg-ink-900/70 p-4 text-xs');
  const node = nodes.find((n) => n.pk === state.selectedPk);

  if (!node) {
    panel.appendChild(el('p', 'text-slate-500', 'Click a node to inspect a PK, or an arrow to inspect a transfer. Use ← → to step through PKs.'));
    container.appendChild(panel);
    return;
  }

  const header = el('div', 'shrink-0 space-y-3');
  panel.appendChild(header);

  header.appendChild(pkGraphDetailPkRow('PK', node.pk));
  if (selectedDot) header.appendChild(pkGraphDetailSelectedDotRow(selectedDot));
  header.appendChild(pkGraphDetailBalanceRow(fullNodeByPk?.get(node.pk) ?? node));

  // Scrolls internally instead of growing the panel (see PK_GRAPH_PANEL_HEIGHT).
  const history = el('div', 'thin-scroll min-h-0 flex-1 space-y-3 overflow-y-auto pt-3');
  panel.appendChild(history);

  const activityBox = el('div', 'space-y-2 rounded-lg border border-white/10 bg-ink-950/40 p-2');
  if (node.receivedCount > 0) activityBox.appendChild(pkGraphDetailAmountRow('Received (origin unknown)', node.received, node.receivedCount));
  if (node.depositCount > 0) activityBox.appendChild(pkGraphDetailAmountRow('Deposited', node.deposited, node.depositCount));
  if (node.withdrawCount > 0) activityBox.appendChild(pkGraphDetailAmountRow('Withdrawn', node.withdrawn, node.withdrawCount));
  if (node.transferInCount > 0) activityBox.appendChild(pkGraphDetailAmountRow('Received (transfers)', node.transferIn, node.transferInCount));
  if (node.transferOutCount > 0) activityBox.appendChild(pkGraphDetailAmountRow('Sent (transfers)', node.transferOut, node.transferOutCount));
  if (activityBox.children.length > 0) history.appendChild(activityBox);

  const neighbors = pkGraphNeighborEdges(node.pk, edges);
  if (neighbors.length > 0) {
    const transfersBox = el('div', 'space-y-1 rounded-lg border border-white/10 bg-ink-950/40 p-2');
    transfersBox.appendChild(el('div', 'text-[10px] uppercase tracking-wide text-slate-500', 'Transfers'));
    const list = el('div', 'space-y-1');
    for (const edge of neighbors) {
      const outgoing = edge.from === node.pk;
      const other = outgoing ? edge.to : edge.from;
      list.appendChild(el(
        'div',
        'flex items-center justify-between gap-2 font-mono text-slate-300',
        `${outgoing ? '→' : '←'} ${truncateHex(other).display} · ${formatTokenAmount(edge.amount)} (${edge.count})`,
      ));
    }
    transfersBox.appendChild(list);
    history.appendChild(transfersBox);
  }

  const nav = el('div', 'mt-auto flex shrink-0 items-center justify-between gap-2 pt-4');
  const prevBtn = el('button', 'rounded-full border border-white/10 px-3 py-1 text-[11px] text-slate-300 transition hover:border-cyan-300/30 hover:text-cyan-100', '← Prev');
  prevBtn.type = 'button';
  prevBtn.addEventListener('click', () => movePkGraphSelection(-1));
  const nextBtn = el('button', 'rounded-full border border-white/10 px-3 py-1 text-[11px] text-slate-300 transition hover:border-cyan-300/30 hover:text-cyan-100', 'Next →');
  nextBtn.type = 'button';
  nextBtn.addEventListener('click', () => movePkGraphSelection(1));
  nav.appendChild(prevBtn);
  nav.appendChild(nextBtn);
  panel.appendChild(nav);

  container.appendChild(panel);
}

const PK_TIMELINE_LABEL_WIDTH = 108;

/** Rounds a polygon's corners in place by pulling each vertex back along its two edges and joining with a quadratic curve through the original vertex. */
function roundedPolygonPath(points, cornerRadius) {
  const n = points.length;
  const parts = [];

  for (let i = 0; i < n; i += 1) {
    const curr = points[i];
    const prev = points[(i - 1 + n) % n];
    const next = points[(i + 1) % n];

    const toPrevLen = Math.hypot(prev.x - curr.x, prev.y - curr.y) || 1;
    const toNextLen = Math.hypot(next.x - curr.x, next.y - curr.y) || 1;
    const r = Math.min(cornerRadius, toPrevLen / 2, toNextLen / 2);

    const p1 = { x: curr.x + ((prev.x - curr.x) / toPrevLen) * r, y: curr.y + ((prev.y - curr.y) / toPrevLen) * r };
    const p2 = { x: curr.x + ((next.x - curr.x) / toNextLen) * r, y: curr.y + ((next.y - curr.y) / toNextLen) * r };

    parts.push(i === 0 ? `M ${p1.x} ${p1.y}` : `L ${p1.x} ${p1.y}`);
    parts.push(`Q ${curr.x} ${curr.y} ${p2.x} ${p2.y}`);
  }

  parts.push('Z');
  return parts.join(' ');
}

function roundedTrianglePath(radius, cornerRadius) {
  const angles = [-Math.PI / 2, -Math.PI / 2 + (2 * Math.PI) / 3, -Math.PI / 2 + (4 * Math.PI) / 3];
  const points = angles.map((a) => ({ x: radius * Math.cos(a), y: radius * Math.sin(a) }));
  return roundedPolygonPath(points, cornerRadius);
}

/**
 * Swimlane timeline: x = ledger, one lane per PK. A transfer's two dots
 * (sender's lane, receiver's lane) always share the transfer's ledger, so
 * the connecting arrow is always a straight vertical line at that x.
 * Deposits/withdraws only ever mark their own PK's dot — never an arrow.
 */
function renderPkGraph(rows, containerWidth, filters) {
  const builtGraph = buildPkGraph(rows, filters);
  const builtTimeline = buildPkTimelineEvents(rows, filters);
  const { nodes, edges } = filterPkGraphByPk(builtGraph.nodes, builtGraph.edges, filters.pk);
  const { dots, flows } = filterPkTimelineByPk(builtTimeline.dots, builtTimeline.flows, filters.pk);
  const nodeByPk = new Map(nodes.map((n) => [n.pk, n]));

  // Current balance ignores active filters — always the full loaded audit.
  const fullNodeByPk = new Map(fullPkGraph().nodes.map((n) => [n.pk, n]));

  // Chronological (by first appearance) so the lane order reads like a story,
  // stable by PK so the layout doesn't jitter on re-render.
  const firstLedgerOf = new Map();
  for (const dot of dots) {
    const seen = firstLedgerOf.get(dot.pk);
    if (seen == null || dot.ledger < seen) firstLedgerOf.set(dot.pk, dot.ledger);
  }
  const orderedPks = [...firstLedgerOf.keys()].sort((a, b) => {
    const diff = firstLedgerOf.get(a) - firstLedgerOf.get(b);
    return diff !== 0 ? diff : a.localeCompare(b);
  });
  state.pkGraphNodes = orderedPks.map((pk) => nodeByPk.get(pk)).filter(Boolean);

  if (state.selectedPk && !orderedPks.includes(state.selectedPk)) {
    state.selectedPk = null;
  }
  const selectedFlow = flows.find((f) => sameFlow(state.selectedFlow, f)) ?? null;
  state.selectedFlow = selectedFlow;
  const selectedDot = state.selectedDot
    ? dots.find((d) => d.pk === state.selectedDot.pk && d.txIndex === state.selectedDot.txIndex) ?? null
    : null;
  state.selectedDot = selectedDot ? { pk: selectedDot.pk, txIndex: selectedDot.txIndex } : null;

  const outer = el('div', 'flex items-stretch gap-4');
  // Fixed height so the detail panel's history scrolls internally instead of growing this row.
  outer.style.height = `${PK_GRAPH_PANEL_HEIGHT}px`;
  const graphWrap = el('div', 'relative flex min-w-0 flex-1 flex-col rounded-2xl border border-white/8 bg-ink-900/70 p-4');
  outer.appendChild(graphWrap);
  resultsEl.appendChild(outer);

  if (orderedPks.length === 0) {
    graphWrap.appendChild(el('p', 'text-sm text-slate-500', 'No public keys to plot.'));
    renderPkGraphDetailPanel(outer, nodes, edges, selectedFlow, selectedDot, fullNodeByPk);
    return;
  }

  graphWrap.appendChild(renderPkGraphLegend());

  const { minLedger, maxLedger } = dots.reduce((acc, dot) => {
    if (dot.ledger < acc.minLedger) acc.minLedger = dot.ledger;
    if (dot.ledger > acc.maxLedger) acc.maxLedger = dot.ledger;
    return acc;
  }, { minLedger: Infinity, maxLedger: -Infinity });

  const width = Math.max(640, (containerWidth || 0) - GRAPH_SIDE_PANEL_ALLOWANCE);
  const plotWidth = Math.max(400, width - PK_TIMELINE_LABEL_WIDTH);
  const padding = 24;
  const rowHeight = 34;
  const topPad = 16;
  const axisHeight = 28;
  const LANES_VIEWPORT_MAX_HEIGHT = GRAPH_PANEL_MIN_HEIGHT - axisHeight;
  const lanesContentHeight = topPad + orderedPks.length * rowHeight;
  const lanesNeedScroll = lanesContentHeight > LANES_VIEWPORT_MAX_HEIGHT;
  const laneAreaHeight = Math.max(LANES_VIEWPORT_MAX_HEIGHT, lanesContentHeight);

  const xScale = scaleLinear()
    .domain([minLedger, maxLedger === minLedger ? maxLedger + 1 : maxLedger])
    .range([padding, plotWidth - padding])
    .nice();

  const laneIndexOf = new Map(orderedPks.map((pk, i) => [pk, i]));
  const yFor = (pk) => topPad + laneIndexOf.get(pk) * rowHeight + rowHeight / 2;

  const DOT_RADIUS = 6;
  const FLOW_STROKE_WIDTH = 2.5;
  const FLOW_HEAD_LENGTH = 9;
  const FLOW_HEAD_HALF_WIDTH = 5;

  const laneStripeFill = (pk) => (pk === state.selectedPk
    ? 'rgba(34,211,238,0.08)'
    : laneIndexOf.get(pk) % 2 === 0 ? 'rgba(255,255,255,0.02)' : 'transparent');

  // Label column stays fixed (frozen first column); horizontal scroll is
  // driven by the axis strip below (always visible, unlike a scrollbar on
  // the plot itself), and the plot mirrors it via a transform + wheel forwarding.
  // overflow-y-auto only when content genuinely exceeds the baseline —
  // otherwise laneAreaHeight is padded to match it exactly (see above), and
  // relying on that pixel-for-pixel match with maxHeight to suppress the
  // scrollbar is too fragile (subpixel layout rounding can still trigger it).
  const lanesScrollEl = el('div', lanesNeedScroll ? 'thin-scroll overflow-y-auto overflow-x-hidden rounded-lg' : 'overflow-hidden rounded-lg');
  lanesScrollEl.style.height = `${LANES_VIEWPORT_MAX_HEIGHT}px`;
  graphWrap.appendChild(lanesScrollEl);

  const lanesRow = el('div', 'flex');
  lanesScrollEl.appendChild(lanesRow);

  const labelsCol = el('div', 'shrink-0');
  lanesRow.appendChild(labelsCol);

  const plotScrollX = el('div', 'min-w-0 flex-1 overflow-hidden');
  lanesRow.appendChild(plotScrollX);

  const axisRow = el('div', 'flex shrink-0 border-t border-white/8 pt-1');
  graphWrap.appendChild(axisRow);

  const axisSpacer = el('div', 'shrink-0');
  axisSpacer.style.width = `${PK_TIMELINE_LABEL_WIDTH}px`;
  axisRow.appendChild(axisSpacer);

  const axisScrollX = el('div', 'thin-scroll min-w-0 flex-1 overflow-x-auto overflow-y-hidden');
  axisRow.appendChild(axisScrollX);

  const axisSvgEl = select(axisScrollX).append('svg')
    .attr('width', plotWidth)
    .attr('height', axisHeight)
    .style('display', 'block');
  axisSvgEl.append('g')
    .attr('transform', 'translate(0, 1)')
    .call(axisBottom(xScale).ticks(Math.min(10, maxLedger - minLedger + 1)).tickFormat(format('d')))
    .call((g) => g.select('.domain').attr('stroke', 'rgba(255,255,255,0.15)'))
    .call((g) => g.selectAll('line').attr('stroke', 'rgba(255,255,255,0.15)'))
    .call((g) => g.selectAll('text').attr('fill', '#94a3b8').attr('font-size', 10));

  axisScrollX.addEventListener('scroll', () => {
    select(plotScrollX).select('svg').style('transform', `translateX(${-axisScrollX.scrollLeft}px)`);
  });

  plotScrollX.addEventListener('wheel', (event) => {
    if (event.deltaX === 0) return;
    axisScrollX.scrollLeft += event.deltaX;
    event.preventDefault();
  }, { passive: false });

  // Frozen label column: lane stripes + PK labels only, never scrolls horizontally.
  const labelsSvg = select(labelsCol).append('svg')
    .attr('width', PK_TIMELINE_LABEL_WIDTH)
    .attr('height', laneAreaHeight)
    .style('display', 'block');

  labelsSvg.append('g')
    .selectAll('rect')
    .data(orderedPks)
    .join('rect')
    .attr('x', 0)
    .attr('y', (pk) => topPad + laneIndexOf.get(pk) * rowHeight)
    .attr('width', PK_TIMELINE_LABEL_WIDTH)
    .attr('height', rowHeight)
    .attr('fill', laneStripeFill);

  labelsSvg.append('g')
    .selectAll('text')
    .data(orderedPks)
    .join('text')
    .attr('x', 0)
    .attr('y', (pk) => yFor(pk))
    .attr('dy', '0.32em')
    .attr('font-size', 11)
    .attr('font-family', 'monospace')
    .attr('fill', (pk) => colorForPk(pk))
    .style('cursor', 'pointer')
    .style('user-select', 'none')
    .text((pk) => shortPkLabel(pk))
    .on('click', (_event, pk) => selectPkGraphNode(pk))
    .append('title')
    .text((pk) => pk);

  const svg = select(plotScrollX).append('svg')
    .attr('width', plotWidth)
    .attr('height', laneAreaHeight)
    .attr('viewBox', `0 0 ${plotWidth} ${laneAreaHeight}`)
    .style('display', 'block');

  // Lane rows: alternating stripes for readability, selected PK's lane lit —
  // matches the label column's stripes so a lane reads as one continuous row.
  svg.append('g')
    .selectAll('rect')
    .data(orderedPks)
    .join('rect')
    .attr('x', 0)
    .attr('y', (pk) => topPad + laneIndexOf.get(pk) * rowHeight)
    .attr('width', plotWidth)
    .attr('height', rowHeight)
    .attr('fill', laneStripeFill);

  // Behind the marks (same drag-to-zoom-by-ledger-range as the Note graph),
  // so it and click-to-select coexist — marks appended after it stay on top.
  const brush = brushX()
    .extent([[padding, 0], [plotWidth - padding, laneAreaHeight]])
    .on('end', (event) => {
      if (!event.selection) return;
      const [x0, x1] = event.selection;
      if (x1 - x0 < 4) {
        brushGroup.call(brush.move, null);
        return;
      }
      const fromLedger = Math.round(xScale.invert(x0));
      const toLedger = Math.round(xScale.invert(x1));
      applyGraphBrushRange(Math.min(fromLedger, toLedger), Math.max(fromLedger, toLedger));
    });
  const brushGroup = svg.append('g').attr('class', 'gvk-pk-graph-brush').call(brush);

  // Hand-drawn shaft + triangular head (not an SVG <marker>, to avoid its scaling/orientation quirks).
  const flowGeoms = flows.map((f) => {
    const x = xScale(f.ledger);
    const fromY = yFor(f.fromPk);
    const toY = yFor(f.toPk);
    const down = toY > fromY;
    const tipY = down ? toY - DOT_RADIUS : toY + DOT_RADIUS;
    const headBaseY = down ? tipY - FLOW_HEAD_LENGTH : tipY + FLOW_HEAD_LENGTH;
    const shaftStartY = down ? fromY + (DOT_RADIUS - 1.5) : fromY - (DOT_RADIUS - 1.5);
    return { flow: f, x, shaftStartY, shaftEndY: headBaseY, tipY, headBaseY, color: colorForPk(f.fromPk) };
  });

  const isSelectedFlow = (f) => (
    state.selectedFlow?.txIndex === f.txIndex
    && state.selectedFlow?.fromPk === f.fromPk
    && state.selectedFlow?.toPk === f.toPk
  );

  const flowGroups = svg.append('g')
    .selectAll('g')
    .data(flowGeoms)
    .join('g')
    .style('cursor', 'pointer')
    .on('click', (_event, g) => selectPkGraphFlow(g.flow));

  // Wide invisible hit target under the thin visible shaft.
  flowGroups.append('line')
    .attr('x1', (g) => g.x)
    .attr('x2', (g) => g.x)
    .attr('y1', (g) => g.shaftStartY)
    .attr('y2', (g) => g.tipY)
    .attr('stroke', 'transparent')
    .attr('stroke-width', 14);

  flowGroups.append('line')
    .attr('x1', (g) => g.x)
    .attr('x2', (g) => g.x)
    .attr('y1', (g) => g.shaftStartY)
    .attr('y2', (g) => g.shaftEndY)
    .attr('stroke', (g) => g.color)
    .attr('stroke-width', (g) => (isSelectedFlow(g.flow) ? FLOW_STROKE_WIDTH + 2 : FLOW_STROKE_WIDTH))
    .attr('stroke-linecap', 'round')
    .style('filter', (g) => (isSelectedFlow(g.flow) ? 'drop-shadow(0 0 3px rgba(255,255,255,0.8))' : null));

  flowGroups.append('path')
    .attr('d', (g) => `M ${g.x - FLOW_HEAD_HALF_WIDTH} ${g.headBaseY} L ${g.x + FLOW_HEAD_HALF_WIDTH} ${g.headBaseY} L ${g.x} ${g.tipY} Z`)
    .attr('fill', (g) => g.color)
    .style('filter', (g) => (isSelectedFlow(g.flow) ? 'drop-shadow(0 0 3px rgba(255,255,255,0.8))' : null));

  flowGroups.append('title')
    .text((g) => `tx ${g.flow.txIndex} · ledger ${g.flow.ledger}\n${truncateHex(g.flow.fromPk).display} → ${truncateHex(g.flow.toPk).display}\n${formatTokenAmount(g.flow.amount)}`);

  // Circle for a transfer touch; rounded triangle up = withdraw, down = deposit.
  const circlePathD = symbol().type(symbolCircle).size(Math.PI * DOT_RADIUS * DOT_RADIUS)();
  const trianglePathD = roundedTrianglePath(DOT_RADIUS * 1.35, DOT_RADIUS * 0.6);
  const dotPathD = (d) => (d.deposited > 0n || d.withdrawn > 0n ? trianglePathD : circlePathD);

  const isSelectedDot = (d) => !!selectedDot && selectedDot.pk === d.pk && selectedDot.txIndex === d.txIndex;

  svg.append('g')
    .selectAll('path')
    .data(dots)
    .join('path')
    .attr('data-gvk-pk-node', (d) => d.pk)
    .attr('transform', (d) => {
      const rotate = d.deposited > 0n ? ' rotate(180)' : '';
      return `translate(${xScale(d.ledger)}, ${yFor(d.pk)})${rotate}`;
    })
    .attr('d', dotPathD)
    .attr('fill', (d) => colorForPk(d.pk))
    .attr('stroke', (d) => (isSelectedDot(d) || d.pk === state.selectedPk ? '#e0f2fe' : '#0b1220'))
    .attr('stroke-width', (d) => (isSelectedDot(d) ? 3 : d.pk === state.selectedPk ? 2.5 : 1))
    .style('cursor', 'pointer')
    .style('filter', (d) => (isSelectedDot(d) ? 'drop-shadow(0 0 3px rgba(255,255,255,0.8))' : null))
    .on('click', (_event, d) => selectPkGraphDot(d))
    .append('title')
    .text((d) => {
      const label = d.deposited > 0n
        ? `Deposited ${formatTokenAmount(d.deposited)}`
        : d.withdrawn > 0n
          ? `Withdrawn ${formatTokenAmount(d.withdrawn)}`
          : d.received > 0n
            ? `Received ${formatTokenAmount(d.received)} (origin unknown)`
            : null;
      return [d.pk, `tx ${d.txIndex} · ledger ${d.ledger}`, label].filter(Boolean).join('\n');
    });

  renderPkGraphDetailPanel(outer, nodes, edges, selectedFlow, selectedDot, fullNodeByPk);
}

function pushTx(tx) {
  state.txCounter += 1;
  const index = state.txCounter;
  const kind = state.poolGvkMode === 'traceable' ? classifyTx(tx) : null;
  state.rows.push({ tx, index, kind });
}

// Serializes all cursor access — a filter change can trigger a background
// drain (see ensureFullyLoaded) while a user-initiated fetch is in flight,
// and `state.audit.nextTx()` is a stateful iterator that isn't safe to call
// concurrently from two call sites.
let cursorQueue = Promise.resolve();

function queueCursorOp(fn) {
  const run = cursorQueue.then(fn, fn);
  cursorQueue = run.then(() => {}, () => {});
  return run;
}

async function fetchBatch(limit) {
  return queueCursorOp(async () => {
    let fetched = 0;
    while (fetched < limit) {
      const tx = await state.audit.nextTx();
      if (tx == null) {
        state.exhausted = true;
        break;
      }
      pushTx(tx);
      fetched += 1;
    }
    return fetched;
  });
}

let drainPromise = null;

/** Exhausts the audit cursor so filters can see the full result set, not just what's paged in so far. */
async function ensureFullyLoaded() {
  if (!state.audit || state.exhausted) return;
  if (!drainPromise) {
    drainPromise = (async () => {
      while (!state.exhausted) {
        await fetchBatch(BATCH_SIZE);
      }
    })().finally(() => {
      drainPromise = null;
    });
  }
  await drainPromise;
}

function setLoadMoreHighlight(active) {
  loadMoreBtnEl.classList.toggle('border-white/10', !active);
  loadMoreBtnEl.classList.toggle('text-slate-300', !active);
  loadMoreBtnEl.classList.toggle('border-cyan-300/50', active);
  loadMoreBtnEl.classList.toggle('text-cyan-100', active);
  loadMoreBtnEl.classList.toggle('bg-cyan-400/10', active);
}

function updateLoadMoreButton() {
  if (!loadMoreBtnEl) return;
  if (!state.audit) {
    loadMoreBtnEl.disabled = true;
    setLoadMoreHighlight(false);
    return;
  }

  const filters = readFilters();
  const hasMore = isFiltersActive(filters)
    ? state.filteredVisibleCount < computeFilteredRows(filters).length
    : !state.exhausted;

  loadMoreBtnEl.disabled = !hasMore;
  setLoadMoreHighlight(hasMore);
}

function updateExportButton() {
  if (!exportBtnEl) return;
  exportBtnEl.disabled = !state.audit;
}

function syncActionButtons() {
  updateLoadMoreButton();
  updateExportButton();
}

function csvEscape(value) {
  const s = value == null ? '' : String(value);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/** Every note (input and output) across all loaded rows, flattened one-per-row — always the full set, ignoring active filters. */
function slotToCsvRow(txIndex, tx, side, slot) {
  return [
    txIndex,
    tx.ledger,
    side,
    slot.index,
    slot.audited ? parseFieldAmount(slot.audited.note?.amount).toString() : '',
    slot.audited?.note?.pk ?? '',
    slot.audited?.commitment ?? slot.commitment ?? '',
    side === 'input' ? (slot.nullifier ?? '') : '',
  ];
}

function buildNotesCsvRows() {
  const header = ['tx_index', 'ledger', 'side', 'note_index', 'amount_stroops', 'pk', 'commitment', 'nullifier'];
  const rows = [header];

  for (const { tx, index } of state.rows) {
    for (const slot of normalizedOutputs(tx)) rows.push(slotToCsvRow(index, tx, 'output', slot));
    for (const slot of normalizedInputs(tx)) rows.push(slotToCsvRow(index, tx, 'input', slot));
  }

  return rows;
}

function noteToCsvRow(note) {
  return [
    note.createdTxIndex ?? '',
    note.createdLedger ?? '',
    note.spentTxIndex ?? '',
    note.spentLedger ?? '',
    note.audited?.note?.pk ?? '',
    note.audited?.note?.amount ? parseFieldAmount(note.audited.note.amount).toString() : '',
    note.commitment ?? '',
    note.spentTxIndex != null ? 'spent' : 'unspent',
    note.nullifier ?? '',
  ];
}

/** One row per note (matching the note-view table), instead of one row per input/output slot. */
function buildNoteViewCsvRows() {
  const header = [
    'created_tx_index', 'created_ledger', 'spent_tx_index', 'spent_ledger',
    'pk', 'amount_stroops', 'commitment', 'status', 'nullifier',
  ];
  return [header, ...collectNotes(state.rows).map(noteToCsvRow)];
}

/** One row per transfer edge, plus one row per PK for its deposit/withdraw totals (which have no edge). Always the full set, ignoring active filters (see buildNotesCsvRows). */
function buildPkGraphCsvRows() {
  const header = ['kind', 'from_pk', 'to_pk', 'count', 'amount_stroops'];
  const { nodes, edges } = fullPkGraph();
  const rows = [header];

  for (const edge of edges) {
    rows.push(['transfer', edge.from, edge.to, edge.count, edge.amount.toString()]);
  }
  for (const node of nodes) {
    if (node.receivedCount > 0) rows.push(['received', '', node.pk, node.receivedCount, node.received.toString()]);
    if (node.depositCount > 0) rows.push(['deposit', '', node.pk, node.depositCount, node.deposited.toString()]);
    if (node.withdrawCount > 0) rows.push(['withdraw', node.pk, '', node.withdrawCount, node.withdrawn.toString()]);
  }

  return rows;
}

function downloadCsv(filename, rows) {
  const csv = rows.map((row) => row.map(csvEscape).join(',')).join('\r\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function updateStatus() {
  const filters = readFilters();

  if (state.rows.length === 0) {
    setPanelStatus('No audited transacts yet — pool may have no activity.', 'info');
    return;
  }

  if (isFiltersActive(filters)) {
    const filteredRows = computeFilteredRows(filters);
    const shown = Math.min(state.filteredVisibleCount, filteredRows.length);
    const more = shown < filteredRows.length ? ' — more available, click Load more.' : '';
    setPanelStatus(
      `Showing ${shown} of ${filteredRows.length} matching transaction(s) (${state.rows.length} scanned).${more}`,
      'ok',
    );
    return;
  }

  if (state.exhausted) {
    setPanelStatus(`Showing ${state.rows.length} transaction(s). Audit complete.`, 'ok');
  } else {
    setPanelStatus(`Showing ${state.rows.length} transaction(s) — more available, click Load more.`, 'ok');
  }
}

function updateViewButtons() {
  for (const [btn, view] of [
    [viewTxBtnEl, 'tx'], [viewNoteBtnEl, 'note'], [viewGraphBtnEl, 'graph'], [viewPkGraphBtnEl, 'pkGraph'],
  ]) {
    if (!btn) continue;
    const active = state.view === view;
    btn.setAttribute('aria-pressed', String(active));
    btn.classList.toggle('bg-cyan-400/15', active);
    btn.classList.toggle('text-cyan-100', active);
    btn.classList.toggle('text-slate-400', !active);
  }
}

function setView(view) {
  if (state.view === view) return;
  state.view = view;
  updateViewButtons();
  renderResults();
}

function setFilterControlsDisabled(disabled) {
  for (const filterEl of [
    filterAmountMinEl, filterAmountMaxEl, filterLedgerFromEl, filterLedgerToEl,
    filterPkEl, filterTimeFromEl, filterTimeToEl, filtersClearBtnEl,
  ]) {
    if (filterEl) filterEl.disabled = disabled;
  }
}

/** Drains the cursor first (if a filter needs the full result set), then re-renders. */
async function applyFiltersAndRender() {
  const filters = readFilters();
  if (isFiltersActive(filters) && state.audit && !state.exhausted) {
    setFilterControlsDisabled(true);
    setPanelStatus('Loading full result set to apply filters…', 'info');
    try {
      await ensureFullyLoaded();
    } finally {
      setFilterControlsDisabled(false);
    }
  }
  renderResults();
  syncActionButtons();
  updateStatus();
}

async function populatePools() {
  if (!poolSelectEl) return;

  const config = client().contractConfig();
  state.pools = (config?.pools ?? []).filter((pool) => pool?.gvkMode && pool.gvkMode !== 'off');

  poolSelectEl.innerHTML = '';
  if (state.pools.length === 0) {
    const option = document.createElement('option');
    option.value = '';
    option.textContent = 'No GVK-enabled pools in deployment';
    poolSelectEl.appendChild(option);
    poolSelectEl.disabled = true;
    auditBtnEl.disabled = true;
    return;
  }

  for (const pool of state.pools) {
    const option = document.createElement('option');
    option.value = pool.poolContractId;
    const assetLabel = pool.asset?.kind === 'native'
      ? 'XLM'
      : pool.asset?.symbol || pool.asset?.code || 'asset';
    const shortId = `${pool.poolContractId.slice(0, 6)}...${pool.poolContractId.slice(-4)}`;
    option.textContent = `${assetLabel} · ${pool.gvkMode} · ${shortId}`;
    poolSelectEl.appendChild(option);
  }
  poolSelectEl.disabled = false;
  auditBtnEl.disabled = false;
}

async function loadStoredAuthorityKey() {
  if (!privateKeyEl) return;

  try {
    const setting = await client().storage().getGvkAuthoritySetting();
    if (setting?.privateKey) {
      privateKeyEl.value = setting.privateKey;
      if (keyHintEl) {
        keyHintEl.textContent = 'Loaded authority key from local DB (gvk_authority). Not saved from this page.';
      }
    }
  } catch (err) {
    console.warn('[global-view] authority key load failed:', err);
  }
}

function resetAuditState() {
  state.audit = null;
  state.auditedPoolContractId = null;
  state.rows = [];
  state.poolGvkMode = null;
  state.txCounter = 0;
  state.exhausted = false;
  state.filteredVisibleCount = BATCH_SIZE;
  state.selectedNoteId = null;
  state.graphNotes = null;
  state.selectedPk = null;
  state.selectedFlow = null;
  state.selectedDot = null;
  state.pkGraphNodes = null;
  fullPkGraphCache = null;
}

async function startAudit({ reset }) {
  const poolContractId = poolSelectEl?.value?.trim();
  const privateKey = privateKeyEl?.value?.trim();

  if (!poolContractId) {
    throw new Error('Select a GVK-enabled pool');
  }
  if (!privateKey) {
    throw new Error('Enter the authority private key');
  }

  if (reset) {
    resetAuditState();
    renderResults();
  }

  if (!state.audit) {
    const wallet = getWalletAccount();
    if (!wallet) {
      throw new Error('Connect a wallet before starting a Global View audit');
    }
    await client().openAccount(wallet);
    const pool = await client().account().pool({ poolContract: poolContractId });
    state.audit = await pool.audit(privateKey);
    state.auditedPoolContractId = poolContractId;
    const poolEntry = state.pools.find((entry) => entry.poolContractId === poolContractId);
    state.poolGvkMode = poolEntry?.gvkMode ?? null;
  }

  await fetchBatch(BATCH_SIZE);
}

let getWalletAccount = () => null;

export async function initGvkAuditPanel({ ensureCryptoReady, showToast, getWalletAccount: getWallet }) {
  if (!poolSelectEl) return;
  if (getWallet) getWalletAccount = getWallet;

  viewTxBtnEl?.addEventListener('click', () => setView('tx'));
  viewNoteBtnEl?.addEventListener('click', () => setView('note'));
  viewGraphBtnEl?.addEventListener('click', () => setView('graph'));
  viewPkGraphBtnEl?.addEventListener('click', () => setView('pkGraph'));
  updateViewButtons();

  document.addEventListener('keydown', (event) => {
    if (state.view !== 'graph' && state.view !== 'pkGraph') return;
    if (['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement?.tagName)) return;
    const move = state.view === 'graph' ? moveGraphSelection : movePkGraphSelection;
    if (event.key === 'ArrowLeft') {
      move(-1);
      event.preventDefault();
    } else if (event.key === 'ArrowRight') {
      move(1);
      event.preventDefault();
    }
  });

  for (const filterEl of [filterAmountMinEl, filterAmountMaxEl, filterLedgerFromEl, filterLedgerToEl, filterPkEl]) {
    filterEl?.addEventListener('input', () => {
      state.filteredVisibleCount = BATCH_SIZE;
      applyFiltersAndRender();
    });
  }

  for (const filterEl of [filterTimeFromEl, filterTimeToEl]) {
    filterEl?.addEventListener('change', async () => {
      state.filteredVisibleCount = BATCH_SIZE;
      await updateTimeFilterLedgers();
      applyFiltersAndRender();
    });
  }

  poolSelectEl?.addEventListener('change', () => {
    if (!state.audit || poolSelectEl.value === state.auditedPoolContractId) return;
    resetAuditState();
    renderResults();
    syncActionButtons();
    setPanelStatus('Pool changed — click Sync & Audit to load it.', 'info');
  });

  filtersClearBtnEl?.addEventListener('click', () => {
    for (const filterEl of [
      filterAmountMinEl, filterAmountMaxEl, filterLedgerFromEl, filterLedgerToEl,
      filterPkEl, filterTimeFromEl, filterTimeToEl,
    ]) {
      if (filterEl) filterEl.value = '';
    }
    state.timeFilterLedgers = { from: null, to: null };
    if (filterTimeHintEl) filterTimeHintEl.textContent = TIME_FILTER_HINT_DEFAULT;
    state.filteredVisibleCount = BATCH_SIZE;
    renderResults();
    syncActionButtons();
    updateStatus();
  });

  auditBtnEl?.addEventListener('click', async () => {
    const originalText = auditBtnEl.textContent;
    try {
      auditBtnEl.disabled = true;
      loadMoreBtnEl.disabled = true;
      auditBtnEl.textContent = 'Syncing…';
      setPanelStatus('Syncing chain data and opening audit cursor…', 'info');
      await ensureCryptoReady();
      await startAudit({ reset: true });
      await applyFiltersAndRender();
    } catch (err) {
      setPanelStatus(friendlyErrorMessage(err?.message || String(err)), 'error');
      showToast?.(`Global View audit failed: ${err?.message || err}`, 'error');
    } finally {
      auditBtnEl.disabled = false;
      auditBtnEl.textContent = originalText;
      syncActionButtons();
    }
  });

  loadMoreBtnEl?.addEventListener('click', async () => {
    // Filters already forced a full drain, so "load more" just widens the
    // locally-visible window instead of touching the cursor.
    if (isFiltersActive(readFilters())) {
      state.filteredVisibleCount += BATCH_SIZE;
      renderResults();
      syncActionButtons();
      updateStatus();
      return;
    }

    const originalText = loadMoreBtnEl.textContent;
    try {
      loadMoreBtnEl.disabled = true;
      loadMoreBtnEl.textContent = 'Loading…';
      await startAudit({ reset: false });
      await applyFiltersAndRender();
    } catch (err) {
      setPanelStatus(friendlyErrorMessage(err?.message || String(err)), 'error');
      showToast?.(`Load more failed: ${err?.message || err}`, 'error');
    } finally {
      loadMoreBtnEl.textContent = originalText;
      syncActionButtons();
    }
  });

  exportBtnEl?.addEventListener('click', async () => {
    if (!state.audit) return;

    const originalText = exportBtnEl.textContent;
    try {
      exportBtnEl.disabled = true;
      exportBtnEl.textContent = 'Exporting…';
      if (!state.exhausted) setPanelStatus('Loading full result set to export…', 'info');
      await ensureFullyLoaded();

      const poolContractId = poolSelectEl?.value?.trim() || 'pool';
      const rows = state.view === 'note'
        ? buildNoteViewCsvRows()
        : state.view === 'pkGraph'
          ? buildPkGraphCsvRows()
          : buildNotesCsvRows();
      downloadCsv(`gvk-notes-${poolContractId.slice(0, 8)}-${Date.now()}.csv`, rows);
      updateStatus();
    } catch (err) {
      setPanelStatus(friendlyErrorMessage(err?.message || String(err)), 'error');
      showToast?.(`Export failed: ${err?.message || err}`, 'error');
    } finally {
      exportBtnEl.textContent = originalText;
      syncActionButtons();
    }
  });

  try {
    await ensureCryptoReady();
    bindResultHighlights();
    await populatePools();
    await loadStoredAuthorityKey();
  } catch (err) {
    console.warn('[global-view] init failed:', err);
    setPanelStatus('Global View unavailable until the app runtime is ready.', 'error');
  }
}
