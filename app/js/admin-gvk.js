/**
 * Global View admin tab — pool decrypt cursor with paginated tx rows.
 */

import * as d3 from 'd3';
import { client } from './wasm-facade.js';
import { friendlyErrorMessage } from './facade-errors.js';

const BATCH_SIZE = 20;

const poolSelectEl = document.getElementById('gvkPoolSelect');
const privateKeyEl = document.getElementById('gvkPrivateKey');
const keyHintEl = document.getElementById('gvkKeyHint');
const auditBtnEl = document.getElementById('gvkAuditBtn');
const loadMoreBtnEl = document.getElementById('gvkLoadMoreBtn');
const viewTxBtnEl = document.getElementById('gvkViewTxBtn');
const viewNoteBtnEl = document.getElementById('gvkViewNoteBtn');
const viewGraphBtnEl = document.getElementById('gvkViewGraphBtn');
const exportBtnEl = document.getElementById('gvkExportBtn');
const statusEl = document.getElementById('gvkAuditStatus');
const emptyEl = document.getElementById('gvkAuditEmpty');
const resultsEl = document.getElementById('gvkAuditResults');
const filterAmountMinEl = document.getElementById('gvkFilterAmountMin');
const filterAmountMaxEl = document.getElementById('gvkFilterAmountMax');
const filterLedgerFromEl = document.getElementById('gvkFilterLedgerFrom');
const filterLedgerToEl = document.getElementById('gvkFilterLedgerTo');
const filterPkEl = document.getElementById('gvkFilterPk');
const filtersClearBtnEl = document.getElementById('gvkFiltersClearBtn');

const state = {
  pools: [],
  audit: null,
  rows: [],
  poolGvkMode: null,
  txCounter: 0,
  exhausted: false,
  noteLinks: new Map(),
  filteredVisibleCount: BATCH_SIZE,
  view: 'tx',
  selectedNoteId: null,
};

function noteRowId(txIndex, side, slotIndex) {
  return `${txIndex}:${side}:${slotIndex}`;
}

function truncateHex(value) {
  const s = String(value ?? '').trim();
  if (!s) return { display: '—', full: null };
  if (s.length <= 11) return { display: s, full: null };
  return { display: `${s.slice(0, 11)}…`, full: s };
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
  const cellValue = typeof value === 'object' && value != null && 'display' in value
    ? value
    : asCell(value);
  const { display, full, matchPk } = cellValue;
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
let activeTxSquareIndex = null;

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
  setTxSquaresVisible(activeTxSquareIndex, false);
  activeTxSquareIndex = null;
}

function syncTxSquaresForElement(el) {
  clearTxSquares();
  if (!el) return;
  // Whichever side this specific dot represents (see the tagging rules in
  // renderGraph) — never both, so we never mix in an unrelated transaction.
  const txIndex = el.dataset?.gvkTxCreated ?? el.dataset?.gvkTxSpent;
  if (txIndex == null) return;
  activeTxSquareIndex = txIndex;
  setTxSquaresVisible(txIndex, true);
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

    clearAllHighlights();
  });

  resultsEl.addEventListener('mouseleave', () => {
    clearAllHighlights();
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
  if (!hex) return '—';
  const stroops = parseFieldAmount(hex);
  if (stroops === 0n) return '0 XLM';

  const whole = stroops / STROOPS_PER_XLM;
  if (whole > 0n) return `${whole.toString()} XLM`;

  const frac = stroops % STROOPS_PER_XLM;
  const fracStr = frac.toString().padStart(7, '0').replace(/0+$/, '');
  return `0.${fracStr} XLM`;
}

/** @returns {import('stellar-private-payments/types/gvk').GvkAuditedNote | null} */
function asAuditedNote(value) {
  if (!value) return null;
  if (value.note?.pk != null && value.commitment != null) return value;
  return null;
}

/** Normalize output slots (legacy `GvkAuditedNote[]` or `GvkOutputSlot[]`). */
function normalizedOutputs(tx) {
  return (tx.outputs ?? []).map((slot, index) => {
    if (slot?.note === null || slot?.note?.note) {
      return {
        index,
        commitment: slot.commitment ?? null,
        audited: asAuditedNote(slot.note),
      };
    }
    return {
      index,
      commitment: slot?.commitment ?? null,
      audited: asAuditedNote(slot),
    };
  });
}

/** Normalize input slots (legacy parallel vecs or `GvkSpentInput[]`). */
function normalizedInputs(tx) {
  const nullifiers = tx.nullifiers ?? [];
  const inputs = tx.inputs ?? [];

  return inputs.map((slot, index) => {
    if (slot?.nullifier != null) {
      return {
        index,
        nullifier: slot.nullifier,
        audited: asAuditedNote(slot.note),
      };
    }
    return {
      index,
      nullifier: nullifiers[index] ?? null,
      audited: asAuditedNote(slot),
    };
  });
}

function sumAuditedAmounts(slots) {
  return slots.reduce(
    (sum, slot) => sum + parseFieldAmount(slot.audited?.note?.amount),
    0n,
  );
}

function classifyTx(tx) {
  const inputSum = sumAuditedAmounts(normalizedInputs(tx));
  const outputSum = sumAuditedAmounts(normalizedOutputs(tx));
  const nullifierCount = tx.nullifiers?.length
    ?? normalizedInputs(tx).filter((slot) => slot.nullifier).length;

  if (!tx.inputs?.length) {
    if (outputSum > 0n) return 'deposit';
    if (nullifierCount > 0) return 'withdraw';
    return 'transfer';
  }

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

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
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

  return {
    amountMin: toStroops(filterAmountMinEl),
    amountMax: toStroops(filterAmountMaxEl),
    ledgerFrom: toInt(filterLedgerFromEl),
    ledgerTo: toInt(filterLedgerToEl),
    pk: normalizeFieldKey(filterPkEl?.value),
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

function rowMatchesFilters(row, filters) {
  const { tx } = row;

  if (filters.ledgerFrom != null && tx.ledger < filters.ledgerFrom) return false;
  if (filters.ledgerTo != null && tx.ledger > filters.ledgerTo) return false;

  if (filters.amountMin == null && filters.amountMax == null && !filters.pk) return true;

  const notes = txNotes(tx);
  return notes.some((note) => {
    if (filters.pk && !normalizeFieldKey(note.note?.pk)?.includes(filters.pk)) return false;
    if (filters.amountMin != null || filters.amountMax != null) {
      const amount = parseFieldAmount(note.note?.amount);
      if (filters.amountMin != null && amount < filters.amountMin) return false;
      if (filters.amountMax != null && amount > filters.amountMax) return false;
    }
    return true;
  });
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
    renderNoteTable(visibleRows);
  } else if (state.view === 'graph') {
    renderGraph(visibleRows, containerWidth);
  } else {
    renderTxCards(visibleRows);
  }

  rebuildNoteLinks();
}

function renderTxCards(rows) {
  for (const row of rows) {
    const { tx, index, kind } = row;
    const outputs = normalizedOutputs(tx);
    const inputs = normalizedInputs(tx);
    const metaParts = [`${outputs.length} output note(s)`];
    if (state.poolGvkMode === 'traceable') {
      metaParts.push(`${inputs.length} input note(s)`);
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

  for (const { tx, index } of rows) {
    for (const slot of normalizedOutputs(tx)) {
      const commitment = slot.audited?.commitment ?? slot.commitment ?? null;
      const key = normalizeFieldKey(commitment) ?? `~${fallbackKey++}`;
      notes.set(key, {
        commitment,
        audited: slot.audited,
        createdTxIndex: index,
        createdLedger: tx.ledger,
        spentTxIndex: null,
        spentLedger: null,
        nullifier: null,
        noteId: noteRowId(index, 'output', slot.index),
      });
    }
  }

  for (const { tx, index } of rows) {
    for (const slot of normalizedInputs(tx)) {
      const commitmentKey = normalizeFieldKey(slot.audited?.commitment);
      const existing = commitmentKey ? notes.get(commitmentKey) : null;

      if (existing) {
        existing.spentTxIndex = index;
        existing.spentLedger = tx.ledger;
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
        spentTxIndex: index,
        spentLedger: tx.ledger,
        nullifier: slot.nullifier,
        noteId: noteRowId(index, 'input', slot.index),
      });
    }
  }

  return [...notes.values()];
}

function txLabel(txIndex, ledger) {
  return txIndex == null ? '—' : `tx ${txIndex} · ledger ${ledger}`;
}

function renderNoteTable(rows) {
  const notes = collectNotes(rows);
  const headers = ['Created', 'PK', 'Amount', 'Commitment', 'Status', 'Spent', 'Nullifier'];
  const wrap = el('div', 'overflow-x-auto rounded-2xl border border-white/8 bg-ink-900/70');
  const grid = el('div', 'grid gap-px bg-white/6 text-[11px]');
  grid.style.gridTemplateColumns = `repeat(${headers.length}, minmax(0, 1fr))`;

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

function colorForNote(note) {
  const pk = normalizeFieldKey(note.audited?.note?.pk);
  if (!pk) return '#64748b';
  let hash = 0;
  for (let i = 0; i < pk.length; i += 1) hash = (hash * 31 + pk.charCodeAt(i)) >>> 0;
  return `hsl(${hash % 360} 70% 60%)`;
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

function moveGraphSelection(delta) {
  const notes = collectNotes(computeVisibleRows(readFilters())).sort((a, b) => noteSortKey(a) - noteSortKey(b));
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

  const addRow = (label, value) => {
    const row = el('div');
    row.appendChild(el('div', 'text-[10px] uppercase tracking-wide text-slate-500', label));
    row.appendChild(el('div', 'font-mono text-slate-200 break-all', value));
    rows.appendChild(row);
  };

  addRow('PK', cellDisplay(cells.pk));
  addRow('Amount', cellDisplay(cells.amount));
  addRow('Status', spent ? 'Spent' : 'Unspent');
  addRow('Commitment', note.commitment ? cellDisplay(truncateHex(note.commitment)) : '—');
  addRow('Created', txLabel(note.createdTxIndex, note.createdLedger));
  addRow('Spent', txLabel(note.spentTxIndex, note.spentLedger));
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
// Rough allowance for the detail panel (w-64 + gap-4) sitting beside the graph.
const GRAPH_SIDE_PANEL_ALLOWANCE = 288;

function renderGraph(rows, containerWidth) {
  const notes = collectNotes(rows).sort((a, b) => noteSortKey(a) - noteSortKey(b));

  if (state.selectedNoteId && !notes.some((n) => n.noteId === state.selectedNoteId)) {
    state.selectedNoteId = null;
  }

  const outer = el('div', 'flex items-stretch gap-4');
  const graphWrap = el('div', 'min-w-0 flex-1 overflow-x-auto rounded-2xl border border-white/8 bg-ink-900/70 p-4');
  outer.appendChild(graphWrap);
  resultsEl.appendChild(outer);

  if (notes.length === 0) {
    graphWrap.appendChild(el('p', 'text-sm text-slate-500', 'No notes to plot.'));
    renderGraphDetailPanel(outer, notes);
    return;
  }

  const ledgers = notes.flatMap((note) => [note.createdLedger, note.spentLedger].filter((v) => v != null));
  const minLedger = Math.min(...ledgers);
  const maxLedger = Math.max(...ledgers);
  const width = Math.max(640, (containerWidth || 0) - GRAPH_SIDE_PANEL_ALLOWANCE);
  const padding = 32;
  const rowHeight = 22;
  const topPad = 16;
  const bottomAxis = 28;
  const minHeight = 360;

  const xScale = d3.scaleLinear()
    .domain([minLedger, maxLedger === minLedger ? maxLedger + 1 : maxLedger])
    .range([padding, width - padding])
    .nice();

  const laneOf = assignGraphLanes(notes, xScale, rowHeight);
  const laneCount = Math.max(...laneOf.values()) + 1;
  const contentHeight = laneCount * rowHeight;
  const height = Math.max(minHeight, topPad + contentHeight + bottomAxis);

  // Center the plotted lanes vertically within the (possibly taller) canvas,
  // rather than always packing them against the top.
  const plotAreaHeight = height - bottomAxis - topPad;
  const yOffset = topPad + Math.max(0, (plotAreaHeight - contentHeight) / 2);
  const yFor = (note) => yOffset + laneOf.get(note.noteId) * rowHeight + rowHeight / 2;

  const svg = d3.select(graphWrap).append('svg')
    .attr('width', width)
    .attr('height', height)
    .attr('viewBox', `0 0 ${width} ${height}`);

  svg.append('g')
    .attr('transform', `translate(0, ${height - bottomAxis})`)
    .call(d3.axisBottom(xScale).ticks(Math.min(10, maxLedger - minLedger + 1)).tickFormat(d3.format('d')))
    .call((g) => g.select('.domain').attr('stroke', 'rgba(255,255,255,0.15)'))
    .call((g) => g.selectAll('line').attr('stroke', 'rgba(255,255,255,0.15)'))
    .call((g) => g.selectAll('text').attr('fill', '#94a3b8').attr('font-size', 10));

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
  svg.append('g')
    .selectAll('circle')
    .data(notes)
    .join('circle')
    .attr('data-gvk-pk', (d) => normalizeFieldKey(d.audited?.note?.pk))
    .attr('data-gvk-note-id', (d) => d.noteId)
    .attr('data-gvk-tx-created', (d) => (d.createdTxIndex != null ? d.createdTxIndex : null))
    .attr('data-gvk-tx-spent', (d) => (d.createdTxIndex == null && d.spentTxIndex != null ? d.spentTxIndex : null))
    .attr('cx', (d) => xScale(d.createdLedger ?? d.spentLedger))
    .attr('cy', yFor)
    .attr('r', (d) => (d.noteId === state.selectedNoteId ? 7 : 5))
    .attr('fill', colorForNote)
    .attr('stroke', (d) => (d.noteId === state.selectedNoteId ? '#e0f2fe' : '#0b1220'))
    .attr('stroke-width', (d) => (d.noteId === state.selectedNoteId ? 2 : 1))
    .style('cursor', 'pointer')
    .on('click', (_event, d) => selectGraphNote(d.noteId));

  // Secondary (spend) dot only ever represents the spend event at the spend
  // ledger, so it's tagged for the spent-tx group only.
  svg.append('g')
    .selectAll('circle')
    .data(spentNotes)
    .join('circle')
    .attr('data-gvk-pk', (d) => normalizeFieldKey(d.audited?.note?.pk))
    .attr('data-gvk-note-id', (d) => d.noteId)
    .attr('data-gvk-tx-spent', (d) => d.spentTxIndex)
    .attr('cx', (d) => xScale(d.spentLedger))
    .attr('cy', yFor)
    .attr('r', 4)
    .attr('fill', '#0b1220')
    .attr('stroke', colorForNote)
    .attr('stroke-width', 1.5)
    .style('cursor', 'pointer')
    .on('click', (_event, d) => selectGraphNote(d.noteId));

  // Little square around each note touched by a tx that touches more than
  // one visible note in total — counting BOTH its outputs and the inputs it
  // consumed, since they share one ledger. Purely decorative
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
    .attr('fill', 'transparent')
    .attr('stroke', 'rgba(226,232,240,0.6)')
    .attr('stroke-width', 1)
    .style('pointer-events', 'none')
    .style('opacity', (d) => (selectedTxIndex != null && d.spentTxIndex === selectedTxIndex ? 1 : 0));

  renderGraphDetailPanel(outer, notes);
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

function updateLoadMoreButton() {
  if (!loadMoreBtnEl) return;
  if (!state.audit) {
    loadMoreBtnEl.disabled = true;
    return;
  }

  const filters = readFilters();
  if (isFiltersActive(filters)) {
    loadMoreBtnEl.disabled = state.filteredVisibleCount >= computeFilteredRows(filters).length;
    return;
  }

  loadMoreBtnEl.disabled = state.exhausted;
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
function buildNotesCsvRows() {
  const header = ['tx_index', 'ledger', 'side', 'note_index', 'amount_stroops', 'pk', 'commitment', 'nullifier'];
  const rows = [header];

  for (const { tx, index } of state.rows) {
    for (const slot of normalizedOutputs(tx)) {
      rows.push([
        index,
        tx.ledger,
        'output',
        slot.index,
        slot.audited ? parseFieldAmount(slot.audited.note?.amount).toString() : '',
        slot.audited?.note?.pk ?? '',
        slot.audited?.commitment ?? slot.commitment ?? '',
        '',
      ]);
    }
    for (const slot of normalizedInputs(tx)) {
      rows.push([
        index,
        tx.ledger,
        'input',
        slot.index,
        slot.audited ? parseFieldAmount(slot.audited.note?.amount).toString() : '',
        slot.audited?.note?.pk ?? '',
        slot.audited?.commitment ?? '',
        slot.nullifier ?? '',
      ]);
    }
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
    setPanelStatus(
      `Showing ${shown} of ${filteredRows.length} matching transaction(s) (${state.rows.length} scanned).`,
      'ok',
    );
    return;
  }

  if (state.exhausted) {
    setPanelStatus(`Showing ${state.rows.length} transaction(s). Audit complete.`, 'ok');
  } else {
    setPanelStatus(`Showing ${state.rows.length} transaction(s).`, 'ok');
  }
}

function updateViewButtons() {
  for (const [btn, view] of [[viewTxBtnEl, 'tx'], [viewNoteBtnEl, 'note'], [viewGraphBtnEl, 'graph']]) {
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
  for (const filterEl of [filterAmountMinEl, filterAmountMaxEl, filterLedgerFromEl, filterLedgerToEl, filterPkEl, filtersClearBtnEl]) {
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
    option.textContent = `${assetLabel} · ${pool.gvkMode} · ${pool.poolContractId.slice(0, 8)}…`;
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

async function startAudit({ reset }) {
  const poolContractId = poolSelectEl?.value?.trim();
  const privateKey = privateKeyEl?.value?.trim();

  if (!poolContractId) {
    throw new Error('Select a GVK-enabled pool');
  }
  if (!privateKey) {
    throw new Error('Enter the authority private key');
  }

  const pool = state.pools.find((entry) => entry.poolContractId === poolContractId);
  state.poolGvkMode = pool?.gvkMode ?? null;

  if (reset) {
    state.audit = null;
    state.rows = [];
    state.txCounter = 0;
    state.exhausted = false;
    state.filteredVisibleCount = BATCH_SIZE;
    renderResults();
  }

  if (!state.audit) {
    state.audit = await client().gvkAudit(poolContractId, privateKey);
  }

  await fetchBatch(BATCH_SIZE);
}

export async function initGvkAuditPanel({ ensureCryptoReady, showToast }) {
  if (!poolSelectEl) return;

  viewTxBtnEl?.addEventListener('click', () => setView('tx'));
  viewNoteBtnEl?.addEventListener('click', () => setView('note'));
  viewGraphBtnEl?.addEventListener('click', () => setView('graph'));
  updateViewButtons();

  document.addEventListener('keydown', (event) => {
    if (state.view !== 'graph') return;
    if (['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement?.tagName)) return;
    if (event.key === 'ArrowLeft') {
      moveGraphSelection(-1);
      event.preventDefault();
    } else if (event.key === 'ArrowRight') {
      moveGraphSelection(1);
      event.preventDefault();
    }
  });

  for (const filterEl of [filterAmountMinEl, filterAmountMaxEl, filterLedgerFromEl, filterLedgerToEl, filterPkEl]) {
    filterEl?.addEventListener('input', () => {
      state.filteredVisibleCount = BATCH_SIZE;
      applyFiltersAndRender();
    });
  }

  filtersClearBtnEl?.addEventListener('click', () => {
    for (const filterEl of [filterAmountMinEl, filterAmountMaxEl, filterLedgerFromEl, filterLedgerToEl, filterPkEl]) {
      if (filterEl) filterEl.value = '';
    }
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
      downloadCsv(`gvk-notes-${poolContractId.slice(0, 8)}-${Date.now()}.csv`, buildNotesCsvRows());
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
