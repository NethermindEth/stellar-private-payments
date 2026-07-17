// Reusable, presentational note helpers shared by the Advanced notes table
// (app/js/ui/notes-table.js) and the Selective Disclosure selector
// (app/js/disclosure.js).
//
// This module is intentionally PURE and STATELESS: it has no dependency on
// App.state, App.events, polling, or DOM <template> tags. Every element is
// built with el()/elc(), so the module works regardless of which view panel
// mounts it (the Advanced notes table or the Disclosure view, both in
// index.html). Callers own their state/lifecycle and pass in data +
// callbacks; the module returns DOM and derived values.
//
// Reuse boundary (by design): the table view keeps its own <tr>/<td> row
// (it is a real HTML table) but reuses filterNotes(), the statusBadge spec,
// and the formatting helpers below. createNoteRow() is an el()-based CARD row
// for non-table note lists (the disclosure selector and any future surface).

// ---------------------------------------------------------------------------
// Minimal DOM builders (signature-compatible with disclosure.js el()/elc()).
// ---------------------------------------------------------------------------

export function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = String(text);
  return node;
}

// Create an element and append DOM-node children. `children` only ever contains
// Nodes (or null) — never raw strings — so nothing untrusted reaches the DOM as
// markup.
export function elc(tag, className, children) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  for (const child of children) {
    if (child instanceof Node) node.appendChild(child);
  }
  return node;
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

// Format a token amount in base units (stroops) to a decimal string with symbol.
// Mirrors both Utils.formatTokenAmount (core.js) and disclosure.js formatAmount.
export function formatAmount(amount, symbol = 'XLM', decimals = 7) {
  try {
    let value = typeof amount === 'bigint' ? amount : BigInt(amount ?? 0);
    const negative = value < 0n;
    if (negative) value = -value;
    const abs = value.toString().padStart(decimals + 1, '0');
    const intPart = abs.slice(0, -decimals);
    const frac = abs.slice(-decimals).replace(/0+$/, '');
    const out = frac ? `${intPart}.${frac}` : intPart;
    return `${negative ? '-' : ''}${out} ${symbol}`;
  } catch {
    return `0 ${symbol}`;
  }
}

// Token symbol for a pool, derived from the deployment config's asset descriptor.
// Takes the pool object (mirrors Utils.poolLabel).
export function tokenLabel(pool) {
  const asset = pool?.asset || {};
  if (asset.kind === 'native') return 'XLM';
  if (asset.kind === 'classic') return asset.code || 'Asset';
  if (asset.kind === 'contract') return asset.symbol || 'Token';
  return 'Token';
}

// Convenience for callers that hold a pool contract id + the pools list
// (mirrors disclosure.js tokenLabelForPool).
export function tokenLabelFor(poolContractId, pools) {
  const pool = (pools || []).find((p) => p.poolContractId === poolContractId);
  return tokenLabel(pool);
}

// Shorten a hex string for display (mirrors disclosure.js shortCommitment).
export function shortHex(hex, start = 8, end = 4, ellipsis = '…') {
  if (!hex || hex.length < start + end + 2) return hex || '--';
  return `${hex.slice(0, start)}${ellipsis}${hex.slice(-end)}`;
}

// ---------------------------------------------------------------------------
// Filtering (pure) — mirrors notes-table.js render() filter semantics.
// ---------------------------------------------------------------------------

// Filter notes by spent status ('all' | 'unspent' | 'spent') and optional pool.
export function filterNotes(notes, { status = 'all', poolId = null } = {}) {
  return (notes || []).filter((note) => {
    const statusOk =
      status === 'all' ? true : status === 'unspent' ? !note.spent : note.spent;
    const poolOk = !poolId || note.poolContractId === poolId;
    return statusOk && poolOk;
  });
}

// ---------------------------------------------------------------------------
// Status badge — one source of truth for the Spent/Available pill.
// ---------------------------------------------------------------------------

// Returns { text, className } so callers can either build a fresh element
// (createStatusBadge) or apply the styling to an existing span (the table view,
// which keeps its `.note-status` hook class).
export function statusBadgeSpec(spent) {
  return spent
    ? {
        text: 'Spent',
        className:
          'inline-flex rounded-full border border-rose-400/30 bg-rose-400/10 px-2 py-1 text-[11px] font-medium text-rose-200',
      }
    : {
        text: 'Available',
        className:
          'inline-flex rounded-full border border-cyan-400/30 bg-cyan-400/10 px-2 py-1 text-[11px] font-medium text-cyan-100',
      };
}

export function createStatusBadge(spent) {
  const { text, className } = statusBadgeSpec(spent);
  return el('span', className, text);
}

// ---------------------------------------------------------------------------
// Card row (el()-based) for non-table note lists.
// ---------------------------------------------------------------------------

// Build a note card row.
//
// note: { id, poolContractId, amount, spent, leafIndex?, createdAtLedger? }
// opts:
//   symbol      — token label to display (falls back to note.tokenLabel/'Token')
//   selectable  — render a leading checkbox
//   selected    — checkbox checked + highlighted row
//   disabled    — checkbox disabled (e.g. max selection reached)
//   onToggle    — (note, checked) => void, fired on checkbox change
//   showBadge   — include the Spent/Available badge (default true)
//   actions     — array of trailing DOM nodes (e.g. buttons); nulls ignored
export function createNoteRow(note, opts = {}) {
  const {
    symbol: symbolOpt,
    selectable = false,
    selected = false,
    disabled = false,
    onToggle,
    showBadge = true,
    actions = [],
  } = opts;

  const symbol = symbolOpt || note.tokenLabel || 'Token';

  const rowTag = selectable ? 'label' : 'div';
  const row = el(
    rowTag,
    `w-full text-left p-3 rounded-lg border transition-all duration-200 flex items-center justify-between gap-3 ${
      selectable ? 'cursor-pointer ' : ''
    }${
      selected
        ? 'bg-brand-500/10 border-brand-500/40 text-brand-300'
        : 'bg-dark-800 border-dark-700 hover:border-dark-600 text-dark-200'
    }`,
  );
  if (note.id) row.dataset.noteId = note.id;

  // Left cluster: optional checkbox + commitment / meta line.
  const leftItems = [];
  if (selectable) {
    const checkbox = el('input', 'accent-brand-500');
    checkbox.type = 'checkbox';
    checkbox.checked = selected;
    if (disabled) checkbox.disabled = true;
    checkbox.addEventListener('change', () => onToggle?.(note, checkbox.checked));
    leftItems.push(checkbox);
  }

  const metaParts = [symbol];
  if (note.leafIndex != null) metaParts.push(`Leaf ${note.leafIndex}`);
  metaParts.push(`Ledger ${note.createdAtLedger ?? 0}`);

  leftItems.push(
    elc('div', 'min-w-0', [
      el('div', 'font-mono text-xs truncate', shortHex(note.id)),
      el('div', 'text-[10px] text-dark-500 mt-0.5', metaParts.join(' · ')),
    ]),
  );
  const left = elc('div', 'flex items-center gap-3 min-w-0', leftItems);

  // Right cluster: status badge + amount + any caller actions.
  const rightItems = [];
  if (showBadge) rightItems.push(createStatusBadge(note.spent));
  rightItems.push(
    el(
      'div',
      `text-xs font-medium whitespace-nowrap ${selected ? 'text-brand-300' : 'text-dark-300'}`,
      formatAmount(note.amount, symbol),
    ),
  );
  for (const action of actions) if (action) rightItems.push(action);
  const right = elc('div', 'flex items-center gap-3 whitespace-nowrap', rightItems);

  row.append(left, right);
  return row;
}
