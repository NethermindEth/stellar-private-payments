export function noteRowId(txIndex, side, slotIndex) {
  return `${txIndex}:${side}:${slotIndex}`;
}

export function normalizeFieldKey(value) {
  const raw = String(value ?? '').trim().toLowerCase();
  return raw || null;
}

export function parseFieldAmount(hex) {
  const s = String(hex ?? '').trim();
  if (!s.startsWith('0x')) return 0n;
  try {
    return BigInt(s);
  } catch {
    return 0n;
  }
}

export function amountByPk(slots) {
  const totals = new Map();
  for (const slot of slots) {
    const pk = normalizeFieldKey(slot.audited.note.pk);
    if (!pk) continue;
    totals.set(pk, (totals.get(pk) ?? 0n) + parseFieldAmount(slot.audited.note.amount));
  }
  return totals;
}

/** @returns {import('stellar-private-payments/types/gvk').GvkAuditedNote | null} */
function asAuditedNote(value) {
  if (!value) return null;
  if (value.note?.pk != null && value.commitment != null) return value;
  return null;
}

export function normalizedOutputs(tx) {
  return (tx.outputs ?? []).map((slot, index) => ({
    index,
    commitment: slot?.commitment ?? null,
    audited: asAuditedNote(slot?.note),
  }));
}

export function normalizedInputs(tx) {
  return (tx.inputs ?? []).map((slot, index) => ({
    index,
    nullifier: slot?.nullifier ?? null,
    audited: asAuditedNote(slot?.note),
  }));
}

const blank = {
  createdTxIndex: null,
  createdLedger: null,
  createdKind: null,
  spentTxIndex: null,
  spentLedger: null,
  spentKind: null,
  nullifier: null,
  spentNoteId: null,
  knownSpent: false,
};

/** Incrementally pairs creation and spend events across the loaded audit. */
export function createNoteIndex() {
  const notes = [];
  const unspent = new Map();
  const byTransaction = new Map();
  const links = new Map();
  const received = new Map();
  const spent = new Map();

  function add(totals, audited) {
    const pk = normalizeFieldKey(audited?.note.pk);
    if (pk) totals.set(pk, (totals.get(pk) ?? 0n) + parseFieldAmount(audited.note.amount));
  }

  /** Appends a transaction and returns the indices of earlier transactions whose notes changed. */
  function append({ tx, index, kind }) {
    const changedTransactions = new Set();
    const touched = [];
    byTransaction.set(index, touched);
    // Inputs before outputs: a tx cannot spend its own outputs.
    for (const slot of normalizedInputs(tx)) {
      const spend = {
        spentTxIndex: index,
        spentLedger: tx.ledger,
        spentKind: kind,
        nullifier: slot.nullifier,
        knownSpent: true,
      };
      // The GVK ciphertext carries no leaf index, so guess the oldest unspent copy:
      // the SDK spends a wallet's oldest copy first.
      const key = normalizeFieldKey(slot.audited?.commitment);
      const copies = unspent.get(key);
      const existing = copies?.shift();
      if (copies?.length === 0) unspent.delete(key);

      if (existing) {
        // Debit what the output credited, before a spend can reveal a view-only output.
        add(spent, existing.audited);
        Object.assign(existing, spend, { spentNoteId: noteRowId(index, 'input', slot.index) });
        links.set(existing.noteId, existing.spentNoteId);
        links.set(existing.spentNoteId, existing.noteId);
        touched.push(existing);
        if (!existing.audited && slot.audited) existing.audited = slot.audited;
        changedTransactions.add(existing.createdTxIndex);
        continue;
      }

      // Spent, but its creating output isn't in the given rows.
      const note = {
        order: notes.length,
        ...blank,
        ...spend,
        commitment: slot.audited?.commitment ?? null,
        audited: slot.audited,
        noteId: noteRowId(index, 'input', slot.index),
      };
      notes.push(note);
      touched.push(note);
    }

    for (const slot of normalizedOutputs(tx)) {
      const commitment = slot.audited?.commitment ?? slot.commitment ?? null;
      const note = {
        order: notes.length,
        ...blank,
        commitment,
        audited: slot.audited,
        createdTxIndex: index,
        createdLedger: tx.ledger,
        createdKind: kind,
        noteId: noteRowId(index, 'output', slot.index),
      };
      notes.push(note);
      touched.push(note);
      add(received, slot.audited);
      const key = normalizeFieldKey(commitment);
      if (!key) continue;
      if (!unspent.has(key)) unspent.set(key, []);
      unspent.get(key).push(note);
    }
    return changedTransactions;
  }

  // Clip event details to the visible transactions, retaining the known spend status.
  function visibleNotes(rows) {
    const shown = new Set(rows.map((row) => row.index));
    const touched = new Set(rows.flatMap((row) => byTransaction.get(row.index) ?? []));
    return [...touched].filter((note) => note.audited).sort((a, b) => a.order - b.order).map((record) => {
      const note = { ...record };
      if (!shown.has(note.createdTxIndex)) {
        Object.assign(note, { createdTxIndex: null, createdLedger: null, createdKind: null });
      }
      if (!shown.has(note.spentTxIndex)) {
        Object.assign(note, { spentTxIndex: null, spentLedger: null, spentKind: null, nullifier: null });
      }
      return note;
    });
  }

  return {
    append,
    links,
    visibleNotes,
    auditedNotes: () => notes.filter((note) => note.audited),
    balanceOf: (pk) => (received.get(normalizeFieldKey(pk)) ?? 0n) - (spent.get(normalizeFieldKey(pk)) ?? 0n),
    receivedBy: (pk) => received.get(normalizeFieldKey(pk)) ?? 0n,
  };
}

function indexRows(rows) {
  const index = createNoteIndex();
  rows.forEach(index.append);
  return index;
}

export function collectNotes(rows, visible = rows) {
  const index = indexRows(rows);
  return visible === rows ? index.auditedNotes() : index.visibleNotes(visible);
}

export function noteLinks(rows) {
  return indexRows(rows).auditedNotes().filter((note) => note.spentNoteId)
    .map((note) => [note.noteId, note.spentNoteId]);
}

/** Per PK, the value of its notes that no loaded transaction spent. */
export function unspentByPk(notes) {
  return amountByPk(notes.filter((note) => note.spentTxIndex == null));
}
