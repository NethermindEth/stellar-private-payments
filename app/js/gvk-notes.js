export function noteRowId(txIndex, side, slotIndex) {
  return `${txIndex}:${side}:${slotIndex}`;
}

export function normalizeFieldKey(value) {
  const raw = String(value ?? '').trim().toLowerCase();
  return raw || null;
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
};

function groupNotes(rows) {
  const notes = [];
  const unspent = new Map();

  for (const { tx, index, kind } of rows) {
    // Inputs before outputs: a tx cannot spend its own outputs.
    for (const slot of normalizedInputs(tx)) {
      const spend = {
        spentTxIndex: index,
        spentLedger: tx.ledger,
        spentKind: kind,
        nullifier: slot.nullifier,
      };
      // The GVK ciphertext carries no leaf index, so the oldest copy counts as the one spent.
      const existing = unspent.get(normalizeFieldKey(slot.audited?.commitment))?.shift();

      if (existing) {
        Object.assign(existing, spend, { spentNoteId: noteRowId(index, 'input', slot.index) });
        if (!existing.audited && slot.audited) existing.audited = slot.audited;
        continue;
      }

      // Spent, but its creating output isn't in the given rows.
      notes.push({
        ...blank,
        ...spend,
        commitment: slot.audited?.commitment ?? null,
        audited: slot.audited,
        noteId: noteRowId(index, 'input', slot.index),
      });
    }

    for (const slot of normalizedOutputs(tx)) {
      const commitment = slot.audited?.commitment ?? slot.commitment ?? null;
      const note = {
        ...blank,
        commitment,
        audited: slot.audited,
        createdTxIndex: index,
        createdLedger: tx.ledger,
        createdKind: kind,
        noteId: noteRowId(index, 'output', slot.index),
      };
      notes.push(note);
      const key = normalizeFieldKey(commitment);
      if (!key) continue;
      if (!unspent.has(key)) unspent.set(key, []);
      unspent.get(key).push(note);
    }
  }

  return notes;
}

/**
 * Collapses every output/input slot across `rows` into one record per note, so
 * copies of a commitment are separate records and a note created in one tx and
 * spent in another shows up once. Keeps the notes created or spent in `visible`,
 * with the creation or spend fields of a hidden tx set to null.
 */
export function collectNotes(rows, visible = rows) {
  const shown = new Set(visible.map((row) => row.index));
  const notes = groupNotes(rows).filter((note) =>
    note.audited && (shown.has(note.createdTxIndex) || shown.has(note.spentTxIndex)));
  for (const note of notes) {
    if (!shown.has(note.createdTxIndex)) {
      Object.assign(note, { createdTxIndex: null, createdLedger: null, createdKind: null });
    }
    if (!shown.has(note.spentTxIndex)) {
      Object.assign(note, { spentTxIndex: null, spentLedger: null, spentKind: null, nullifier: null });
    }
  }
  return notes;
}

/** Pairs each note's output id with the input id that spent it. */
export function noteLinks(rows) {
  return groupNotes(rows)
    .filter((note) => note.spentNoteId)
    .map((note) => [note.noteId, note.spentNoteId]);
}
