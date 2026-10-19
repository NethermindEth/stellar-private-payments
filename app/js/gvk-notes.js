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

/** Flat table of every note across the given tx rows — no tx-card grouping. */
/**
 * Collapses every output/input slot across the given tx rows into one record
 * per distinct note (keyed by commitment), so a note created in one tx and
 * later spent in another shows up exactly once — not once per tx it touches.
 */
export function collectNotes(rows) {
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
