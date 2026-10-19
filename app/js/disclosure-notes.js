export function normalizeCommitment(s) {
  if (!s) return '';
  let t = s.toLowerCase().trim();
  if (t.startsWith('0x')) t = t.slice(2);
  // strip leading zeros so "0x01" and "0x1" and "1" match
  t = t.replace(/^0+/, '');
  return t;
}

// Copies of a commitment share `id`, so only the pool and leaf tell them apart.
export function sameNote(a, b) {
  return a.poolContractId === b.poolContractId && a.leafIndex === b.leafIndex;
}

// The copy the SDK proves for this note's commitment: lowest unspent leaf, else lowest spent.
export function disclosedCopy(notes, note) {
  const commitment = normalizeCommitment(note.id);
  return notes
    .filter((n) =>
      n.poolContractId === note.poolContractId && normalizeCommitment(n.id) === commitment)
    .sort((a, b) => a.spent - b.spent || a.leafIndex - b.leafIndex)[0];
}

export function preselectNotes(notes, commitments) {
  return [...new Set(commitments.map(normalizeCommitment))]
    .map((commitment) => notes.find((n) => normalizeCommitment(n.id) === commitment))
    .filter(Boolean)
    .map((note) => disclosedCopy(notes, note))
    .slice(0, 4);
}
