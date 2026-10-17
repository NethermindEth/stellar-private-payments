// Blocklist key helpers. Kept out of admin.js so Node tests can import it.

// The form the app shows a note public key in: `0x` and 32 bytes of hex.
const NOTE_PUBLIC_KEY = /^0x[0-9a-fA-F]{64}$/;

/** One note public key per line. Drops blanks and repeats, which fail a batched insert. */
export function parseBlocklistKeys(text) {
  const keys = text.split('\n').flatMap((line, index) => {
    const key = line.trim();
    if (!key) return [];
    if (!NOTE_PUBLIC_KEY.test(key)) {
      throw new Error(`Line ${index + 1} is not a note public key (0x and 64 hex digits)`);
    }
    return [BigInt(`0x${key.slice(2).match(/../g).reverse().join('')}`)];
  });
  return [...new Set(keys)];
}

/** The note public key form the Blocklist tab takes: the key's bytes reversed. */
export function blocklistKeyToNoteKey(key) {
  return `0x${key.toString(16).padStart(64, '0').match(/../g).reverse().join('')}`;
}

/** `insert_leaves` when `batched`, else `insert_leaf` for a single key. */
export function blocklistInsertCall(keys, batched) {
  if (batched) return { method: 'insert_leaves', args: { entries: keys.map((key) => [key, key]) } };
  if (keys.length > 1) throw new Error('This blocklist predates batched inserts. Add one key at a time.');
  return { method: 'insert_leaf', args: { key: keys[0], value: keys[0] } };
}
