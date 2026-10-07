/**
 * Converts between the note public keys an admin enters for the blocklist and
 * the keys the blocklist stores, and builds the call that adds them.
 *
 * Separate from `admin.js` so Node can import it in unit tests.
 */

// The form the app shows a note public key in: `0x` and 32 bytes of hex.
const NOTE_PUBLIC_KEY = /^0x[0-9a-fA-F]{64}$/;

/**
 * Parses note public keys, one per line, into the blocklist keys they stand for.
 *
 * Skips blank lines and repeats, which would fail a batched insert, and keeps
 * first-seen order.
 *
 * @param {string} text
 * @returns {bigint[]}
 * @throws {Error} naming the first line that is not a note public key.
 */
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

/**
 * Returns the note public key a blocklist key stands for, in the form the
 * Blocklist tab takes it: `0x` and the key's 32 bytes in reverse order.
 *
 * @param {bigint} key - A key as the blocklist stores it.
 * @returns {string}
 */
export function blocklistKeyToNoteKey(key) {
  return `0x${key.toString(16).padStart(64, '0').match(/../g).reverse().join('')}`;
}

/**
 * Returns the blocklist call that adds `keys`, each listed with itself as its
 * value.
 *
 * @param {bigint[]} keys
 * @param {boolean} batched - Whether the blocklist has `insert_leaves`.
 * @returns {{method: string, args: Object}}
 * @throws {Error} when the blocklist has no `insert_leaves` and more than one
 *   key is given.
 */
export function blocklistInsertCall(keys, batched) {
  if (batched) return { method: 'insert_leaves', args: { entries: keys.map((key) => [key, key]) } };
  if (keys.length > 1) throw new Error('This blocklist predates batched inserts. Add one key at a time.');
  return { method: 'insert_leaf', args: { key: keys[0], value: keys[0] } };
}
