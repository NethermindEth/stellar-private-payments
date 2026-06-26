import { Buffer } from 'buffer';
import { sha256 } from '@noble/hashes/sha2.js';

function hash(data) {
  const bytes = typeof data === "string" ? Buffer.from(data, "utf8") : data;
  return Buffer.from(sha256(bytes));
}

export { hash };
//# sourceMappingURL=hashing.js.map
