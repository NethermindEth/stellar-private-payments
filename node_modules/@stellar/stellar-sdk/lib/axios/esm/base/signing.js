import { Buffer } from 'buffer';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';

ed.hashes.sha512 = sha512;
function generate(secretKey) {
  return Buffer.from(ed.getPublicKey(secretKey));
}
function sign(data, rawSecret) {
  return Buffer.from(ed.sign(Buffer.from(data), rawSecret));
}
function verify(data, signature, rawPublicKey) {
  return ed.verify(
    Buffer.from(signature),
    Buffer.from(data),
    Buffer.from(rawPublicKey),
    {
      zip215: false
    }
  );
}

export { generate, sign, verify };
//# sourceMappingURL=signing.js.map
