// Stellar account strkeys (G...) from raw ed25519 public keys, without pulling
// the Stellar SDK into the test package.

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const ED25519_PUBLIC_KEY_VERSION = 6 << 3;

function crc16Xmodem(bytes) {
  let crc = 0;
  for (const byte of bytes) {
    crc ^= byte << 8;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc & 0x8000) ? ((crc << 1) ^ 0x1021) : (crc << 1);
      crc &= 0xffff;
    }
  }
  return crc;
}

function base32Encode(bytes) {
  let value = 0;
  let bits = 0;
  let output = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  return bits ? output + BASE32_ALPHABET[(value << (5 - bits)) & 31] : output;
}

/** Encode a 32-byte ed25519 public key as a G... account address. */
export function encodeAccountAddress(publicKey) {
  if (publicKey.length !== 32) throw new TypeError(`expected a 32-byte ed25519 key, got ${publicKey.length} bytes`);
  const encoded = Buffer.alloc(35);
  encoded[0] = ED25519_PUBLIC_KEY_VERSION;
  Buffer.from(publicKey).copy(encoded, 1);
  const checksum = crc16Xmodem(encoded.subarray(0, 33));
  encoded[33] = checksum & 0xff;
  encoded[34] = checksum >>> 8;
  return base32Encode(encoded);
}
