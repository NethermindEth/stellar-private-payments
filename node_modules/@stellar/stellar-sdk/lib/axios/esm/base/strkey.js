import { Buffer } from 'buffer';
import base32 from 'base32.js';
import { verifyChecksum } from './util/checksum.js';

const versionBytes = {
  ed25519PublicKey: 6 << 3,
  // G (when encoded in base32)
  ed25519SecretSeed: 18 << 3,
  // S
  med25519PublicKey: 12 << 3,
  // M
  preAuthTx: 19 << 3,
  // T
  sha256Hash: 23 << 3,
  // X
  signedPayload: 15 << 3,
  // P
  contract: 2 << 3,
  // C
  liquidityPool: 11 << 3,
  // L
  claimableBalance: 1 << 3
  // B
};
const strkeyTypes = {
  G: "ed25519PublicKey",
  S: "ed25519SecretSeed",
  M: "med25519PublicKey",
  T: "preAuthTx",
  X: "sha256Hash",
  P: "signedPayload",
  C: "contract",
  L: "liquidityPool",
  B: "claimableBalance"
};
function hasVersionByteName(versionByteName) {
  return Object.prototype.hasOwnProperty.call(versionBytes, versionByteName);
}
class StrKey {
  static types = strkeyTypes;
  /**
   * Encodes `data` to strkey ed25519 public key.
   *
   * @param data - raw data to encode
   */
  static encodeEd25519PublicKey(data) {
    return encodeCheck("ed25519PublicKey", data);
  }
  /**
   * Decodes strkey ed25519 public key to raw data.
   *
   * If the parameter is a muxed account key ("M..."), this will only encode it
   * as a basic Ed25519 key (as if in "G..." format).
   *
   * @param data - "G..." (or "M...") key representation to decode
   */
  static decodeEd25519PublicKey(data) {
    return decodeCheck("ed25519PublicKey", data);
  }
  /**
   * Returns true if the given Stellar public key is a valid ed25519 public key.
   *
   * @param publicKey - public key to check
   */
  static isValidEd25519PublicKey(publicKey) {
    return isValid("ed25519PublicKey", publicKey);
  }
  /**
   * Encodes data to strkey ed25519 seed.
   *
   * @param data - data to encode
   */
  static encodeEd25519SecretSeed(data) {
    return encodeCheck("ed25519SecretSeed", data);
  }
  /**
   * Decodes strkey ed25519 seed to raw data.
   *
   * @param address - data to decode
   */
  static decodeEd25519SecretSeed(address) {
    return decodeCheck("ed25519SecretSeed", address);
  }
  /**
   * Returns true if the given Stellar secret key is a valid ed25519 secret seed.
   *
   * @param seed - seed to check
   */
  static isValidEd25519SecretSeed(seed) {
    return isValid("ed25519SecretSeed", seed);
  }
  /**
   * Encodes data to strkey med25519 public key.
   *
   * @param data - data to encode
   */
  static encodeMed25519PublicKey(data) {
    return encodeCheck("med25519PublicKey", data);
  }
  /**
   * Decodes strkey med25519 public key to raw data.
   *
   * @param address - data to decode
   */
  static decodeMed25519PublicKey(address) {
    return decodeCheck("med25519PublicKey", address);
  }
  /**
   * Returns true if the given Stellar public key is a valid med25519 public key.
   *
   * @param publicKey - public key to check
   */
  static isValidMed25519PublicKey(publicKey) {
    return isValid("med25519PublicKey", publicKey);
  }
  /**
   * Encodes data to strkey preAuthTx.
   *
   * @param data - data to encode
   */
  static encodePreAuthTx(data) {
    return encodeCheck("preAuthTx", data);
  }
  /**
   * Decodes strkey PreAuthTx to raw data.
   *
   * @param address - data to decode
   */
  static decodePreAuthTx(address) {
    return decodeCheck("preAuthTx", address);
  }
  /**
   * Encodes data to strkey sha256 hash.
   *
   * @param data - data to encode
   */
  static encodeSha256Hash(data) {
    return encodeCheck("sha256Hash", data);
  }
  /**
   * Decodes strkey sha256 hash to raw data.
   *
   * @param address - data to decode
   */
  static decodeSha256Hash(address) {
    return decodeCheck("sha256Hash", address);
  }
  /**
   * Encodes raw data to strkey signed payload (P...).
   *
   * @param data - data to encode
   */
  static encodeSignedPayload(data) {
    return encodeCheck("signedPayload", data);
  }
  /**
   * Decodes strkey signed payload (P...) to raw data.
   *
   * @param address - address to decode
   */
  static decodeSignedPayload(address) {
    return decodeCheck("signedPayload", address);
  }
  /**
   * Checks validity of alleged signed payload (P...) strkey address.
   *
   * @param address - signer key to check
   */
  static isValidSignedPayload(address) {
    return isValid("signedPayload", address);
  }
  /**
   * Encodes raw data to strkey contract (C...).
   *
   * @param data - data to encode
   */
  static encodeContract(data) {
    return encodeCheck("contract", data);
  }
  /**
   * Decodes strkey contract (C...) to raw data.
   *
   * @param address - address to decode
   */
  static decodeContract(address) {
    return decodeCheck("contract", address);
  }
  /**
   * Checks validity of alleged contract (C...) strkey address.
   *
   * @param address - signer key to check
   */
  static isValidContract(address) {
    return isValid("contract", address);
  }
  /**
   * Encodes raw data to strkey claimable balance (B...).
   *
   * @param data - data to encode
   */
  static encodeClaimableBalance(data) {
    return encodeCheck("claimableBalance", data);
  }
  /**
   * Decodes strkey claimable balance (B...) to raw data.
   *
   * @param address - balance to decode
   */
  static decodeClaimableBalance(address) {
    return decodeCheck("claimableBalance", address);
  }
  /**
   * Checks validity of alleged claimable balance (B...) strkey address.
   *
   * @param address - balance to check
   */
  static isValidClaimableBalance(address) {
    return isValid("claimableBalance", address);
  }
  /**
   * Encodes raw data to strkey liquidity pool (L...).
   *
   * @param data - data to encode
   */
  static encodeLiquidityPool(data) {
    return encodeCheck("liquidityPool", data);
  }
  /**
   * Decodes strkey liquidity pool (L...) to raw data.
   *
   * @param address - address to decode
   */
  static decodeLiquidityPool(address) {
    return decodeCheck("liquidityPool", address);
  }
  /**
   * Checks validity of alleged liquidity pool (L...) strkey address.
   *
   * @param address - pool to check
   */
  static isValidLiquidityPool(address) {
    return isValid("liquidityPool", address);
  }
  /**
   * Returns the strkey type based on the prefix of the given strkey address,
   * or undefined if the prefix is invalid.
   *
   * @param address - the strkey address to check
   */
  static getVersionByteForPrefix(address) {
    if (address.length < 1) {
      return void 0;
    }
    const prefix = address[0];
    return strkeyTypes[prefix];
  }
}
function isValid(versionByteName, encoded) {
  if (typeof encoded !== "string") {
    return false;
  }
  switch (versionByteName) {
    case "ed25519PublicKey":
    // falls through
    case "ed25519SecretSeed":
    // falls through
    case "preAuthTx":
    // falls through
    case "sha256Hash":
    // falls through
    case "contract":
    // falls through
    case "liquidityPool":
      if (encoded.length !== 56) {
        return false;
      }
      break;
    case "claimableBalance":
      if (encoded.length !== 58) {
        return false;
      }
      break;
    case "med25519PublicKey":
      if (encoded.length !== 69) {
        return false;
      }
      break;
    case "signedPayload":
      if (encoded.length < 56 || encoded.length > 165) {
        return false;
      }
      break;
    default:
      return false;
  }
  let decoded;
  try {
    decoded = decodeCheck(versionByteName, encoded);
  } catch {
    return false;
  }
  switch (versionByteName) {
    case "ed25519PublicKey":
    // falls through
    case "ed25519SecretSeed":
    // falls through
    case "preAuthTx":
    // falls through
    case "sha256Hash":
    // falls through
    case "contract":
    case "liquidityPool":
      return decoded.length === 32;
    case "claimableBalance":
      return decoded.length === 32 + 1;
    // +1 byte for discriminant
    case "med25519PublicKey":
      return decoded.length === 40;
    // +8 bytes for the ID
    case "signedPayload":
      return (
        // 32 for the signer, +4 for the payload size, then either +4 for the
        // min or +64 for the max payload
        decoded.length >= 32 + 4 + 4 && decoded.length <= 32 + 4 + 64
      );
    default:
      return false;
  }
}
function decodeCheck(versionByteName, encoded) {
  if (typeof encoded !== "string") {
    throw new TypeError("encoded argument must be of type String");
  }
  const decoded = base32.decode(encoded);
  const versionByte = decoded[0];
  const payload = decoded.slice(0, -2);
  const data = payload.slice(1);
  const checksum = decoded.slice(-2);
  if (encoded !== base32.encode(decoded)) {
    throw new Error("invalid encoded string");
  }
  if (!hasVersionByteName(versionByteName)) {
    throw new Error(
      `${versionByteName} is not a valid version byte name. Expected one of ${Object.keys(versionBytes).join(", ")}`
    );
  }
  const expectedVersion = versionBytes[versionByteName];
  if (versionByte !== expectedVersion) {
    throw new Error(
      `invalid version byte. expected ${expectedVersion}, got ${versionByte}`
    );
  }
  const expectedChecksum = calculateChecksum(payload);
  if (!verifyChecksum(expectedChecksum, checksum)) {
    throw new Error(`invalid checksum`);
  }
  return Buffer.from(data);
}
function encodeCheck(versionByteName, data) {
  if (data === null || data === void 0) {
    throw new Error("cannot encode null data");
  }
  if (!hasVersionByteName(versionByteName)) {
    throw new Error(
      `${versionByteName} is not a valid version byte name. Expected one of ${Object.keys(versionBytes).join(", ")}`
    );
  }
  const versionByte = versionBytes[versionByteName];
  data = Buffer.from(data);
  const versionBuffer = Buffer.from([versionByte]);
  const payload = Buffer.concat([versionBuffer, data]);
  const checksum = Buffer.from(calculateChecksum(payload));
  const unencoded = Buffer.concat([payload, checksum]);
  return base32.encode(unencoded);
}
function calculateChecksum(payload) {
  const crcTable = [
    0,
    4129,
    8258,
    12387,
    16516,
    20645,
    24774,
    28903,
    33032,
    37161,
    41290,
    45419,
    49548,
    53677,
    57806,
    61935,
    4657,
    528,
    12915,
    8786,
    21173,
    17044,
    29431,
    25302,
    37689,
    33560,
    45947,
    41818,
    54205,
    50076,
    62463,
    58334,
    9314,
    13379,
    1056,
    5121,
    25830,
    29895,
    17572,
    21637,
    42346,
    46411,
    34088,
    38153,
    58862,
    62927,
    50604,
    54669,
    13907,
    9842,
    5649,
    1584,
    30423,
    26358,
    22165,
    18100,
    46939,
    42874,
    38681,
    34616,
    63455,
    59390,
    55197,
    51132,
    18628,
    22757,
    26758,
    30887,
    2112,
    6241,
    10242,
    14371,
    51660,
    55789,
    59790,
    63919,
    35144,
    39273,
    43274,
    47403,
    23285,
    19156,
    31415,
    27286,
    6769,
    2640,
    14899,
    10770,
    56317,
    52188,
    64447,
    60318,
    39801,
    35672,
    47931,
    43802,
    27814,
    31879,
    19684,
    23749,
    11298,
    15363,
    3168,
    7233,
    60846,
    64911,
    52716,
    56781,
    44330,
    48395,
    36200,
    40265,
    32407,
    28342,
    24277,
    20212,
    15891,
    11826,
    7761,
    3696,
    65439,
    61374,
    57309,
    53244,
    48923,
    44858,
    40793,
    36728,
    37256,
    33193,
    45514,
    41451,
    53516,
    49453,
    61774,
    57711,
    4224,
    161,
    12482,
    8419,
    20484,
    16421,
    28742,
    24679,
    33721,
    37784,
    41979,
    46042,
    49981,
    54044,
    58239,
    62302,
    689,
    4752,
    8947,
    13010,
    16949,
    21012,
    25207,
    29270,
    46570,
    42443,
    38312,
    34185,
    62830,
    58703,
    54572,
    50445,
    13538,
    9411,
    5280,
    1153,
    29798,
    25671,
    21540,
    17413,
    42971,
    47098,
    34713,
    38840,
    59231,
    63358,
    50973,
    55100,
    9939,
    14066,
    1681,
    5808,
    26199,
    30326,
    17941,
    22068,
    55628,
    51565,
    63758,
    59695,
    39368,
    35305,
    47498,
    43435,
    22596,
    18533,
    30726,
    26663,
    6336,
    2273,
    14466,
    10403,
    52093,
    56156,
    60223,
    64286,
    35833,
    39896,
    43963,
    48026,
    19061,
    23124,
    27191,
    31254,
    2801,
    6864,
    10931,
    14994,
    64814,
    60687,
    56684,
    52557,
    48554,
    44427,
    40424,
    36297,
    31782,
    27655,
    23652,
    19525,
    15522,
    11395,
    7392,
    3265,
    61215,
    65342,
    53085,
    57212,
    44955,
    49082,
    36825,
    40952,
    28183,
    32310,
    20053,
    24180,
    11923,
    16050,
    3793,
    7920
  ];
  let crc16 = 0;
  for (let i = 0; i < payload.length; i += 1) {
    const byte = payload[i];
    if (byte === void 0) {
      continue;
    }
    const lookupIndex = crc16 >> 8 ^ byte;
    crc16 = crc16 << 8 ^ (crcTable[lookupIndex] ?? 0);
    crc16 &= 65535;
  }
  const checksum = new Uint8Array(2);
  checksum[0] = crc16 & 255;
  checksum[1] = crc16 >> 8 & 255;
  return checksum;
}

export { StrKey, decodeCheck, encodeCheck };
//# sourceMappingURL=strkey.js.map
