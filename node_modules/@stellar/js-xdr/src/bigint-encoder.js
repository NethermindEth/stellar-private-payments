/**
 * Encode a native `bigint` value from a list of arbitrary integer-like values.
 *
 * @param {Array<number|bigint|string>} parts - Slices to encode in big-endian
 *    format (i.e. earlier elements are higher bits)
 * @param {64|128|256} size - Number of bits in the target integer type
 * @param {boolean} unsigned - Whether it's an unsigned integer
 *
 * @returns {bigint}
 */
export function encodeBigIntFromBits(parts, size, unsigned) {
  if (!(parts instanceof Array)) {
    // allow a single parameter instead of an array
    parts = [parts];
  } else if (parts.length && parts[0] instanceof Array) {
    // unpack nested array param
    parts = parts[0];
  }

  const total = parts.length;
  const sliceSize = size / total;
  switch (sliceSize) {
    case 32:
    case 64:
    case 128:
    case 256:
      break;

    default:
      throw new RangeError(
        `expected slices to fit in 32/64/128/256 bits, got ${parts}`
      );
  }

  // normalize all inputs to bigint
  try {
    for (let i = 0; i < parts.length; i++) {
      if (typeof parts[i] !== 'bigint') {
        parts[i] = BigInt(parts[i].valueOf());
      }
    }
  } catch (e) {
    throw new TypeError(`expected bigint-like values, got: ${parts} (${e})`);
  }

  // fast path: single value — validate and return directly without assembly
  if (parts.length === 1) {
    const value = parts[0];
    if (unsigned && value < 0n) {
      throw new RangeError(`expected a positive value, got: ${parts}`);
    }
    const [min, max] = calculateBigIntBoundaries(size, unsigned);
    if (value < min || value > max) {
      throw new RangeError(
        `bigint value ${value} for ${formatIntName(
          size,
          unsigned
        )} out of range [${min}, ${max}]`
      );
    }
    return value;
  }

  // multi-part assembly: encode in big-endian fashion, shifting each slice
  let result = 0n;

  for (let i = 0; i < parts.length; i++) {
    assertSliceFits(parts[i], sliceSize);
    result |= BigInt.asUintN(sliceSize, parts[i]) << BigInt(i * sliceSize);
  }

  if (!unsigned) {
    result = BigInt.asIntN(size, result);
  }

  // check boundaries
  const [min, max] = calculateBigIntBoundaries(size, unsigned);
  if (result >= min && result <= max) {
    return result;
  }

  // failed to encode
  throw new RangeError(
    `bigint values [${parts}] for ${formatIntName(
      size,
      unsigned
    )} out of range [${min}, ${max}]: ${result}`
  );
}

/**
 * Transforms a single bigint value that's supposed to represent a `size`-bit
 * integer into a list of `sliceSize`d chunks.
 *
 * @param {bigint} value - Single bigint value to decompose
 * @param {64|128|256} iSize - Number of bits represented by `value`
 * @param {32|64|128} sliceSize - Number of chunks to decompose into
 * @return {bigint[]} List of signed bigint chunks in big-endian order (i.e. earlier elements are higher bits)
 */
export function sliceBigInt(value, iSize, sliceSize) {
  if (typeof value !== 'bigint') {
    throw new TypeError(`Expected bigint 'value', got ${typeof value}`);
  }

  const total = iSize / sliceSize;
  if (total === 1) {
    return [value];
  }

  if (
    sliceSize < 32 ||
    sliceSize > 128 ||
    (total !== 2 && total !== 4 && total !== 8)
  ) {
    throw new TypeError(
      `invalid bigint (${value}) and slice size (${iSize} -> ${sliceSize}) combination`
    );
  }

  const shift = BigInt(sliceSize);

  // iterate shift and mask application
  const result = new Array(total);
  for (let i = 0; i < total; i++) {
    // we force a signed interpretation to preserve sign in each slice value,
    // but downstream can convert to unsigned if it's appropriate
    result[i] = BigInt.asIntN(sliceSize, value); // clamps to size

    // move on to the next chunk
    value >>= shift;
  }

  return result;
}

export function formatIntName(precision, unsigned) {
  return `${unsigned ? 'u' : 'i'}${precision}`;
}

/**
 * Get min|max boundaries for an integer with a specified bits size
 * @param {64|128|256} size - Number of bits in the source integer type
 * @param {Boolean} unsigned - Whether it's an unsigned integer
 * @return {BigInt[]}
 */
export function calculateBigIntBoundaries(size, unsigned) {
  if (unsigned) {
    return [0n, (1n << BigInt(size)) - 1n];
  }

  const boundary = 1n << BigInt(size - 1);
  return [0n - boundary, boundary - 1n];
}

/**
 * Asserts that a given part fits within the specified slice size.
 * @param {bigint | number | string} part - The part to check.
 * @param {number} sliceSize - The size of the slice in bits (e.g., 32, 64, 128)
 * @returns {void}
 * @throws {RangeError} If the part does not fit within the slice size.
 */
function assertSliceFits(part, sliceSize) {
  const fitsSigned = BigInt.asIntN(sliceSize, part) === part;
  const fitsUnsigned = BigInt.asUintN(sliceSize, part) === part;

  if (!fitsSigned && !fitsUnsigned) {
    throw new RangeError(
      `slice value ${part} does not fit in ${sliceSize} bits`
    );
  }
}
