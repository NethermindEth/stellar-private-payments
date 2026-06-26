import { NestedXdrType } from './xdr-type';
import { XdrWriterError, XdrReaderError } from './errors';

export class Array extends NestedXdrType {
  constructor(childType, length, maxDepth = NestedXdrType.DEFAULT_MAX_DEPTH) {
    super(maxDepth);
    this._childType = childType;
    this._length = length;
  }

  /**
   * @inheritDoc
   */
  read(reader, remainingDepth = this._maxDepth) {
    // Upper-bound fast-fail: remaining bytes is a loose capacity check since
    // each XDR element typically consumes more than 1 byte (e.g., 4+ bytes).
    if (this._length > reader.remainingBytes()) {
      throw new XdrReaderError(
        `Array length ${
          this._length
        } exceeds remaining ${reader.remainingBytes()} bytes`
      );
    }
    NestedXdrType.checkDepth(remainingDepth);
    const result = [];
    // read values
    for (let i = 0; i < this._length; i++) {
      result.push(this._childType.read(reader, remainingDepth - 1));
    }
    return result;
  }

  /**
   * @inheritDoc
   */
  write(value, writer) {
    if (!global.Array.isArray(value))
      throw new XdrWriterError(`value is not array`);

    if (value.length !== this._length)
      throw new XdrWriterError(
        `got array of size ${value.length}, expected ${this._length}`
      );

    for (const child of value) {
      this._childType.write(child, writer);
    }
  }

  /**
   * @inheritDoc
   */
  isValid(value) {
    if (!(value instanceof global.Array) || value.length !== this._length) {
      return false;
    }

    for (const child of value) {
      if (!this._childType.isValid(child)) return false;
    }
    return true;
  }
}
