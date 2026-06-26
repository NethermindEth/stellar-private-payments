import { UnsignedInt } from './unsigned-int';
import { NestedXdrType } from './xdr-type';
import { XdrReaderError, XdrWriterError } from './errors';

export class VarArray extends NestedXdrType {
  constructor(
    childType,
    maxLength = UnsignedInt.MAX_VALUE,
    maxDepth = NestedXdrType.DEFAULT_MAX_DEPTH
  ) {
    super(maxDepth);
    this._childType = childType;
    this._maxLength = maxLength;
  }

  /**
   * @inheritDoc
   */
  read(reader, remainingDepth = this._maxDepth) {
    NestedXdrType.checkDepth(remainingDepth);
    const length = UnsignedInt.read(reader);
    if (length > this._maxLength)
      throw new XdrReaderError(
        `saw ${length} length VarArray, max allowed is ${this._maxLength}`
      );

    // Upper-bound fast-fail: remaining bytes is a loose capacity check since
    // each XDR element typically consumes more than 1 byte (e.g., 4+ bytes)
    if (length > reader.remainingBytes()) {
      throw new XdrReaderError(
        `VarArray length ${length} exceeds remaining ${reader.remainingBytes()} bytes`
      );
    }

    const result = [];
    for (let i = 0; i < length; i++) {
      result.push(this._childType.read(reader, remainingDepth - 1));
    }
    return result;
  }

  /**
   * @inheritDoc
   */
  write(value, writer) {
    if (!(value instanceof Array))
      throw new XdrWriterError(`value is not array`);

    if (value.length > this._maxLength)
      throw new XdrWriterError(
        `got array of size ${value.length}, max allowed is ${this._maxLength}`
      );

    UnsignedInt.write(value.length, writer);
    for (const child of value) {
      this._childType.write(child, writer);
    }
  }

  /**
   * @inheritDoc
   */
  isValid(value) {
    if (!(value instanceof Array) || value.length > this._maxLength) {
      return false;
    }
    for (const child of value) {
      if (!this._childType.isValid(child)) return false;
    }
    return true;
  }
}
