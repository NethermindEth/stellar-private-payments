import { Bool } from './bool';
import { NestedXdrType } from './xdr-type';

export class Option extends NestedXdrType {
  constructor(childType, maxDepth = NestedXdrType.DEFAULT_MAX_DEPTH) {
    super(maxDepth);
    this._childType = childType;
  }

  /**
   * @inheritDoc
   */
  read(reader, remainingDepth = this._maxDepth) {
    NestedXdrType.checkDepth(remainingDepth);
    if (Bool.read(reader)) {
      return this._childType.read(reader, remainingDepth - 1);
    }

    return undefined;
  }

  /**
   * @inheritDoc
   */
  write(value, writer) {
    const isPresent = value !== null && value !== undefined;

    Bool.write(isPresent, writer);

    if (isPresent) {
      this._childType.write(value, writer);
    }
  }

  /**
   * @inheritDoc
   */
  isValid(value) {
    if (value === null || value === undefined) {
      return true;
    }
    return this._childType.isValid(value);
  }
}
