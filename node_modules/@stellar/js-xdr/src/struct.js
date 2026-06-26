import { Reference } from './reference';
import { NestedXdrType, isSerializableIsh } from './xdr-type';
import { XdrWriterError } from './errors';

export class Struct extends NestedXdrType {
  constructor(attributes, maxDepth) {
    const resolvedMaxDepth = maxDepth ?? new.target?._maxDepth;
    super(resolvedMaxDepth);
    this._attributes = attributes || {};
  }

  /**
   * @inheritDoc
   */
  static read(reader, remainingDepth = this._maxDepth) {
    NestedXdrType.checkDepth(remainingDepth);

    const attributes = {};
    for (const [fieldName, type] of this._fields) {
      attributes[fieldName] = type.read(reader, remainingDepth - 1);
    }
    return new this(attributes, this._maxDepth);
  }

  /**
   * @inheritDoc
   */
  static write(value, writer) {
    if (!this.isValid(value)) {
      throw new XdrWriterError(
        `${value} has struct name ${value?.constructor?.structName}, not ${
          this.structName
        }: ${JSON.stringify(value)}`
      );
    }

    for (const [fieldName, type] of this._fields) {
      const attribute = value._attributes[fieldName];
      type.write(attribute, writer);
    }
  }

  /**
   * @inheritDoc
   */
  static isValid(value) {
    return (
      value?.constructor?.structName === this.structName ||
      isSerializableIsh(value, this)
    );
  }

  static create(
    context,
    name,
    fields,
    maxDepth = NestedXdrType.DEFAULT_MAX_DEPTH
  ) {
    const ChildStruct = class extends Struct {};

    ChildStruct.structName = name;
    ChildStruct._maxDepth = maxDepth;
    context.results[name] = ChildStruct;

    const mappedFields = new Array(fields.length);
    for (let i = 0; i < fields.length; i++) {
      const fieldDescriptor = fields[i];
      const fieldName = fieldDescriptor[0];
      let field = fieldDescriptor[1];
      if (field instanceof Reference) {
        field = field.resolve(context);
      }
      mappedFields[i] = [fieldName, field];
      // create accessors
      ChildStruct.prototype[fieldName] = createAccessorMethod(fieldName);
    }

    ChildStruct._fields = mappedFields;

    return ChildStruct;
  }
}

function createAccessorMethod(name) {
  return function readOrWriteAttribute(value) {
    if (value !== undefined) {
      this._attributes[name] = value;
    }
    return this._attributes[name];
  };
}
