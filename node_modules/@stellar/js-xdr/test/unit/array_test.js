import { XdrReader } from '../../src/serialization/xdr-reader';
import { XdrWriter } from '../../src/serialization/xdr-writer';

let zero = new XDR.Array(XDR.Int, 0);
let one = new XDR.Array(XDR.Int, 1);
let many = new XDR.Array(XDR.Int, 2);

describe('Array#read', function () {
  function createFixedSizeChild() {
    let calls = 0;

    return {
      FixedSizeChild: class FixedSizeChild {
        static read(io) {
          calls += 1;
          return io.readInt32BE();
        }

        static write() {}

        static isValid() {
          return true;
        }
      },
      getCalls() {
        return calls;
      }
    };
  }

  it('decodes correctly', function () {
    expect(read(zero, [])).to.eql([]);
    expect(read(zero, [0x00, 0x00, 0x00, 0x00])).to.eql([]);

    expect(read(one, [0x00, 0x00, 0x00, 0x00])).to.eql([0]);
    expect(read(one, [0x00, 0x00, 0x00, 0x01])).to.eql([1]);

    expect(read(many, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01])).to.eql(
      [0, 1]
    );
    expect(read(many, [0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01])).to.eql(
      [1, 1]
    );
  });

  it("throws XdrReaderError when the byte stream isn't large enough", function () {
    expect(() => read(many, [0x00, 0x00, 0x00, 0x00])).to.throw(
      /(read outside the boundary|insufficient bytes)/i
    );
  });

  it('fast-fails before decoding child elements when remaining bytes are insufficient', function () {
    const { FixedSizeChild, getCalls } = createFixedSizeChild();

    const fixed = new XDR.Array(FixedSizeChild, 5);
    const reader = new XdrReader([0x00, 0x00, 0x00, 0x01]);
    expect(() => fixed.read(reader)).to.throw(
      new RegExp(`exceeds remaining ${reader.remainingBytes()} bytes`, 'i')
    );
    expect(getCalls()).to.eql(0);
  });

  it('decodes on exact-fit byte length and reads each child exactly once', function () {
    const { FixedSizeChild, getCalls } = createFixedSizeChild();

    const fixed = new XDR.Array(FixedSizeChild, 2);
    const reader = new XdrReader([
      0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02
    ]);

    expect(fixed.read(reader)).to.eql([1, 2]);
    expect(getCalls()).to.eql(2);
  });

  it('zero-length array does not decode child elements', function () {
    const { FixedSizeChild, getCalls } = createFixedSizeChild();

    const fixed = new XDR.Array(FixedSizeChild, 0);
    const reader = new XdrReader([0x01, 0x02, 0x03, 0x04]);

    expect(fixed.read(reader)).to.eql([]);
    expect(getCalls()).to.eql(0);
  });

  it('keeps reader position unchanged on Array fast-fail', function () {
    const { FixedSizeChild } = createFixedSizeChild();

    const fixed = new XDR.Array(FixedSizeChild, 3);
    const reader = new XdrReader([0x00, 0x00]);
    const before = reader.remainingBytes();

    expect(() => fixed.read(reader)).to.throw(
      new RegExp(`exceeds remaining ${reader.remainingBytes()} bytes`, 'i')
    );
    expect(reader.remainingBytes()).to.eql(before);
  });

  function read(arr, bytes) {
    let reader = new XdrReader(bytes);
    return arr.read(reader);
  }
});

describe('Array#read maxDepth', function () {
  it('throws when depth exceeds maxDepth', function () {
    const arrayType = new XDR.Array(XDR.Int, 2, 2);
    const bytes = [0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x0a];
    const reader = new XdrReader(bytes);

    expect(() => arrayType.read(reader, -1)).to.throw(
      /exceeded max decoding depth.*/i
    );
  });

  it('succeeds when depth is within maxDepth', function () {
    const arrayType = new XDR.Array(XDR.Int, 2, 5);
    const bytes = [0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x0a];
    const reader = new XdrReader(bytes);

    const result = arrayType.read(reader, 4);
    expect(result).to.eql([5, 10]);
  });

  it('uses default maxDepth of 200', function () {
    const arrayType = new XDR.Array(XDR.Int, 2);
    const bytes = [0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x0a];
    const reader = new XdrReader(bytes);

    expect(arrayType._maxDepth).to.equal(200);
    expect(() => arrayType.read(reader, -1)).to.throw(
      /exceeded max decoding depth.*/i
    );
  });

  it('uses the root maxDepth for nested arrays', function () {
    const innerArray = new XDR.Array(XDR.Int, 1, 2);
    const outerArray = new XDR.Array(innerArray, 1, 5);
    const bytes = [0x00, 0x00, 0x00, 0x2a];
    const reader = new XdrReader(bytes);

    const result = outerArray.read(reader, 2);
    expect(result).to.eql([[42]]);
  });
});

describe('Array#write', function () {
  let subject = many;

  it('encodes correctly', function () {
    expect(write([1, 2])).to.eql([
      0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02
    ]);
    expect(write([3, 4])).to.eql([
      0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04
    ]);
  });

  it('throws a write error if the value is not the correct length', function () {
    expect(() => write(null)).to.throw(/write error/i);
    expect(() => write(undefined)).to.throw(/write error/i);
    expect(() => write([])).to.throw(/write error/i);
    expect(() => write([1])).to.throw(/write error/i);
    expect(() => write([1, 2, 3])).to.throw(/write error/i);
  });

  it('throws a write error if a child element is of the wrong type', function () {
    expect(() => write([1, null])).to.throw(/write error/i);
    expect(() => write([1, undefined])).to.throw(/write error/i);
    expect(() => write([1, 'hi'])).to.throw(/write error/i);
  });

  function write(value) {
    let writer = new XdrWriter(8);
    subject.write(value, writer);
    return writer.toArray();
  }
});

describe('Array#isValid', function () {
  let subject = many;

  it('returns true for an array of the correct size with the correct types', function () {
    expect(subject.isValid([1, 2])).to.be.true;
  });

  it('returns false for arrays of the wrong size', function () {
    expect(subject.isValid([])).to.be.false;
    expect(subject.isValid([1])).to.be.false;
    expect(subject.isValid([1, 2, 3])).to.be.false;
  });

  it('returns false if a child element is invalid for the child type', function () {
    expect(subject.isValid([1, null])).to.be.false;
    expect(subject.isValid([1, undefined])).to.be.false;
    expect(subject.isValid([1, 'hello'])).to.be.false;
    expect(subject.isValid([1, []])).to.be.false;
    expect(subject.isValid([1, {}])).to.be.false;
  });
});
