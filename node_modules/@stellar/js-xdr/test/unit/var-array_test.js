import { XdrReader } from '../../src/serialization/xdr-reader';
import { XdrWriter } from '../../src/serialization/xdr-writer';

const subject = new XDR.VarArray(XDR.Int, 2);

describe('VarArray#read', function () {
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
    expect(read([0x00, 0x00, 0x00, 0x00])).to.eql([]);

    expect(read([0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00])).to.eql([0]);
    expect(read([0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01])).to.eql([1]);

    expect(
      read([
        0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
      ])
    ).to.eql([0, 1]);
    expect(
      read([
        0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01
      ])
    ).to.eql([1, 1]);
  });

  it('throws read error when the encoded array is too large', function () {
    expect(() => read([0x00, 0x00, 0x00, 0x03])).to.throw(/read error/i);
  });

  it('fast-fails when declared length cannot fit remaining bytes for fixed-size child', function () {
    const { FixedSizeChild, getCalls } = createFixedSizeChild();

    const arr = new XDR.VarArray(FixedSizeChild, 10);
    const io = new XdrReader([0x00, 0x00, 0x00, 0x02]);
    const remainingAfterLengthPrefix = io.remainingBytes() - 4;

    expect(() => arr.read(io)).to.throw(
      new RegExp(`exceeds remaining ${remainingAfterLengthPrefix} bytes`, 'i')
    );
    expect(getCalls()).to.eql(0);
  });

  it('decodes on exact-fit payload and reads each child once', function () {
    const { FixedSizeChild, getCalls } = createFixedSizeChild();

    const arr = new XDR.VarArray(FixedSizeChild, 10);
    const io = new XdrReader([
      0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02
    ]);

    expect(arr.read(io)).to.eql([1, 2]);
    expect(getCalls()).to.eql(2);
  });

  it('checks maxLength before insufficient-bytes fast-fail', function () {
    const { FixedSizeChild, getCalls } = createFixedSizeChild();

    const arr = new XDR.VarArray(FixedSizeChild, 1);
    const io = new XdrReader([0x00, 0x00, 0x00, 0x02]);

    expect(() => arr.read(io)).to.throw(/max allowed/i);
    expect(getCalls()).to.eql(0);
  });

  it('consumes only the 4-byte length prefix on VarArray insufficient-bytes fast-fail', function () {
    const { FixedSizeChild } = createFixedSizeChild();

    const arr = new XDR.VarArray(FixedSizeChild, 10);
    const io = new XdrReader([0x00, 0x00, 0x00, 0x02]);
    const before = io.remainingBytes();
    const remainingAfterLengthPrefix = io.remainingBytes() - 4;

    expect(() => arr.read(io)).to.throw(
      new RegExp(`exceeds remaining ${remainingAfterLengthPrefix} bytes`, 'i')
    );
    expect(before - io.remainingBytes()).to.eql(4);
  });

  function read(bytes) {
    let io = new XdrReader(bytes);
    return subject.read(io);
  }
});

describe('VarArray#read maxDepth', function () {
  it('throws when depth exceeds maxDepth', function () {
    const varArrayType = new XDR.VarArray(XDR.Int, 10, 2);
    const bytes = [0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05];
    const reader = new XdrReader(bytes);

    expect(() => varArrayType.read(reader, -1)).to.throw(
      /exceeded max decoding depth.*/i
    );
  });

  it('succeeds when depth is within maxDepth', function () {
    const varArrayType = new XDR.VarArray(XDR.Int, 10, 5);
    const bytes = [
      0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x0a
    ];
    const reader = new XdrReader(bytes);

    const result = varArrayType.read(reader, 4);
    expect(result).to.eql([5, 10]);
  });

  it('uses default maxDepth of 200', function () {
    const varArrayType = new XDR.VarArray(XDR.Int, 10);
    const bytes = [0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05];
    const reader = new XdrReader(bytes);

    expect(varArrayType._maxDepth).to.equal(200);
    expect(() => varArrayType.read(reader, -1)).to.throw(
      /exceeded max decoding depth.*/i
    );
  });

  it('uses the root maxDepth for child types', function () {
    const innerArray = new XDR.VarArray(XDR.Int, 10, 2);
    const outerArray = new XDR.VarArray(innerArray, 10, 5);
    const bytes = [
      0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01
    ];
    const reader = new XdrReader(bytes);

    const result = outerArray.read(reader, 2);
    expect(result).to.eql([[1]]);
  });

  it('VarArray containing Strings respects depth', function () {
    const stringType = new XDR.String(100);
    const arrayOfStrings = new XDR.VarArray(stringType, 10, 3);

    const bytes = [
      0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x41, 0x00, 0x00, 0x00
    ];
    const reader = new XdrReader(bytes);

    const result = arrayOfStrings.read(reader, 2);
    expect(result.length).to.eql(1);
    expect(result[0].toString('utf8')).to.eql('A');
  });

  it('deeply nested VarArrays read at appropriate depth', function () {
    const level3 = new XDR.VarArray(XDR.Int, 10, 4);
    const level2 = new XDR.VarArray(level3, 10, 4);
    const level1 = new XDR.VarArray(level2, 10, 4);

    const bytes = [
      0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x01
    ];
    const reader = new XdrReader(bytes);

    const result = level1.read(reader, 2);
    expect(result).to.eql([[[1]]]);
  });

  it('deeply nested VarArrays throw when depth exceeds limit', function () {
    const level3 = new XDR.VarArray(XDR.Int, 10, 2);
    const level2 = new XDR.VarArray(level3, 10, 2);
    const level1 = new XDR.VarArray(level2, 10, 2);

    const bytes = [
      0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x01
    ];
    const reader = new XdrReader(bytes);

    expect(() => level1.read(reader, 1)).to.throw(
      /exceeded max decoding depth.*/i
    );
  });
});

describe('VarArray#write', function () {
  it('encodes correctly', function () {
    expect(write([])).to.eql([0x00, 0x00, 0x00, 0x00]);
    expect(write([0])).to.eql([0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
    expect(write([0, 1])).to.eql([
      0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    ]);
  });

  it('throws a write error if the value is too large', function () {
    expect(() => write([1, 2, 3])).to.throw(/write error/i);
  });

  it('throws a write error if a child element is of the wrong type', function () {
    expect(() => write([1, null])).to.throw(/write error/i);
    expect(() => write([1, undefined])).to.throw(/write error/i);
    expect(() => write([1, 'hi'])).to.throw(/write error/i);
  });

  function write(value) {
    let io = new XdrWriter(256);
    subject.write(value, io);
    return io.toArray();
  }
});

describe('VarArray#isValid', function () {
  it('returns true for an array of the correct sizes with the correct types', function () {
    expect(subject.isValid([])).to.be.true;
    expect(subject.isValid([1])).to.be.true;
    expect(subject.isValid([1, 2])).to.be.true;
  });

  it('returns false for arrays of the wrong size', function () {
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

describe('VarArray#constructor', function () {
  let subject = new XDR.VarArray(XDR.Int);

  it('defaults to max length of a uint max value', function () {
    expect(subject._maxLength).to.eql(Math.pow(2, 32) - 1);
  });
});
