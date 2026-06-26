import { XdrWriter } from '../../src/serialization/xdr-writer';
import { XdrReader } from '../../src/serialization/xdr-reader';
import { LargeInt } from '../../src/large-int';

// -- Inline 128-bit subclasses for testing the >64 bit LargeInt paths --

class Int128 extends LargeInt {
  constructor(...args) {
    super(args);
  }
  get size() {
    return 128;
  }
  get unsigned() {
    return false;
  }
}
Int128.defineIntBoundaries();

class UnsignedInt128 extends LargeInt {
  constructor(...args) {
    super(args);
  }
  get size() {
    return 128;
  }
  get unsigned() {
    return true;
  }
}
UnsignedInt128.defineIntBoundaries();

// ---------- Construction ----------

describe('Int128 construction', function () {
  it('constructs zero', function () {
    const val = new Int128(0n);
    expect(val.toBigInt()).to.eql(0n);
  });

  it('constructs positive values', function () {
    const val = new Int128(123456789012345678901234n);
    expect(val.toBigInt()).to.eql(123456789012345678901234n);
  });

  it('constructs negative values', function () {
    const val = new Int128(-42n);
    expect(val.toBigInt()).to.eql(-42n);
  });

  it('constructs from exact boundary values', function () {
    expect(() => new Int128(Int128.MAX_VALUE)).to.not.throw();
    expect(() => new Int128(Int128.MIN_VALUE)).to.not.throw();
    expect(new Int128(Int128.MAX_VALUE).toBigInt()).to.eql(Int128.MAX_VALUE);
    expect(new Int128(Int128.MIN_VALUE).toBigInt()).to.eql(Int128.MIN_VALUE);
  });

  it('constructs from two 64-bit chunks', function () {
    // low=1, high=2 => 2 * 2^64 + 1
    const val = new Int128(1n, 2n);
    expect(val.toBigInt()).to.eql(2n * 2n ** 64n + 1n);
  });

  it('constructs from four 32-bit chunks', function () {
    const val = new Int128(1n, 2n, 3n, 4n);
    expect(val.toBigInt()).to.eql((4n << 96n) | (3n << 64n) | (2n << 32n) | 1n);
  });
});

describe('UnsignedInt128 construction', function () {
  it('constructs zero', function () {
    const val = new UnsignedInt128(0n);
    expect(val.toBigInt()).to.eql(0n);
  });

  it('constructs max value', function () {
    const val = new UnsignedInt128(UnsignedInt128.MAX_VALUE);
    expect(val.toBigInt()).to.eql(2n ** 128n - 1n);
  });
});

// ---------- Overflow / Underflow ----------

describe('Int128 overflow/underflow', function () {
  it('throws when value exceeds i128 max', function () {
    const tooBig = 2n ** 127n; // one above MAX_VALUE
    expect(() => new Int128(tooBig)).to.throw(/out of range|does not fit/i);
  });

  it('throws when value is below i128 min', function () {
    const tooSmall = -(2n ** 127n) - 1n;
    expect(() => new Int128(tooSmall)).to.throw(/out of range|does not fit/i);
  });

  it('throws for a 300-bit bigint', function () {
    expect(() => new Int128(2n ** 300n)).to.throw(/out of range|does not fit/i);
  });
});

describe('UnsignedInt128 overflow/underflow', function () {
  it('throws when value exceeds u128 max', function () {
    const tooBig = 2n ** 128n;
    expect(() => new UnsignedInt128(tooBig)).to.throw(
      /out of range|does not fit/i
    );
  });

  it('throws for negative values', function () {
    expect(() => new UnsignedInt128(-1n)).to.throw(/positive/i);
  });
});

// ---------- Read / Write round-trip ----------

describe('Int128 read/write', function () {
  it('round-trips zero', function () {
    const original = new Int128(0n);
    const writer = new XdrWriter(16);
    Int128.write(original, writer);
    const reader = new XdrReader(writer.finalize());
    const decoded = Int128.read(reader);
    expect(decoded.toBigInt()).to.eql(0n);
  });

  it('round-trips positive values', function () {
    const value = 123456789012345678901234n;
    const original = new Int128(value);
    const writer = new XdrWriter(16);
    Int128.write(original, writer);
    const reader = new XdrReader(writer.finalize());
    const decoded = Int128.read(reader);
    expect(decoded.toBigInt()).to.eql(value);
  });

  it('round-trips negative values', function () {
    const value = -987654321098765432109876n;
    const original = new Int128(value);
    const writer = new XdrWriter(16);
    Int128.write(original, writer);
    const reader = new XdrReader(writer.finalize());
    const decoded = Int128.read(reader);
    expect(decoded.toBigInt()).to.eql(value);
  });

  it('round-trips max value', function () {
    const writer = new XdrWriter(16);
    Int128.write(new Int128(Int128.MAX_VALUE), writer);
    const reader = new XdrReader(writer.finalize());
    expect(Int128.read(reader).toBigInt()).to.eql(Int128.MAX_VALUE);
  });

  it('round-trips min value', function () {
    const writer = new XdrWriter(16);
    Int128.write(new Int128(Int128.MIN_VALUE), writer);
    const reader = new XdrReader(writer.finalize());
    expect(Int128.read(reader).toBigInt()).to.eql(Int128.MIN_VALUE);
  });
});

describe('UnsignedInt128 read/write', function () {
  it('round-trips zero', function () {
    const writer = new XdrWriter(16);
    UnsignedInt128.write(new UnsignedInt128(0n), writer);
    const reader = new XdrReader(writer.finalize());
    expect(UnsignedInt128.read(reader).toBigInt()).to.eql(0n);
  });

  it('round-trips max value', function () {
    const writer = new XdrWriter(16);
    UnsignedInt128.write(new UnsignedInt128(UnsignedInt128.MAX_VALUE), writer);
    const reader = new XdrReader(writer.finalize());
    expect(UnsignedInt128.read(reader).toBigInt()).to.eql(
      UnsignedInt128.MAX_VALUE
    );
  });
});

// ---------- isValid ----------

describe('Int128.isValid', function () {
  it('returns true for in-range bigint values', function () {
    expect(Int128.isValid(0n)).to.be.true;
    expect(Int128.isValid(-1n)).to.be.true;
    expect(Int128.isValid(Int128.MAX_VALUE)).to.be.true;
    expect(Int128.isValid(Int128.MIN_VALUE)).to.be.true;
  });

  it('returns false for out-of-range bigint values', function () {
    expect(Int128.isValid(2n ** 127n)).to.be.false;
    expect(Int128.isValid(-(2n ** 127n) - 1n)).to.be.false;
  });

  it('returns true for instances', function () {
    expect(Int128.isValid(new Int128(42n))).to.be.true;
  });

  it('returns false for non-bigint/non-instance values', function () {
    expect(Int128.isValid(42)).to.be.false;
    expect(Int128.isValid('42')).to.be.false;
    expect(Int128.isValid(null)).to.be.false;
  });
});

// ---------- toString / toJSON ----------

describe('Int128 serialization helpers', function () {
  it('toString returns decimal string', function () {
    const val = new Int128(-42n);
    expect(val.toString()).to.eql('-42');
  });

  it('toJSON returns object with string value', function () {
    const val = new Int128(999n);
    expect(val.toJSON()).to.eql({ _value: '999' });
  });
});
