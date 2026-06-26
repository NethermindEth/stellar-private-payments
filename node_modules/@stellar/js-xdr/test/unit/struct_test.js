import { XdrReader } from '../../src/serialization/xdr-reader';
import { XdrWriter } from '../../src/serialization/xdr-writer';
import { Struct } from '../../src/struct';

/* jshint -W030 */

let emptyContext = { definitions: {}, results: {} };
let MyRange = XDR.Struct.create(emptyContext, 'MyRange', [
  ['begin', XDR.Int],
  ['end', XDR.Int],
  ['inclusive', XDR.Bool]
]);

describe('Struct.read', function () {
  it('decodes correctly', function () {
    let empty = read([
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ]);
    expect(empty).to.be.instanceof(MyRange);
    expect(empty.begin()).to.eql(0);
    expect(empty.end()).to.eql(0);
    expect(empty.inclusive()).to.eql(false);

    let filled = read([
      0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x01
    ]);
    expect(filled).to.be.instanceof(MyRange);
    expect(filled.begin()).to.eql(5);
    expect(filled.end()).to.eql(255);
    expect(filled.inclusive()).to.eql(true);
  });

  function read(bytes) {
    let io = new XdrReader(bytes);
    return MyRange.read(io);
  }
});

describe('Struct.read maxDepth', function () {
  let context;

  beforeEach(function () {
    context = { definitions: {}, results: {} };
  });

  it('throws when depth exceeds maxDepth', function () {
    const MyStruct = XDR.Struct.create(context, 'DepthStruct', [
      ['value', XDR.Int]
    ]);
    MyStruct._maxDepth = 2;

    const bytes = [0x00, 0x00, 0x00, 0x05];
    const reader = new XdrReader(bytes);

    expect(() => MyStruct.read(reader, -1)).to.throw(
      /exceeded max decoding depth.*/i
    );
  });

  it('succeeds when depth is within maxDepth', function () {
    const MyStruct = XDR.Struct.create(context, 'DepthStruct2', [
      ['value', XDR.Int]
    ]);
    MyStruct._maxDepth = 5;

    const bytes = [0x00, 0x00, 0x00, 0x05];
    const reader = new XdrReader(bytes);

    const result = MyStruct.read(reader, 4);
    expect(result.value()).to.eql(5);
  });

  it('uses default maxDepth of 200 from create', function () {
    const MyStruct = XDR.Struct.create(context, 'DepthStruct3', [
      ['value', XDR.Int]
    ]);
    expect(MyStruct._maxDepth).to.eql(200);

    const bytes = [0x00, 0x00, 0x00, 0x05];
    const reader = new XdrReader(bytes);

    expect(() => MyStruct.read(reader, -1)).to.throw(
      /exceeded max decoding depth.*/i
    );
  });

  it('uses maxDepth provided by create', function () {
    const MyStruct = XDR.Struct.create(
      context,
      'DepthStruct3',
      [['value', XDR.Int]],
      300
    );
    expect(MyStruct._maxDepth).to.eql(300);
    const bytes = [0x00, 0x00, 0x00, 0x05];
    const reader = new XdrReader(bytes);

    expect(() => MyStruct.read(reader, -1)).to.throw(
      /exceeded max decoding depth.*/i
    );
  });

  it('propagates depth to child fields', function () {
    const stringArray = new XDR.VarArray(new XDR.String(100), 10, 3);
    const MyStruct = XDR.Struct.create(context, 'NestedStruct', [
      ['names', stringArray]
    ]);

    const bytes = [
      0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x48, 0x69, 0x00, 0x00
    ];
    const reader = new XdrReader(bytes);

    const result = MyStruct.read(reader, 1);
    expect(result.names().length).to.eql(1);
    expect(result.names()[0].toString('utf8')).to.eql('Hi');
  });

  it('uses struct maxDepth for nested field decoding', function () {
    const innerArray = new XDR.VarArray(XDR.Int, 10, 1);
    const outerArray = new XDR.VarArray(innerArray, 10, 5);
    const MyStruct = XDR.Struct.create(
      context,
      'NestedDepthStruct',
      [['values', outerArray]],
      5
    );

    const bytes = [
      0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x2a
    ];
    const reader = new XdrReader(bytes);

    const result = MyStruct.read(reader, 2);
    expect(result.values()).to.eql([[42]]);
  });
});

describe('Struct.write', function () {
  it('encodes correctly', function () {
    let empty = new MyRange({
      begin: 0,
      end: 0,
      inclusive: false
    });

    expect(write(empty)).to.eql([
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ]);

    let filled = new MyRange({
      begin: 5,
      end: 255,
      inclusive: true
    });

    expect(write(filled)).to.eql([
      0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x01
    ]);
  });

  it('throws a write error if the value is not the correct type', function () {
    expect(() => write(null)).to.throw(/write error/i);
    expect(() => write(undefined)).to.throw(/write error/i);
    expect(() => write([])).to.throw(/write error/i);
    expect(() => write({})).to.throw(/write error/i);
    expect(() => write(1)).to.throw(/write error/i);
    expect(() => write(true)).to.throw(/write error/i);
  });

  it('throws a write error if the struct is not valid', function () {
    expect(() => write(new MyRange({}))).to.throw(/write error/i);
  });

  function write(value) {
    let io = new XdrWriter(256);
    MyRange.write(value, io);
    return io.toArray();
  }
});

describe('Struct.isValid', function () {
  it('returns true for instances of the struct', function () {
    expect(MyRange.isValid(new MyRange({}))).to.be.true;
  });

  it('works for "struct-like" objects', function () {
    class FakeStruct extends Struct {}

    FakeStruct.structName = 'MyRange';
    let r = new FakeStruct();
    expect(MyRange.isValid(r)).to.be.true;

    FakeStruct.structName = 'NotMyRange';
    r = new FakeStruct();
    expect(MyRange.isValid(r)).to.be.false;
  });

  it('returns false for anything else', function () {
    expect(MyRange.isValid(null)).to.be.false;
    expect(MyRange.isValid(undefined)).to.be.false;
    expect(MyRange.isValid([])).to.be.false;
    expect(MyRange.isValid({})).to.be.false;
    expect(MyRange.isValid(1)).to.be.false;
    expect(MyRange.isValid(true)).to.be.false;
  });
});

describe('Struct.validateXDR', function () {
  it('returns true for valid XDRs', function () {
    let subject = new MyRange({ begin: 5, end: 255, inclusive: true });
    expect(MyRange.validateXDR(subject.toXDR())).to.be.true;
    expect(MyRange.validateXDR(subject.toXDR('hex'), 'hex')).to.be.true;
    expect(MyRange.validateXDR(subject.toXDR('base64'), 'base64')).to.be.true;
  });

  it('returns false for invalid XDRs', function () {
    expect(MyRange.validateXDR(Buffer.alloc(1))).to.be.false;
    expect(MyRange.validateXDR('00', 'hex')).to.be.false;
    expect(MyRange.validateXDR('AA==', 'base64')).to.be.false;
  });
});

describe('Struct: attributes', function () {
  it('properly retrieves attributes', function () {
    let subject = new MyRange({ begin: 5, end: 255, inclusive: true });
    expect(subject.begin()).to.eql(5);
  });

  it('properly sets attributes', function () {
    let subject = new MyRange({ begin: 5, end: 255, inclusive: true });
    expect(subject.begin(10)).to.eql(10);
    expect(subject.begin()).to.eql(10);
  });
});

describe('Struct: constructor maxDepth', function () {
  it('inherits maxDepth from the struct class when omitted', function () {
    let context = { definitions: {}, results: {} };
    let DepthStruct = XDR.Struct.create(
      context,
      'CtorDepthStruct',
      [['value', XDR.Int]],
      9
    );

    expect(new DepthStruct({ value: 1 })._maxDepth).to.eql(9);

    DepthStruct._maxDepth = 4;
    expect(new DepthStruct({ value: 2 })._maxDepth).to.eql(4);
  });
});
