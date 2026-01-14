jest.mock('../witness/index.js', () => ({
  __esModule: true,
  initWitness: jest.fn(async () => {}),
  computeWitness: jest.fn(async () => new Uint8Array([1, 2, 3])),
  computeWitnessArray: jest.fn(async () => [1n, 2n]),
  getCircuitInfo: jest.fn(() => ({ witnessSize: 1 })),
  bytesToWitness: jest.fn(() => [1n]),
}));

function setupGlobals() {
  global.Response = class {
    constructor(body) {
      this._body = body;
    }

    async arrayBuffer() {
      if (this._body instanceof Uint8Array) {
        return this._body.buffer;
      }
      return this._body;
    }
  };

  global.caches = {
    open: jest.fn(async () => ({
      match: jest.fn(async () => null),
      put: jest.fn(async () => {}),
    })),
    delete: jest.fn(async () => true),
  };

  global.fetch = jest.fn(async (url) => {
    const isProvingKey = String(url).includes('proving_key');
    const bytes = isProvingKey
      ? new Uint8Array([1, 2])
      : new Uint8Array([3, 4]);

    return {
      ok: true,
      headers: { get: () => null },
      body: null,
      arrayBuffer: async () => bytes.buffer,
    };
  });
}

describe('bridge', () => {
  beforeEach(() => {
    jest.resetModules();
    jest.clearAllMocks();
    setupGlobals();
  });

  test('numberToField returns field bytes for a safe integer', async () => {
    const { numberToField } = await import('../bridge.js');

    expect(numberToField(5)).toEqual(new Uint8Array([11]));
  });

  test('numberToField rejects invalid values', async () => {
    const { numberToField } = await import('../bridge.js');

    expect(() => numberToField(-1)).toThrow('Value must be a non-negative safe integer');
    expect(() => numberToField(Number.MAX_SAFE_INTEGER + 1)).toThrow(
      'Value must be a non-negative safe integer'
    );
  });

  test('ensureProvingArtifacts downloads and returns bytes', async () => {
    const { ensureProvingArtifacts } = await import('../bridge.js');

    const { provingKey, r1cs } = await ensureProvingArtifacts();

    expect(provingKey).toEqual(new Uint8Array([1, 2]));
    expect(r1cs).toEqual(new Uint8Array([3, 4]));
  });

  test('generateWitness throws before initialization', async () => {
    const { generateWitness } = await import('../bridge.js');

    await expect(generateWitness({})).rejects.toThrow(
      'Witness module not initialized. Call initWitnessModule() first.'
    );
  });

  test('createMerkleTree returns a tree instance', async () => {
    const { createMerkleTree } = await import('../bridge.js');

    const tree = createMerkleTree(12);
    expect(tree.depth).toBe(12);
  });
});
