// app/js/__tests__/bridge.test.js

jest.mock('../prover.js', () => require('../__mocks__/prover.js'), { virtual: true });
jest.mock('../witness/witness.js', () => require('../__mocks__/witness.js'), { virtual: true });

function setupGlobals() {
  global.Response = class {
    constructor(body, _init) {
      this._body = body;
    }
    async arrayBuffer() {
      if (this._body instanceof Uint8Array) return this._body.buffer;
      return this._body;
    }
  };

  const cacheStore = new Map();

  global.caches = {
    open: jest.fn(async () => ({
      match: jest.fn(async (url) => {
        const bytes = cacheStore.get(String(url));
        if (!bytes) return null;
        return { arrayBuffer: async () => bytes.buffer };
      }),
      put: jest.fn(async (url, response) => {
        const ab = await response.arrayBuffer();
        cacheStore.set(String(url), new Uint8Array(ab));
      }),
    })),
    delete: jest.fn(async () => {
      cacheStore.clear();     // ✅ IMPORTANT
      return true;
    }),
  };

  global.fetch = jest.fn(async () => ({
    ok: true,
    status: 200,
    headers: { get: () => null },
    body: null,
    arrayBuffer: async () => new Uint8Array([9, 9, 9]).buffer,
  }));

  return { cacheStore };
}


describe('bridge', () => {
  beforeEach(() => {
    jest.resetModules();
    jest.clearAllMocks();
    setupGlobals();
  });

  test('numberToField returns bytes for safe integer', async () => {
    const { numberToField } = await import('../bridge.js');
    expect(numberToField(5)).toEqual(new Uint8Array([11])); // from prover mock
  });

  test('numberToField rejects invalid values', async () => {
    const { numberToField } = await import('../bridge.js');

    expect(() => numberToField(-1)).toThrow('Value must be a non-negative safe integer');
    expect(() => numberToField(Number.MAX_SAFE_INTEGER + 1)).toThrow(
        'Value must be a non-negative safe integer'
    );
  });

  test('createMerkleTree returns a tree instance with correct depth', async () => {
    const { createMerkleTree } = await import('../bridge.js');
    const tree = createMerkleTree(12);
    expect(tree.depth).toBe(12);
  });

  test('generateWitness throws before witness is initialized', async () => {
    const { generateWitness } = await import('../bridge.js');
    await expect(generateWitness({ a: 1 })).rejects.toThrow(
        'Witness module not initialized. Call initWitnessModule() first.'
    );
  });

  test('generateProof throws before prover is initialized', async () => {
    const { generateProof } = await import('../bridge.js');
    expect(() => generateProof(new Uint8Array([1]))).toThrow(
        'Prover not initialized. Call initProver() first.'
    );
  });

  test('bytesToWitness converts little-endian 32-byte elements into BigInt array', async () => {
    const { bytesToWitness } = await import('../bridge.js');

    const bytes = new Uint8Array(32);
    bytes[0] = 1; // little-endian => 1n
    expect(bytesToWitness(bytes)).toEqual([1n]);
  });

  test('bytesToWitness rejects lengths not multiple of 32', async () => {
    const { bytesToWitness } = await import('../bridge.js');
    expect(() => bytesToWitness(new Uint8Array(31))).toThrow('is not a multiple of 32');
  });

  test('ensureProvingArtifacts downloads proving key + r1cs and caches them', async () => {
    const { ensureProvingArtifacts } = await import('../bridge.js');

    global.fetch.mockImplementation(async (url) => {
      const u = String(url);
      const bytes =
          u.includes('proving_key') ? new Uint8Array([1, 2]) :
              u.includes('.r1cs') ? new Uint8Array([3, 4]) :
                  new Uint8Array([9]);

      return {
        ok: true,
        status: 200,
        headers: { get: () => null },
        body: null,
        arrayBuffer: async () => bytes.buffer,
      };
    });

    const first = await ensureProvingArtifacts();
    expect(first.provingKey).toEqual(new Uint8Array([1, 2]));
    expect(first.r1cs).toEqual(new Uint8Array([3, 4]));

    // second call should use in-memory cachedProvingKey/cachedR1cs (no more fetch calls)
    const calls = global.fetch.mock.calls.length;
    const second = await ensureProvingArtifacts();
    expect(second.provingKey).toEqual(new Uint8Array([1, 2]));
    expect(second.r1cs).toEqual(new Uint8Array([3, 4]));
    expect(global.fetch.mock.calls.length).toBe(calls);
  });

  test('clearCache resets cached state', async () => {
    const { ensureProvingArtifacts, clearCache } = await import('../bridge.js');

    global.fetch.mockImplementation(async (url) => {
      const u = String(url);
      const bytes =
          u.includes('proving_key') ? new Uint8Array([1, 2]) :
              u.includes('.r1cs') ? new Uint8Array([3, 4]) :
                  new Uint8Array([9]);

      return {
        ok: true,
        status: 200,
        headers: { get: () => null },
        body: null,
        arrayBuffer: async () => bytes.buffer,
      };
    });

    await ensureProvingArtifacts();
    await clearCache();

    // After clearCache, ensureProvingArtifacts should fetch again (since in-memory cache reset)
    const before = global.fetch.mock.calls.length;
    await ensureProvingArtifacts();
    const after = global.fetch.mock.calls.length;

    expect(after).toBeGreaterThan(before);
  });
});
