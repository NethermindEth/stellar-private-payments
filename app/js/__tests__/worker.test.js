jest.mock('../bridge.js', () => ({
  __esModule: true,
  configure: jest.fn(),
  initProverWasm: jest.fn(async () => {}),
  initWitnessModule: jest.fn(async () => ({ witnessSize: 1 })),
  initProver: jest.fn(async () => ({ version: 'mock' })),
  init: jest.fn(async () => ({ version: 'mock' })),
  isProvingCached: jest.fn(async () => false),
  clearCache: jest.fn(async () => {}),
  generateWitness: jest.fn(async () => new Uint8Array([1])),
  generateProofBytes: jest.fn(() => new Uint8Array([2])),
  extractPublicInputs: jest.fn(() => new Uint8Array([3])),
  verifyProofLocal: jest.fn(() => true),
  getVerifyingKey: jest.fn(() => new Uint8Array([4])),
  getCircuitInfo: jest.fn(() => ({ witnessSize: 1 })),
  derivePublicKey: jest.fn(() => new Uint8Array([5, 6])),
  derivePublicKeyHex: jest.fn(() => '0xdeadbeef'),
  computeCommitment: jest.fn(() => new Uint8Array([7])),
}));

describe('worker', () => {
  beforeEach(() => {
    jest.resetModules();
    jest.clearAllMocks();
    global.self = {
      postMessage: jest.fn(),
      onmessage: null,
    };
  });

  test('posts READY when the worker loads', async () => {
    await import('../worker.js');

    expect(global.self.postMessage).toHaveBeenCalledWith({ type: 'READY' });
  });

  test('responds to PING with state', async () => {
    await import('../worker.js');

    await global.self.onmessage({
      data: { type: 'PING', messageId: 'm1' },
    });

    expect(global.self.postMessage).toHaveBeenCalledWith({
      type: 'PING',
      messageId: 'm1',
      success: true,
      ready: false,
      state: {
        modulesReady: false,
        witnessReady: false,
        proverReady: false,
      },
    });
  });

  test('derives public key bytes on request', async () => {
    await import('../worker.js');

    await global.self.onmessage({
      data: {
        type: 'DERIVE_PUBLIC_KEY',
        messageId: 'm2',
        data: { privateKey: [1, 2, 3], asHex: false },
      },
    });

    expect(global.self.postMessage).toHaveBeenCalledWith({
      type: 'DERIVE_PUBLIC_KEY',
      messageId: 'm2',
      success: true,
      publicKey: [5, 6],
    });
  });

  test('returns error when verifying without prover', async () => {
    await import('../worker.js');

    await global.self.onmessage({
      data: {
        type: 'VERIFY',
        messageId: 'm3',
        data: { proofBytes: [], publicInputsBytes: [] },
      },
    });

    expect(global.self.postMessage).toHaveBeenCalledWith({
      type: 'VERIFY',
      messageId: 'm3',
      success: false,
      error: 'Prover not initialized',
    });
  });
});
