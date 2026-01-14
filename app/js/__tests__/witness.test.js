jest.mock('../witness/witness_calculator.js', () => ({
  __esModule: true,
  default: jest.fn(),
}));

describe('witness helpers', () => {
  beforeEach(() => {
    jest.resetModules();
    jest.clearAllMocks();
  });

  test('bytesToWitness converts little-endian bytes to BigInt values', async () => {
    const { bytesToWitness } = await import('../witness/index.js');

    const bytes = new Uint8Array(64);
    bytes[0] = 1;
    bytes[32] = 2;

    expect(bytesToWitness(bytes)).toEqual([1n, 2n]);
  });

  test('bytesToWitness rejects non-multiple lengths', async () => {
    const { bytesToWitness } = await import('../witness/index.js');

    expect(() => bytesToWitness(new Uint8Array(10))).toThrow(
      'Witness bytes length 10 is not a multiple of 32'
    );
  });

  test('computeWitness throws before initialization', async () => {
    const { computeWitness } = await import('../witness/index.js');

    await expect(computeWitness({})).rejects.toThrow(
      'Witness calculator not initialized. Call initWitness() first.'
    );
  });
});
