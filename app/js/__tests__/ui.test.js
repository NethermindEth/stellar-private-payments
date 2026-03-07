// Mock WASM modules that bridge.js imports
jest.mock('../prover.js', () => require('../__mocks__/prover.js'), { virtual: true });
jest.mock('../witness/witness.js', () => require('../__mocks__/witness.js'), { virtual: true });

// Mock prover-client.js to avoid import.meta.url issues in test environment
jest.mock('../prover-client.js', () => require('../__mocks__/prover-client.js'), { virtual: true });

jest.mock('../wallet.js', () => ({
  __esModule: true,
  connectWallet: jest.fn(),
  getWalletNetwork: jest.fn(),
  signWalletMessage: jest.fn(),
}));

jest.mock('../stellar.js', () => ({
  __esModule: true,
  pingTestnet: jest.fn(async () => ({ success: true })),
  readAllContractStates: jest.fn(async () => ({ success: true })),
  getPoolEvents: jest.fn(async () => ({ success: true, events: [] })),
  formatAddress: jest.fn((addr) => addr),
  loadDeployedContracts: jest.fn(async () => ({
    pool: 'CPOOL',
    aspMembership: 'CMEMBER',
    aspNonMembership: 'CNONMEMBER',
  })),
  getDeployedContracts: jest.fn(() => null),
  validateWalletNetwork: jest.fn(),
}));

describe('ui module', () => {
  beforeEach(() => {
    jest.resetModules();
    jest.clearAllMocks();
    class WorkerStub {
      constructor() {
        this._onmessage = null;
        this._readySent = false;
      }

      set onmessage(handler) {
        this._onmessage = handler;
        if (!this._readySent) {
          this._readySent = true;
          Promise.resolve().then(() => {
            if (this._onmessage) {
              this._onmessage({ data: { type: 'READY' } });
            }
          });
        }
      }

      get onmessage() {
        return this._onmessage;
      }

      postMessage() {}
    }

    global.Worker = WorkerStub;
    global.document = {
      addEventListener: jest.fn(),
    };
  });

  test('registers a DOMContentLoaded handler on import', async () => {
    await import('../ui.js');

    expect(global.document.addEventListener).toHaveBeenCalledWith(
      'DOMContentLoaded',
      expect.any(Function)
    );
  });

  test('deriveKeysFromWallet derives and caches keys on first use', async () => {
    const { signWalletMessage } = await import('../wallet.js');
    const notesStore = {
      hasAuthenticatedKeys: jest.fn().mockReturnValue(false),
      getUserEncryptionKeypair: jest.fn(),
      getUserNoteKeypair: jest.fn(),
      setAuthenticatedKeys: jest.fn(),
    };

    jest.doMock('../state/index.js', () => ({
      __esModule: true,
      notesStore,
    }));

    jest.doMock('../bridge.js', () => ({
      __esModule: true,
      deriveNotePrivateKeyFromSignature: jest.fn((signature) => (
        new Uint8Array([signature[0], signature[1]])
      )),
      deriveEncryptionKeypairFromSignature: jest.fn((signature) => ({
        publicKey: new Uint8Array([signature[0], signature[1]]),
        privateKey: new Uint8Array([signature[2], signature[3]]),
      })),
      derivePublicKey: jest.fn((privateKey) => (
        new Uint8Array(Array.from(privateKey, (value) => value + 9))
      )),
    }));

    const base64FromBytes = (bytes) => Buffer.from(Uint8Array.from(bytes)).toString('base64');
    signWalletMessage
      .mockResolvedValueOnce({ signedMessage: base64FromBytes(new Array(64).fill(1)) })
      .mockResolvedValueOnce({ signedMessage: base64FromBytes(new Array(64).fill(2)) });

    const { deriveKeysFromWallet } = await import('../ui/core.js');
    const result = await deriveKeysFromWallet({});

    expect(signWalletMessage).toHaveBeenCalledTimes(2);
    expect(notesStore.setAuthenticatedKeys).toHaveBeenCalledTimes(1);
    expect(result.privKeyBytes).toEqual(new Uint8Array([1, 1]));
    expect(result.pubKeyBytes).toEqual(new Uint8Array([10, 10]));
    expect(result.encryptionKeypair).toEqual({
      publicKey: new Uint8Array([2, 2]),
      privateKey: new Uint8Array([2, 2]),
    });
  });

  test('deriveKeysFromWallet reuses cached keys for repeated calls on the same account', async () => {
    const { signWalletMessage } = await import('../wallet.js');
    const notesStore = {
      hasAuthenticatedKeys: jest.fn().mockReturnValue(true),
      getUserEncryptionKeypair: jest.fn().mockResolvedValue({
        publicKey: new Uint8Array([7, 8]),
        privateKey: new Uint8Array([9, 10]),
      }),
      getUserNoteKeypair: jest.fn().mockResolvedValue({
        privateKey: new Uint8Array([1, 2]),
        publicKey: new Uint8Array([3, 4]),
      }),
      setAuthenticatedKeys: jest.fn(),
    };

    jest.doMock('../state/index.js', () => ({
      __esModule: true,
      notesStore,
    }));

    jest.doMock('../bridge.js', () => ({
      __esModule: true,
      deriveNotePrivateKeyFromSignature: jest.fn(),
      deriveEncryptionKeypairFromSignature: jest.fn(),
      derivePublicKey: jest.fn(),
    }));

    const { deriveKeysFromWallet } = await import('../ui/core.js');
    const first = await deriveKeysFromWallet({});
    const second = await deriveKeysFromWallet({});

    expect(signWalletMessage).not.toHaveBeenCalled();
    expect(notesStore.getUserEncryptionKeypair).toHaveBeenCalledTimes(2);
    expect(notesStore.getUserNoteKeypair).toHaveBeenCalledTimes(2);
    expect(first).toEqual(second);
    expect(first).toEqual({
      privKeyBytes: new Uint8Array([1, 2]),
      pubKeyBytes: new Uint8Array([3, 4]),
      encryptionKeypair: {
        publicKey: new Uint8Array([7, 8]),
        privateKey: new Uint8Array([9, 10]),
      },
    });
  });
});
