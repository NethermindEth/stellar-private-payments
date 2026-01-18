jest.mock('../wallet.js', () => ({
  __esModule: true,
  connectWallet: jest.fn(),
  getWalletNetwork: jest.fn(),
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
});
