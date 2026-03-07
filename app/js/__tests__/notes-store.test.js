const base64FromBytes = (bytes) => Buffer.from(Uint8Array.from(bytes)).toString('base64');

describe('notes-store issue regression coverage', () => {
  let notesStore;
  let userNotes;
  let signWalletMessage;

  beforeEach(async () => {
    jest.resetModules();
    userNotes = new Map();
    signWalletMessage = jest.fn().mockResolvedValue({
      signedMessage: base64FromBytes(new Array(64).fill(9)),
    });

    jest.doMock('../state/db.js', () => ({
      __esModule: true,
      get: jest.fn(async (_storeName, key) => userNotes.get(key)),
      getAll: jest.fn(async () => Array.from(userNotes.values())),
      getAllByIndex: jest.fn(async (_storeName, indexName, value) => {
        if (indexName !== 'by_owner') {
          return [];
        }
        return Array.from(userNotes.values()).filter((note) => note.owner === value);
      }),
      put: jest.fn(async (_storeName, value) => {
        userNotes.set(value.id, { ...value });
        return value.id;
      }),
      del: jest.fn(async (_storeName, key) => {
        userNotes.delete(key);
      }),
      clear: jest.fn(async () => {
        userNotes.clear();
      }),
    }));

    jest.doMock('../wallet.js', () => ({
      __esModule: true,
      signWalletMessage,
    }));

    jest.doMock('../bridge.js', () => ({
      __esModule: true,
      deriveEncryptionKeypairFromSignature: jest.fn((signature) => ({
        publicKey: new Uint8Array([signature[0], signature[1]]),
        privateKey: new Uint8Array([signature[2], signature[3]]),
      })),
      deriveNotePrivateKeyFromSignature: jest.fn((signature) => (
        new Uint8Array([signature[0], signature[1]])
      )),
      derivePublicKey: jest.fn((privateKey) => (
        new Uint8Array(Array.from(privateKey, (value) => value + 10))
      )),
    }));

    jest.doMock('../state/crypto.js', () => ({
      __esModule: true,
      deriveStorageKey: jest.fn(async (privateKeyBytes) => (
        `storage:${Array.from(privateKeyBytes).join(',')}`
      )),
      encryptField: jest.fn(async (hexValue, aesKey) => `enc(${aesKey})::${hexValue}`),
      decryptField: jest.fn(async (encryptedValue) => encryptedValue.split('::')[1]),
    }));

    notesStore = await import('../state/notes-store.js');
  });

  test('saveNote encrypts secrets at rest and returns plaintext to callers', async () => {
    notesStore.handleAccountChange('GA111');
    notesStore.setAuthenticatedKeys({
      encryptionKeypair: {
        publicKey: new Uint8Array([1, 2]),
        privateKey: new Uint8Array([3, 4]),
      },
      notePrivateKey: new Uint8Array([5, 6]),
      notePublicKey: new Uint8Array([7, 8]),
    });

    const saved = await notesStore.saveNote({
      commitment: '0x0001',
      privateKey: '0x0011',
      blinding: '0x0022',
      amount: 5,
      leafIndex: 9,
      ledger: 12,
    });

    expect(saved.privateKey).toBe('0x0011');
    expect(saved.blinding).toBe('0x0022');

    const raw = userNotes.get('0x0001');
    expect(raw.privateKey).toBe('enc(storage:3,4)::0x0011');
    expect(raw.blinding).toBe('enc(storage:3,4)::0x0022');
    expect(raw.encrypted).toBe(true);
  });

  test('getNotes redacts encrypted secrets when the active account has no cached keys', async () => {
    notesStore.handleAccountChange('GA111');
    notesStore.setAuthenticatedKeys({
      encryptionKeypair: {
        publicKey: new Uint8Array([1, 2]),
        privateKey: new Uint8Array([3, 4]),
      },
      notePrivateKey: new Uint8Array([5, 6]),
      notePublicKey: new Uint8Array([7, 8]),
    });

    await notesStore.saveNote({
      commitment: '0x0002',
      privateKey: '0x00aa',
      blinding: '0x00bb',
      amount: 7,
      leafIndex: 11,
      ledger: 13,
    });

    notesStore.clearKeypairCaches();

    const notes = await notesStore.getNotes();

    expect(notes).toHaveLength(1);
    expect(notes[0].privateKey).toBeNull();
    expect(notes[0].blinding).toBeNull();
    expect(notes[0].amount).toBe('7');
  });

  test('exportNotes rejects when encrypted notes exist but no storage key is available', async () => {
    notesStore.handleAccountChange('GA111');
    notesStore.setAuthenticatedKeys({
      encryptionKeypair: {
        publicKey: new Uint8Array([1, 2]),
        privateKey: new Uint8Array([3, 4]),
      },
      notePrivateKey: new Uint8Array([5, 6]),
      notePublicKey: new Uint8Array([7, 8]),
    });

    await notesStore.saveNote({
      commitment: '0x0003',
      privateKey: '0x00cc',
      blinding: '0x00dd',
      amount: 9,
      leafIndex: 14,
      ledger: 15,
    });

    notesStore.clearKeypairCaches();

    await expect(notesStore.exportNotes()).rejects.toThrow('Cannot export');
  });

  test('importNotes rejects when the active account has no storage key', async () => {
    notesStore.handleAccountChange('GA111');

    const file = {
      text: async () => JSON.stringify({
        version: 1,
        notes: [{
          id: '0x0010',
          owner: 'GA111',
          privateKey: '0x0011',
          blinding: '0x0012',
          amount: '3',
          leafIndex: 2,
          createdAt: '2026-03-07T00:00:00.000Z',
          createdAtLedger: 22,
          spent: false,
          isReceived: false,
        }],
      }),
    };

    await expect(notesStore.importNotes(file)).rejects.toThrow('Cannot import notes');
  });

  test('preserves cached keys per account across A to B to A switches', async () => {
    const accountAKeys = {
      encryptionKeypair: {
        publicKey: new Uint8Array([11, 12]),
        privateKey: new Uint8Array([13, 14]),
      },
      notePrivateKey: new Uint8Array([15, 16]),
      notePublicKey: new Uint8Array([17, 18]),
    };
    const accountBKeys = {
      encryptionKeypair: {
        publicKey: new Uint8Array([21, 22]),
        privateKey: new Uint8Array([23, 24]),
      },
      notePrivateKey: new Uint8Array([25, 26]),
      notePublicKey: new Uint8Array([27, 28]),
    };

    notesStore.handleAccountChange('GA111');
    notesStore.setAuthenticatedKeys(accountAKeys);

    notesStore.handleAccountChange('GB222');
    notesStore.setAuthenticatedKeys(accountBKeys);

    signWalletMessage.mockClear();

    notesStore.handleAccountChange('GA111');

    expect(notesStore.hasAuthenticatedKeys()).toBe(true);
    await expect(notesStore.getUserEncryptionKeypair()).resolves.toEqual(accountAKeys.encryptionKeypair);
    await expect(notesStore.getUserNoteKeypair()).resolves.toEqual({
      privateKey: accountAKeys.notePrivateKey,
      publicKey: accountAKeys.notePublicKey,
    });
    expect(signWalletMessage).not.toHaveBeenCalled();
  });

  test('clears all account caches on disconnect', async () => {
    notesStore.handleAccountChange('GA111');
    notesStore.setAuthenticatedKeys({
      encryptionKeypair: {
        publicKey: new Uint8Array([11, 12]),
        privateKey: new Uint8Array([13, 14]),
      },
      notePrivateKey: new Uint8Array([15, 16]),
      notePublicKey: new Uint8Array([17, 18]),
    });

    notesStore.handleAccountChange(null);
    notesStore.handleAccountChange('GA111');

    expect(notesStore.hasAuthenticatedKeys()).toBe(false);
  });
});
