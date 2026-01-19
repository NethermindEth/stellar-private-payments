import {
  connectWallet,
  getWalletNetwork,
  signWalletAuthEntry,
  signWalletTransaction,
} from '../wallet.js';
import {
  getNetworkDetails,
  isAllowed,
  isConnected,
  requestAccess,
  setAllowed,
  signAuthEntry,
  signTransaction,
} from '@stellar/freighter-api';

jest.mock('@stellar/freighter-api', () => ({
  getNetworkDetails: jest.fn(),
  isAllowed: jest.fn(),
  isConnected: jest.fn(),
  requestAccess: jest.fn(),
  setAllowed: jest.fn(),
  signAuthEntry: jest.fn(),
  signTransaction: jest.fn(),
}));

beforeEach(() => {
  isConnected.mockResolvedValue({ isConnected: true });
  isAllowed.mockResolvedValue({ isAllowed: true });
  setAllowed.mockResolvedValue({ isAllowed: true });
  requestAccess.mockResolvedValue({ address: 'GABC' });
  getNetworkDetails.mockResolvedValue({
    network: 'testnet',
    networkUrl: 'https://example.org',
    networkPassphrase: 'passphrase',
    sorobanRpcUrl: 'https://rpc.example.org',
  });
  signTransaction.mockResolvedValue({
    signedTxXdr: 'signed-xdr',
    signerAddress: 'GABC',
  });
  signAuthEntry.mockResolvedValue({
    signedAuthEntry: 'signed-auth',
    signerAddress: 'GABC',
  });
});

describe('wallet', () => {
  test('connectWallet returns the requested address', async () => {
    await expect(connectWallet()).resolves.toBe('GABC');
    expect(isConnected).toHaveBeenCalledTimes(1);
    expect(isAllowed).toHaveBeenCalledTimes(1);
    expect(setAllowed).not.toHaveBeenCalled();
    expect(requestAccess).toHaveBeenCalledTimes(1);
  });

  test('connectWallet requests allow-list access when not allowed', async () => {
    isAllowed.mockResolvedValue({ isAllowed: false });

    await expect(connectWallet()).resolves.toBe('GABC');
    expect(setAllowed).toHaveBeenCalledTimes(1);
    expect(requestAccess).toHaveBeenCalledTimes(1);
  });

  test('connectWallet throws when Freighter is not detected', async () => {
    isConnected.mockResolvedValue({ isConnected: false });

    await expect(connectWallet()).rejects.toThrow('Freighter not detected');
    expect(isAllowed).not.toHaveBeenCalled();
  });

  test('connectWallet normalizes connection errors', async () => {
    isConnected.mockResolvedValue({ error: { message: 'User denied access' } });

    await expect(connectWallet()).rejects.toMatchObject({
      code: 'USER_REJECTED',
      message: 'User denied access',
    });
  });

  test('connectWallet throws on allow-list errors', async () => {
    isAllowed.mockResolvedValue({ error: { message: 'Allow-list failed' } });

    await expect(connectWallet()).rejects.toMatchObject({
      code: 'WALLET_ERROR',
      message: 'Allow-list failed',
    });
  });

  test('connectWallet marks rejected allow-list requests', async () => {
    isAllowed.mockResolvedValue({ isAllowed: false });
    setAllowed.mockResolvedValue({ error: { message: 'Rejected by user' } });

    await expect(connectWallet()).rejects.toMatchObject({
      code: 'USER_REJECTED',
      message: 'Rejected by user',
    });
  });

  test('connectWallet surfaces access request errors', async () => {
    requestAccess.mockResolvedValue({ error: { message: 'Access declined' } });

    await expect(connectWallet()).rejects.toMatchObject({
      code: 'USER_REJECTED',
      message: 'Access declined',
    });
  });

  test('connectWallet requires a public key', async () => {
    requestAccess.mockResolvedValue({});

    await expect(connectWallet()).rejects.toThrow('No public key returned');
  });

  test('getWalletNetwork returns the freighter network details', async () => {
    await expect(getWalletNetwork()).resolves.toEqual({
      network: 'testnet',
      networkUrl: 'https://example.org',
      networkPassphrase: 'passphrase',
      sorobanRpcUrl: 'https://rpc.example.org',
    });
  });

  test('getWalletNetwork throws on freighter errors', async () => {
    getNetworkDetails.mockResolvedValue({ error: { message: 'Network error' } });

    await expect(getWalletNetwork()).rejects.toMatchObject({
      code: 'WALLET_ERROR',
      message: 'Network error',
    });
  });

  test('signWalletTransaction signs without requesting an address', async () => {
    isAllowed.mockResolvedValue({ isAllowed: false });

    await expect(signWalletTransaction('xdr')).resolves.toEqual({
      signedTxXdr: 'signed-xdr',
      signerAddress: 'GABC',
    });
    expect(setAllowed).toHaveBeenCalledTimes(1);
    expect(requestAccess).not.toHaveBeenCalled();
    expect(signTransaction).toHaveBeenCalledWith('xdr', {});
  });

  test('signWalletTransaction throws on signing errors', async () => {
    signTransaction.mockResolvedValue({ error: { message: 'Signature failed' } });

    await expect(signWalletTransaction('xdr')).rejects.toMatchObject({
      code: 'WALLET_ERROR',
      message: 'Signature failed',
    });
  });

  test('signWalletAuthEntry returns the signed auth entry', async () => {
    await expect(signWalletAuthEntry('entry-xdr')).resolves.toEqual({
      signedAuthEntry: 'signed-auth',
      signerAddress: 'GABC',
    });
  });

  test('signWalletAuthEntry marks rejected signatures', async () => {
    signAuthEntry.mockResolvedValue({ error: { message: 'User rejected signature' } });

    await expect(signWalletAuthEntry('entry-xdr')).rejects.toMatchObject({
      code: 'USER_REJECTED',
      message: 'User rejected signature',
    });
  });
});
