jest.mock('@stellar/stellar-sdk', () => ({
  Horizon: { Server: class { constructor(url) { this.url = url; } } },
  rpc: { Server: class { constructor(url) { this.url = url; } } },
  Networks: {
    TESTNET: 'Test SDF Network ; September 2015',
    FUTURENET: 'Test SDF Future Network ; October 2022',
    PUBLIC: 'Public Global Stellar Network ; September 2015',
  },
  Address: {
    fromScAddress: jest.fn(() => ({ toString: () => 'GMOCK' })),
  },
  xdr: {},
  scValToNative: jest.fn(),
}));

import { formatAddress, validateWalletNetwork } from '../stellar.js';

describe('stellar helpers', () => {
  test('formatAddress leaves short addresses intact', () => {
    expect(formatAddress('GABC')).toBe('GABC');
  });

  test('formatAddress truncates long addresses', () => {
    const address = 'G'.repeat(56);
    expect(formatAddress(address)).toBe(`${address.slice(0, 4)}...${address.slice(-4)}`);
  });

  test('validateWalletNetwork accepts the supported network', () => {
    expect(() => validateWalletNetwork('TESTNET')).not.toThrow();
  });

  test('validateWalletNetwork rejects unsupported networks', () => {
    expect(() => validateWalletNetwork('futurenet')).toThrow(/Network mismatch/);
  });
});
