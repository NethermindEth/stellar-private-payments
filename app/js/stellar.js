/**
 * https://developers.stellar.org/docs/build/guides/dapps/frontend-guide
 */
import { Horizon } from '@stellar/stellar-sdk';

// Initialize the server for Testnet
const server = new Horizon.Server('https://horizon-testnet.stellar.org');

export async function pingTestnet() {
  try {
    // Calling the root endpoint acts as a "ping"
    const response = await server.root();
    console.log('Successfully connected to Horizon!');
    console.log('Network Passphrase:', response.network_passphrase);
    console.log('Horizon Version:', response.horizon_version);
  } catch (error) {
    console.error('Connection failed:', error);
  }
}

