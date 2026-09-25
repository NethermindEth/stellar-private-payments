// Ephemeral per-test accounts against the local network: generate, fund via
// friendbot, and (for accounts Freighter never signs for, i.e. passive
// transfer recipients) register public keys through the app's own SDK
// bundle, driven with a local secret-key signer instead of Freighter.

import { createHash } from 'node:crypto';
import { Keypair, TransactionBuilder } from '@stellar/stellar-sdk';
import { chromium } from 'playwright';
import { CHROMIUM_PATH, requireAppUrl } from './env.mjs';

export const FRIENDBOT_URL = 'http://localhost:8000/friendbot';
export const RPC_URL = 'http://localhost:8000/rpc';
export const NETWORK_PASSPHRASE = 'Standalone Network ; February 2017';

export function createAccount() {
  return Keypair.random();
}

export async function fund(keypair) {
  const res = await fetch(`${FRIENDBOT_URL}?addr=${keypair.publicKey()}`);
  if (!res.ok) throw new Error(`friendbot funding failed for ${keypair.publicKey()}`);
}

// Exposes page-context bridges to sign with `keypair` via the app's
// WalletSigner interface — Freighter is one implementation, this is another.
// Wrap signatures in a real Buffer before toString('hex'/'base64'): a bare
// Uint8Array silently ignores the encoding argument.
async function exposeSigner(page, keypair) {
  const address = keypair.publicKey();
  const signTxName = `__spp_sign_tx_${address}`;
  const signMsgName = `__spp_sign_msg_${address}`;
  const signAuthName = `__spp_sign_auth_${address}`;
  await page.exposeFunction(signTxName, (xdr, networkPassphrase) => {
    const tx = TransactionBuilder.fromXDR(xdr, networkPassphrase);
    tx.sign(keypair);
    return { signedTxXdr: tx.toXDR() };
  });
  await page.exposeFunction(signMsgName, (message) => {
    // SEP-53: sign SHA-256("Stellar Signed Message:\n" + message), not the
    // raw message — key derivation verifies against this exact scheme.
    const digest = createHash('sha256').update(`Stellar Signed Message:\n${message}`).digest();
    return { signedMessage: Buffer.from(keypair.sign(digest)).toString('base64') };
  });
  await page.exposeFunction(signAuthName, (preimageXdrBase64) => {
    const hash = createHash('sha256').update(Buffer.from(preimageXdrBase64, 'base64')).digest();
    return { signedAuthEntry: Buffer.from(keypair.sign(hash)).toString('hex') };
  });
  return { signTxName, signMsgName, signAuthName };
}

// A second, fully separate storage partition used only to register passive
// recipients' public keys. OPFS storage is exclusive per partition, not just
// per page, and the connected page's own partition keeps its storage open
// (with live sync and UI state) for the whole test — so registering through
// that page's storage isn't possible without tearing it down. An ordinary
// isolated browser context gets its own OPFS pool — no profile directory or
// extension needed, unlike the connected page's context — and can register
// recipients at any point in the test, concurrently with the connected app.
let isolatedBrowser;
let isolatedPage;

async function getIsolatedPage() {
  if (isolatedPage) return isolatedPage;
  isolatedBrowser = await chromium.launch({ headless: true, executablePath: CHROMIUM_PATH });
  const context = await isolatedBrowser.newContext();
  isolatedPage = await context.newPage();
  await isolatedPage.goto(requireAppUrl());
  await isolatedPage.waitForLoadState('domcontentloaded');
  return isolatedPage;
}

// Closes the isolated recipient-registration browser, if one was opened.
// Call once at the end of a test run.
export async function closeIsolatedRegistration() {
  if (isolatedBrowser) {
    await isolatedBrowser.close();
    isolatedBrowser = null;
    isolatedPage = null;
  }
}

// Registers `keypair`'s public keys, in the isolated recipient context.
export async function register(keypair) {
  const address = keypair.publicKey();
  const page = await getIsolatedPage();
  const { signTxName, signMsgName, signAuthName } = await exposeSigner(page, keypair);

  await page.evaluate(
    async ({ address, signTxName, signMsgName, signAuthName, rpcUrl, networkPassphrase }) => {
      const { default: init, Client, Storage } = await import('stellar-private-payments');
      await init();
      const contractConfig = await fetch('./deployments.json').then((r) => r.json());
      const circuitsBaseUrl = new URL(
        './js/stellar-private-payments/dist/circuits/',
        window.location.href,
      ).href;
      // This one profile registers every recipient for the whole test run,
      // so its storage handle is opened once and forked for each recipient,
      // the same way the app's own client does for its concurrent consumers.
      if (!window.__recipientStorage) window.__recipientStorage = await Storage.open();
      const client = await Client.new({
        rpcUrl,
        contractConfig,
        circuitsBaseUrl,
        storage: window.__recipientStorage.fork(),
      });
      const signer = {
        getPublicKey: async () => address,
        signTransaction: async (xdr, opts) => window[signTxName](xdr, opts.networkPassphrase),
        signMessage: async (message) => window[signMsgName](message),
        signAuthEntry: async (xdr) => window[signAuthName](xdr),
      };
      const account = await client.account({ userAddress: address, networkPassphrase }, signer);
      await account.derivePrivacyKeys();
      await account.registerPublicKeys();
    },
    {
      address,
      signTxName,
      signMsgName,
      signAuthName,
      rpcUrl: RPC_URL,
      networkPassphrase: NETWORK_PASSPHRASE,
    },
  );
}

// Creates, funds, and registers a passive recipient — one never connected to
// Freighter, only ever looked up by address.
export async function createRegisteredAccount() {
  const account = createAccount();
  await fund(account);
  await register(account);
  return account;
}

// Pre-seeds the app-level state its onboarding wizard gates on (disclaimer,
// retention/bootnode, explorer, storage-persist-prompted, keys+registration),
// so the driver account skips the wizard instead of re-running it every test.
//
// Deliberately self-contained rather than reusing register()'s Client: OPFS
// storage is exclusive per origin, so a second Storage.open() while an
// earlier one is still live fails with "Another tab or window is using this
// app's local database" — confirmed live. One client, one storage handle.
export async function seedDriverOnboarding(page, keypair) {
  const address = keypair.publicKey();
  const { signTxName, signMsgName, signAuthName } = await exposeSigner(page, keypair);

  await page.evaluate(
    async ({ address, signTxName, signMsgName, signAuthName, rpcUrl, networkPassphrase }) => {
      const { default: init, Client, Storage } = await import('stellar-private-payments');
      await init();
      const contractConfig = await fetch('./deployments.json').then((r) => r.json());
      const circuitsBaseUrl = new URL(
        './js/stellar-private-payments/dist/circuits/',
        window.location.href,
      ).href;
      const storage = await Storage.open();
      const client = await Client.new({ rpcUrl, contractConfig, circuitsBaseUrl, storage });
      const signer = {
        getPublicKey: async () => address,
        signTransaction: async (xdr, opts) => window[signTxName](xdr, opts.networkPassphrase),
        signMessage: async (message) => window[signMsgName](message),
        signAuthEntry: async (xdr) => window[signAuthName](xdr),
      };
      const account = await client.account({ userAddress: address, networkPassphrase }, signer);
      await account.derivePrivacyKeys();
      await account.registerPublicKeys();

      const call = (request) => storage.call(request, 5_000);
      const disclaimerState = (await call({ DisclaimerState: address })).DisclaimerState;
      await call({ AcceptDisclaimer: [address, disclaimerState?.disclaimerHashHex || ''] });
      await call({
        SetSetting: { key: 'bootnode_config', value_json: JSON.stringify({ enabled: false, url: '' }) },
      });
      await call({
        SetSetting: {
          key: 'explorer',
          value_json: JSON.stringify({ baseUrl: 'https://stellar.expert/explorer/testnet' }),
        },
      });
      try {
        await navigator.storage.persist();
      } catch {
        // best-effort; the prompted flag below is what the gate actually needs
      }
      window.localStorage.setItem('poolstellar_storage_persist_prompted', '1');

      // Release the OPFS handle before this page closes (see
      // wasm-facade.js's installStoragePauseOnUnload for the same fix).
      await call('Pause');
    },
    {
      address,
      signTxName,
      signMsgName,
      signAuthName,
      rpcUrl: RPC_URL,
      networkPassphrase: NETWORK_PASSPHRASE,
    },
  );
}
