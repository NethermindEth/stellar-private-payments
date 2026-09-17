// Another account signs and pays for the owner's notes. Freighter holds both
// the owner (account C) and account D; D is chosen in the app's picker and
// signs without Freighter switching to it. The deposit and the withdrawal
// back to the owner are each checked on-chain to come from D.

import { createLogger } from '../src/logger.mjs';
import { assert } from '../src/assert.mjs';
import { transactionSourceAccount } from '../src/chain.mjs';
import { waitForSyncedLedger } from '../src/indexer.mjs';
import { deposit, withdraw } from '../src/moveFunds.mjs';
import { gotoAdvanced, gotoMoveFlow, gotoMoveFunds } from '../src/navigation.mjs';
import { waitForNotesAfterIndexer } from '../src/notes.mjs';
import { driveWizard } from '../src/onboarding.mjs';

const log = createLogger('12-signing-account');

// Open the flow's confirmation, read it, and cancel: the helpers that submit
// confirm the dialog without looking at it.
async function readConfirmation(page, { submitSelector, title }) {
  await page.locator(submitSelector).click();
  const dialog = page.getByTestId('confirm-dialog').filter({ hasText: title });
  await dialog.waitFor({ state: 'visible', timeout: 15_000 });
  const text = await dialog.innerText();
  const warning = await dialog.getByTestId('confirm-dialog-warning').innerText().catch(() => '');
  await dialog.getByTestId('confirm-dialog-cancel').click();
  await dialog.waitFor({ state: 'hidden', timeout: 5_000 });
  return { text, warning };
}

export async function run(helpers) {
  const { page, context, waitForFreighterApproval, approveOrWatch } = helpers;
  const logTag = '12-signing-account';
  const rpcUrl = process.env.E2E_RPC_URL || 'https://soroban-testnet.stellar.org';
  const signer = process.env.E2E_ACCOUNT_D_ADDRESS;
  assert(signer, 'E2E_ACCOUNT_D_ADDRESS is not set -- source deployments/testnet/.e2e-accounts.env first');
  const expectedOwner = process.env.E2E_ACCOUNT_C_ADDRESS;
  assert(expectedOwner, 'E2E_ACCOUNT_C_ADDRESS is not set -- source deployments/testnet/.e2e-accounts.env first');

  await driveWizard(page, context, { waitForFreighterApproval, approveOrWatch, logTag });
  await gotoMoveFunds(page);

  const select = page.getByTestId('signing-account-select');
  const owner = await select.locator('option').first().getAttribute('value');
  assert(
    owner === expectedOwner,
    `expected account C to own the notes, not ${owner} -- rebuild the profile with e2e-freighter/scripts/setup.sh --force`,
  );

  await select.selectOption('__other__');
  await page.getByTestId('signing-account-input').fill(signer);
  await page.getByTestId('signing-account-use').click();
  assert((await select.inputValue()) === signer, 'account D was not selected to sign and pay');

  // Deposit paid by D into the owner's notes.
  await gotoMoveFlow(page, 'deposit');
  await page.locator('#deposit-amount').fill('0.01');
  const depositDialog = await readConfirmation(page, { submitSelector: '#btn-deposit', title: 'Confirm deposit' });
  assert(/Notes owned by/.test(depositDialog.text), 'deposit confirmation does not name the note owner');
  assert(/Signed and deposit paid by/.test(depositDialog.text), 'deposit confirmation does not name the paying account');

  const initialSync = await waitForSyncedLedger(page);
  const noteReady = waitForNotesAfterIndexer(page, {
    afterLedger: initialSync.ledger,
    notes: { minCount: 1 },
  });
  const depositResult = await deposit(helpers, { logTag, amount: '0.01', rpcUrl });
  const depositSource = await transactionSourceAccount(depositResult.transactionHash, { rpcUrl });
  assert(depositSource === signer, `deposit was sent by ${depositSource}, not account D`);
  log.info('deposit', depositResult.transactionHash.slice(0, 8), 'signed and paid by account D');

  await gotoAdvanced(page);
  const noteResult = await noteReady;
  assert(noteResult.notes.matchingNotes.length > 0, 'no deposited note was ready after indexer progress');

  // Withdrawal to the owner (blank recipient) signed by D links the two
  // accounts on-chain, and the confirmation says so.
  await gotoMoveFunds(page);
  await gotoMoveFlow(page, 'withdraw');
  assert((await select.inputValue()) === signer, 'the signing account did not stay on account D');
  await page.locator('#withdraw-recipient').fill('');
  await page.locator('#withdraw-amount').fill('0.01');
  const withdrawDialog = await readConfirmation(page, { submitSelector: '#btn-withdraw', title: 'Confirm withdrawal' });
  assert(/Signed and paid by/.test(withdrawDialog.text), 'withdrawal confirmation does not name the signing account');
  assert(/links the two accounts/.test(withdrawDialog.warning), 'withdrawal to the owner signed by D shows no linking warning');

  const withdrawResult = await withdraw(helpers, { logTag, amount: '0.01', rpcUrl, progressTimeoutMs: 180_000 });
  const withdrawSource = await transactionSourceAccount(withdrawResult.transactionHash, { rpcUrl });
  assert(withdrawSource === signer, `withdrawal was sent by ${withdrawSource}, not account D`);

  log.info(
    'OK: deposit', depositResult.transactionHash.slice(0, 8),
    'and withdrawal', withdrawResult.transactionHash.slice(0, 8),
    'signed and paid by account D for the owner\'s notes',
  );
}
