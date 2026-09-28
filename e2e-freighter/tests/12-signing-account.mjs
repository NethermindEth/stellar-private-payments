// Another account signs and pays for the owner's notes. Freighter holds both
// the owner (account C) and account D; D is chosen in the app's picker and
// signs without Freighter switching to it. Deposits must still come from C;
// withdrawals are checked on-chain to come from D.

import { createLogger } from '../src/logger.mjs';
import { assert } from '../src/assert.mjs';
import { transactionSourceAccount } from '../src/chain.mjs';
import { waitForSyncedLedger } from '../src/indexer.mjs';
import { deposit, withdraw, waitForToast } from '../src/moveFunds.mjs';
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
  await gotoMoveFlow(page, 'withdraw');

  const select = page.getByTestId('signing-account-select');
  const owner = await select.locator('option').filter({ hasText: 'Deposit account' }).getAttribute('value');
  assert(
    owner === expectedOwner,
    `expected account C to own the notes, not ${owner} -- rebuild the profile with e2e-freighter/scripts/setup.sh --force`,
  );

  assert((await select.inputValue()) === '', 'signer must start without a default');
  assert((await page.locator('#withdraw-recipient-select').inputValue()) === '', 'recipient must start empty');
  await select.selectOption('__other__');
  await page.getByTestId('signing-account-input').fill(signer);
  await page.getByTestId('signing-account-use').click();
  assert((await select.inputValue()) === signer, 'account D was not selected to sign and pay');

  // A previous selection of D must not affect deposits: C signs and pays.
  await gotoMoveFlow(page, 'deposit');
  assert(!(await select.isVisible()), 'deposit must not offer a signing account picker');
  await page.locator('#deposit-amount').fill('0.01');
  const depositDialog = await readConfirmation(page, { submitSelector: '#btn-deposit', title: 'Confirm deposit' });
  assert(!/Signed and deposit paid by/.test(depositDialog.text), 'deposit confirmation offers a separate paying account');

  const initialSync = await waitForSyncedLedger(page);
  const noteReady = waitForNotesAfterIndexer(page, {
    afterLedger: initialSync.ledger,
    notes: { minCount: 1 },
  });
  const depositResult = await deposit(helpers, { logTag, amount: '0.01', rpcUrl });
  const depositSource = await transactionSourceAccount(depositResult.transactionHash, { rpcUrl });
  assert(depositSource === owner, `deposit was sent by ${depositSource}, not the owner (account C)`);
  log.info('deposit', depositResult.transactionHash.slice(0, 8), 'signed and paid by account C');

  await gotoAdvanced(page);
  const noteResult = await noteReady;
  assert(noteResult.notes.matchingNotes.length > 0, 'no deposited note was ready after indexer progress');

  // Withdrawal to the owner warns about deposit-account reuse with either signer.
  await gotoMoveFunds(page);
  await gotoMoveFlow(page, 'withdraw');
  assert((await select.inputValue()) === signer, 'the signing account did not stay on account D');
  await page.locator('#withdraw-recipient-select').selectOption('');
  await page.locator('#withdraw-amount').fill('0.01');
  await select.selectOption(owner);
  await page.locator('#btn-withdraw').click();
  await waitForToast(page, { origin: 'withdraw', predicate: (toast) => /Choose a withdrawal recipient/.test(toast.message) });
  assert(!(await page.getByTestId('confirm-dialog').isVisible()), 'blank recipient opened confirmation');
  await page.locator('#withdraw-recipient-select').selectOption(owner);
  await select.selectOption('');
  await page.locator('#btn-withdraw').click();
  await waitForToast(page, { origin: 'withdraw', predicate: (toast) => /Choose an account to sign and pay with/.test(toast.message) });
  assert(!(await page.getByTestId('confirm-dialog').isVisible()), 'blank signer opened confirmation');
  await select.selectOption(owner);
  // Saved accounts can receive funds without pasting an address.
  assert(await page.getByTestId('signing-account-warning').isVisible(), 'deposit signer should show an immediate privacy warning');
  await page.locator('#withdraw-recipient-select').selectOption(signer);
  assert(!(await page.locator('#withdraw-recipient').isVisible()), 'saved recipient should not require an address input');
  const savedDialog = await readConfirmation(page, { submitSelector: '#btn-withdraw', title: 'Confirm withdrawal' });
  assert(/Signing with your deposit account/.test(savedDialog.warning), 'deposit signer needs a warning even with a different recipient');

  // A custom address still uses the same validation and privacy checks.
  await page.locator('#withdraw-recipient-select').selectOption('__other__');
  await page.locator('#withdraw-recipient').fill(owner);
  const ownerDialog = await readConfirmation(page, { submitSelector: '#btn-withdraw', title: 'Confirm withdrawal' });
  assert(ownerDialog.warning.startsWith('You are withdrawing to the same account used for deposits'), 'deposit-account reuse must be the first warning');
  assert(/withdraw to an unrelated account/.test(ownerDialog.warning), 'owner withdrawal needs recipient privacy guidance');
  assert(/Signing with your deposit account/.test(ownerDialog.warning), 'owner signing warning must still be included');
  await page.locator('#withdraw-recipient-select').selectOption(owner);
  await select.selectOption(signer);
  assert(!(await page.getByTestId('signing-account-warning').isVisible()), 'signer warning should clear when another account is selected');
  const withdrawDialog = await readConfirmation(page, { submitSelector: '#btn-withdraw', title: 'Confirm withdrawal' });
  assert(/Signed and paid by/.test(withdrawDialog.text), 'withdrawal confirmation does not name the signing account');
  assert(withdrawDialog.warning.startsWith('You are withdrawing to the same account used for deposits'), 'a different signer must still warn about the deposit recipient');
  assert(/withdraw to an unrelated account/.test(withdrawDialog.warning), 'different-signer withdrawal needs recipient privacy guidance');

  const withdrawResult = await withdraw(helpers, { logTag, amount: '0.01', rpcUrl, progressTimeoutMs: 180_000 });
  const withdrawSource = await transactionSourceAccount(withdrawResult.transactionHash, { rpcUrl });
  assert(withdrawSource === signer, `withdrawal was sent by ${withdrawSource}, not account D`);

  log.info(
    'OK: deposit', depositResult.transactionHash.slice(0, 8),
    'and withdrawal', withdrawResult.transactionHash.slice(0, 8),
    'signed by C and D respectively for the owner\'s notes',
  );
}
