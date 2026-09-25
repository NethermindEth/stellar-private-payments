// Another account signs and pays for the owner's notes. Freighter holds the
// owner (the connected driver) and a second ephemeral signer, chosen in the
// app's picker; deposits still come from the owner, withdrawals from the signer.

import { createLogger } from '../src/logger.mjs';
import { assert } from '../src/assert.mjs';
import { transactionSourceAccount } from '../src/chain.mjs';
import { waitForSyncedLedger } from '../src/indexer.mjs';
import { deposit, withdraw, waitForToast } from '../src/moveFunds.mjs';
import { gotoAdvanced, gotoMoveFlow, gotoMoveFunds } from '../src/navigation.mjs';
import { waitForNotesAfterIndexer } from '../src/notes.mjs';
import { driveWizard } from '../src/onboarding.mjs';
import { RPC_URL, createAccount, fund } from '../src/testAccount.mjs';
import { importAdditionalAccount, selectFreighterAccount } from '../src/wallet.mjs';

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

// Import a second account and connect it once, so Freighter grants the site
// access to sign with it later (it won't sign for an unconnected account).
// The app's remembered note owner must not change as a side effect.
async function importAndConnectSigner(context, appUrl, owner) {
  const signerAccount = createAccount();
  await fund(signerAccount);
  await importAdditionalAccount(context, signerAccount.secret());

  const page = await context.newPage();
  await page.goto(appUrl);
  await page.waitForLoadState('domcontentloaded');
  if (await page.locator('#onboarding-close-btn').isVisible().catch(() => false)) {
    await page.locator('#onboarding-close-btn').click();
  }
  await page.locator('#wallet-btn').waitFor({ state: 'visible', timeout: 15_000 });
  const remembered = await page.evaluate(() => localStorage.getItem('poolstellar_note_owner'));
  if (remembered !== owner) {
    throw new Error(`connecting the signer account changed the app's note owner to ${remembered || '(none)'}`);
  }
  await page.close();

  await selectFreighterAccount(context, owner);
  return signerAccount;
}

export async function run(helpers) {
  const { page, context, driver, waitForFreighterApproval, approveOrWatch } = helpers;
  const logTag = '12-signing-account';
  const rpcUrl = RPC_URL;
  const owner = driver.publicKey();

  await driveWizard(page, context, { waitForFreighterApproval, approveOrWatch, logTag });

  const signerAccount = await importAndConnectSigner(context, page.url(), owner);
  const signer = signerAccount.publicKey();

  await gotoMoveFunds(page);
  await gotoMoveFlow(page, 'withdraw');

  const select = page.getByTestId('signing-account-select');
  const pickedOwner = await select.locator('option').filter({ hasText: 'Deposit account' }).getAttribute('value');
  assert(pickedOwner === owner, `expected the driver account to own the notes, not ${pickedOwner}`);

  assert((await select.inputValue()) === '', 'signer must start without a default');
  assert((await page.locator('#withdraw-recipient-select').inputValue()) === '', 'recipient must start empty');
  await select.selectOption('__other__');
  await page.getByTestId('signing-account-input').fill(signer);
  await page.getByTestId('signing-account-use').click();
  assert((await select.inputValue()) === signer, 'the signer account was not selected to sign and pay');

  // A previous selection of the signer must not affect deposits: the owner
  // signs and pays.
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
  assert(depositSource === owner, `deposit was sent by ${depositSource}, not the owner`);
  log.info('deposit', depositResult.transactionHash.slice(0, 8), 'signed and paid by the owner');

  await gotoAdvanced(page);
  const noteResult = await noteReady;
  assert(noteResult.notes.matchingNotes.length > 0, 'no deposited note was ready after indexer progress');

  // Withdrawal to the owner warns about deposit-account reuse with either signer.
  await gotoMoveFunds(page);
  await gotoMoveFlow(page, 'withdraw');
  assert((await select.inputValue()) === signer, 'the signing account did not stay on the signer account');
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
  assert(withdrawSource === signer, `withdrawal was sent by ${withdrawSource}, not the signer account`);

  log.info(
    'OK: deposit', depositResult.transactionHash.slice(0, 8),
    'and withdrawal', withdrawResult.transactionHash.slice(0, 8),
    'signed by the owner and signer respectively for the owner\'s notes',
  );
}
