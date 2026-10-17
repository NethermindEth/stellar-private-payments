// Failure-mode battery for the money flows. Each negative path proves its
// specific pre-signing failure and then finishes with a real successful
// deposit to ensure no failure left the app in a poisoned state.

import { StrKey } from '@stellar/stellar-sdk';
import { createLogger } from '../src/logger.mjs';
import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { promisify } from 'node:util';
import { assert } from '../src/assert.mjs';
import { waitForSyncedLedger } from '../src/indexer.mjs';
import {
  deposit,
  waitForOperationIdle,
  waitForRecipientLookup,
  waitForRecipientLookupReset,
  waitForToast,
} from '../src/moveFunds.mjs';
import { gotoMoveFlow, gotoMoveFunds } from '../src/navigation.mjs';
import { waitForNotesAfterIndexer } from '../src/notes.mjs';
import { driveWizard } from '../src/onboarding.mjs';
import { expectNoFreighterApproval } from '../src/wallet.mjs';
import { waitForCondition } from '../src/waits.mjs';
import { RPC_URL, createRegisteredAccount } from '../src/testAccount.mjs';

const log = createLogger('11-failure-modes');
const APPROVAL_KINDS = ['signMessage', 'signAuthEntry', 'signTransaction'];
const execFileAsync = promisify(execFile);
// ScVal::LedgerKeyContractInstance. Both pool contract variants keep
// MaximumDepositAmount and Fee in the instance entry's storage map, each under
// a key such as ScVal::Vec([ScVal::Symbol("MaximumDepositAmount")]).
const CONTRACT_INSTANCE_KEY_XDR = 'AAAAFA==';
const LOCAL_PASSPHRASE = 'Standalone Network ; February 2017';

async function readInstanceAmount(poolContractId, rpcUrl, name) {
  const { stdout } = await execFileAsync('stellar', [
    'contract', 'read',
    '--id', poolContractId,
    '--key-xdr', CONTRACT_INSTANCE_KEY_XDR,
    '--rpc-url', rpcUrl,
    '--network-passphrase', LOCAL_PASSPHRASE,
    '--output', 'json',
  ]);
  // One CSV row: the key, the entry as JSON with every quote doubled, and two
  // ledger numbers.
  const json = stdout
    .slice(stdout.indexOf(',"') + 2)
    .replace(/",\d+,\d+\s*$/, '')
    .replaceAll('""', '"');
  const entry = (JSON.parse(json).contract_instance.storage ?? [])
    .find(({ key }) => key.vec?.[0]?.symbol === name);
  if (!entry) throw new Error(`could not read ${name} from ${poolContractId}`);
  return BigInt(entry.val.u256 ?? entry.val.i128);
}

function stroopsToDecimal(stroops) {
  const whole = stroops / 10_000_000n;
  const fraction = String(stroops % 10_000_000n).padStart(7, '0');
  return `${whole}.${fraction}`;
}

function randomUnregisteredAddress() {
  return StrKey.encodeEd25519PublicKey(randomBytes(32));
}

async function confirmOperation(page, title) {
  const dialog = page.getByTestId('confirm-dialog').filter({ hasText: title });
  await dialog.waitFor({ state: 'visible', timeout: 10_000 });
  await dialog.getByTestId('confirm-dialog-confirm').click();
}

async function assertNoApproval(context, label) {
  await expectNoFreighterApproval(context, APPROVAL_KINDS, { timeoutMs: 5_000 });
  log.info(`${label}: no Freighter approval appeared (pre-signing failure confirmed)`);
}

export async function run(helpers) {
  const { page, context, waitForAnyFreighterApproval, waitForFreighterApproval, approveOrWatch } = helpers;
  const logTag = '11-failure-modes';
  const rpcUrl = RPC_URL;

  const recipientAccount = await createRegisteredAccount();
  const recipient = recipientAccount.publicKey();

  await driveWizard(page, context, { waitForFreighterApproval, approveOrWatch, logTag });
  await gotoMoveFunds(page);

  const initialSync = await waitForSyncedLedger(page);
  const noteReady = waitForNotesAfterIndexer(page, {
    afterLedger: initialSync.ledger,
    notes: { minCount: 1 },
  });
  const baseline = await deposit(helpers, { logTag, amount: '0.01', rpcUrl });
  await noteReady;
  log.info('baseline deposit', baseline.transactionHash.slice(0, 8), 'is indexed and ready for negative planner paths');

  // Far above every funded test account's private balance, while remaining a
  // valid decimal amount. Coin selection must fail locally before signing.
  const overAmount = '1000000';
  const unregisteredAddress = randomUnregisteredAddress();

  // (1) Over-withdraw: planner rejects the amount before signing.
  await gotoMoveFlow(page, 'withdraw');
  const signingSelect = page.getByTestId('signing-account-select');
  const owner = await signingSelect.locator('option').filter({ hasText: 'Deposit account' }).getAttribute('value');
  assert(owner && owner !== recipient, 'expected a connected owner distinct from the recipient');
  await signingSelect.selectOption(owner);
  await page.locator('#withdraw-recipient-select').selectOption(owner);
  await page.locator('#withdraw-amount').fill(overAmount);
  await page.locator('#btn-withdraw').click();
  await confirmOperation(page, 'Confirm withdrawal');
  const overWithdraw = await waitForToast(page, {
    origin: 'withdraw',
    predicate: (toast) => /^withdraw failed/i.test(toast.message) && /no combination of notes/i.test(toast.message),
  });
  await assertNoApproval(context, 'over-withdraw');
  await waitForOperationIdle(page, { submitSelector: '#btn-withdraw' });
  log.info('(1) over-withdraw:', overWithdraw.message);

  // (2) Over-transfer through a registered-recipient path, isolating the
  // same planner failure from recipient registration behavior.
  await gotoMoveFlow(page, 'transfer');
  await page.locator('#transfer-address').fill(recipient);
  await waitForRecipientLookup(page, { expectedText: 'Found local registration', manualVisible: false });
  await page.locator('#transfer-amount').fill(overAmount);
  await page.locator('#btn-transfer').click();
  await confirmOperation(page, 'Confirm transfer');
  const overTransfer = await waitForToast(page, {
    origin: 'transfer',
    predicate: (toast) => /^transfer failed/i.test(toast.message) && /no combination of notes/i.test(toast.message),
  });
  await assertNoApproval(context, 'over-transfer');
  await waitForOperationIdle(page, { submitSelector: '#btn-transfer' });
  log.info('(2) over-transfer:', overTransfer.message);

  // Clearing the address has an asynchronous lookup reset; wait for that
  // state instead of a fixed delay before testing an unregistered recipient.
  await page.locator('#transfer-address').fill('');
  await waitForRecipientLookupReset(page);

  // (3) Unregistered recipient: lookup failure only; no transaction submit.
  await page.locator('#transfer-address').fill(unregisteredAddress);
  const missingRecipient = await waitForRecipientLookup(page, {
    expectedText: 'No local registration found',
    manualVisible: true,
  });
  assert(missingRecipient.manualVisible, 'manual key-entry fields did not reveal for an unregistered recipient');
  await assertNoApproval(context, 'unregistered recipient');
  log.info('(3) unregistered recipient:', missingRecipient.status);
  await page.locator('#transfer-address').fill('');
  await waitForRecipientLookupReset(page);

  // (4) Read the deployed pool's live cap and fee, and deposit a note that,
  // with the fee on top, exceeds the cap by one stroop. The SDK refuses it
  // before proving. Deployment parameters can change independently of this
  // test branch; a hard-coded amount can silently become valid and open a
  // wallet approval.
  // Mirrors app/js/ui/pool.js's getActivePoolContractId: first enabled pool.
  const poolContractId = await page.evaluate(() =>
    fetch('./deployments.json')
      .then((r) => r.json())
      .then((c) => (c.pools.find((pool) => pool.enabled) || c.pools[0]).poolContractId),
  );
  const maximumDeposit = await readInstanceAmount(poolContractId, rpcUrl, 'MaximumDepositAmount');
  const fee = await readInstanceAmount(poolContractId, rpcUrl, 'Fee');
  const aboveMaximumDeposit = stroopsToDecimal(maximumDeposit - fee + 1n);
  await gotoMoveFlow(page, 'deposit');
  await page.locator('#deposit-amount').fill(aboveMaximumDeposit);
  await page.locator('#btn-deposit').click();
  await confirmOperation(page, 'Confirm deposit');
  const aboveCapOutcome = await Promise.race([
    waitForToast(page, {
      origin: 'deposit',
      predicate: (toast) => /^deposit failed/i.test(toast.message) && /more than the pool maximum/i.test(toast.message),
      timeoutMs: 20_000,
    }).then((toast) => ({ toast })),
    waitForAnyFreighterApproval(context, APPROVAL_KINDS, { timeoutMs: 20_000 })
      .then((approval) => ({ approval })),
  ]);
  assert(
    aboveCapOutcome.toast,
    `above-max deposit unexpectedly reached Freighter approval (${aboveCapOutcome.approval?.kind || 'unknown'})`,
  );
  const aboveCap = aboveCapOutcome.toast;
  await assertNoApproval(context, 'above-max deposit');
  await waitForOperationIdle(page, { submitSelector: '#btn-deposit' });
  log.info(`(4) above max-deposit (${aboveMaximumDeposit} XLM):`, aboveCap.message);

  // (5) A deposit below the pool's 0.001 minimum is refused in the form, which
  // names the minimum, before any confirmation or wallet approval.
  await page.locator('#deposit-amount').fill('0.0001');
  await page.locator('#btn-deposit').click();
  const belowMinimum = await waitForToast(page, {
    origin: 'deposit',
    predicate: (toast) => /minimum deposit is 0\.001 XLM/i.test(toast.message),
  });
  assert(!(await page.getByTestId('confirm-dialog').isVisible()), 'confirm dialog opened for a deposit below the minimum');
  await assertNoApproval(context, 'below-minimum deposit');
  await waitForOperationIdle(page, { submitSelector: '#btn-deposit' });
  log.info('(5) below-minimum deposit:', belowMinimum.message);

  // (6) Signing account: a pasted value that is not an address is refused in
  // the picker itself and never becomes a choice.
  await gotoMoveFlow(page, 'withdraw');
  await page.locator('#withdraw-amount').fill('0.01');
  await signingSelect.selectOption('__other__');
  await page.getByTestId('signing-account-input').fill('GNOTANADDRESS');
  await page.getByTestId('signing-account-use').click();
  await page.getByTestId('signing-account-error').filter({ hasText: 'Enter a valid Stellar address' })
    .waitFor({ state: 'visible', timeout: 5_000 });
  assert(
    (await signingSelect.locator('option[value="GNOTANADDRESS"]').count()) === 0,
    'an invalid pasted address was added to the signing-account list',
  );
  log.info('(6) invalid signing account: refused in the picker');

  // (7) "Enter another address…" left without an address must not quietly fall
  // back to signing as the owner.
  await page.locator('#withdraw-amount').fill('0.01');
  await page.locator('#btn-withdraw').click();
  const noSigner = await waitForToast(page, {
    origin: 'withdraw',
    predicate: (toast) => /enter the account to sign and pay with/i.test(toast.message),
  });
  assert(!(await page.getByTestId('confirm-dialog').isVisible()), 'confirm dialog opened without a chosen signer');
  await assertNoApproval(context, 'no signing account entered');
  await waitForOperationIdle(page, { submitSelector: '#btn-withdraw' });
  log.info('(7) no signing account entered:', noSigner.message);

  // (8) A valid account that does not exist on the network cannot be the
  // transaction's source; stopped before the confirmation and before proving.
  await page.getByTestId('signing-account-input').fill(unregisteredAddress);
  await page.getByTestId('signing-account-use').click();
  // Selection updates after the signing account is saved to encrypted storage.
  await waitForCondition({
    operation: 'signing-account:select-pasted-address',
    observe: () => signingSelect.inputValue(),
    isReady: (address) => address === unregisteredAddress,
    timeoutMs: 5_000,
  });
  await page.locator('#btn-withdraw').click();
  const unfunded = await waitForToast(page, {
    origin: 'withdraw',
    predicate: (toast) => /isn't funded on this network/i.test(toast.message),
  });
  assert(!(await page.getByTestId('confirm-dialog').isVisible()), 'confirm dialog opened for an unfunded signing account');
  await assertNoApproval(context, 'unfunded signing account');
  await waitForOperationIdle(page, { submitSelector: '#btn-withdraw' });
  log.info('(8) unfunded signing account:', unfunded.message);

  // Deposits still use the owner regardless of the withdrawal selection.
  await gotoMoveFlow(page, 'deposit');

  const recovery = await deposit(helpers, { logTag, amount: '0.01', rpcUrl });
  assert(recovery.transactionHash !== baseline.transactionHash, 'recovery deposit somehow reused the baseline transaction hash');
  log.info('OK: all failures remained pre-signing and recovery deposit', recovery.transactionHash.slice(0, 8), 'confirmed SUCCESS');
}
