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
import { formatAmount } from '../../app/js/ui/notes-view.js';

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

function decimalToStroops(decimal) {
  const [whole, fraction = ''] = decimal.split('.');
  return BigInt(whole) * 10_000_000n + BigInt(fraction.padEnd(7, '0'));
}

function randomUnregisteredAddress() {
  return StrKey.encodeEd25519PublicKey(randomBytes(32));
}

async function assertNoApproval(context, label) {
  await expectNoFreighterApproval(context, APPROVAL_KINDS, { timeoutMs: 5_000 });
  log.info(`${label}: no Freighter approval appeared (pre-signing failure confirmed)`);
}

// Submits a spend on the withdraw or transfer form and expects a refusal toast
// matching the predicate, with no confirmation and no wallet approval.
async function expectSpendRefused(page, context, flow, amount, predicate) {
  // The form's previous refusal can read the same, so let it expire first.
  await page.locator(`[data-toast-origin="${flow}"]`).first()
    .waitFor({ state: 'detached', timeout: 10_000 });
  await page.locator(`#${flow}-amount`).fill(amount);
  await page.locator(`#btn-${flow}`).click();
  const toast = await waitForToast(page, { origin: flow, predicate });
  assert(!(await page.getByTestId('confirm-dialog').isVisible()), `confirm dialog opened for a ${flow} of ${amount}`);
  await assertNoApproval(context, `${flow} of ${amount}`);
  await waitForOperationIdle(page, { submitSelector: `#btn-${flow}` });
  return toast.message;
}

export async function run(helpers) {
  const { page, context, waitForFreighterApproval, approveOrWatch } = helpers;
  const logTag = '11-failure-modes';
  const rpcUrl = RPC_URL;

  const recipientAccount = await createRegisteredAccount();
  const recipient = recipientAccount.publicKey();

  await driveWizard(page, context, { waitForFreighterApproval, approveOrWatch, logTag });
  await gotoMoveFunds(page);

  const initialSync = await waitForSyncedLedger(page);

  // (0) A withdrawal before the first deposit: the empty wallet is refused
  // before the confirmation, with its own sentence.
  await gotoMoveFlow(page, 'withdraw');
  const signingSelect = page.getByTestId('signing-account-select');
  const owner = await signingSelect.locator('option').filter({ hasText: 'Deposit account' }).getAttribute('value');
  assert(owner && owner !== recipient, 'expected a connected owner distinct from the recipient');
  await signingSelect.selectOption(owner);
  await page.locator('#withdraw-recipient-select').selectOption(owner);
  const emptyWallet = await expectSpendRefused(page, context, 'withdraw', '0.001', (toast) => (
    toast.message === 'You have nothing to send yet. If you just deposited, try again in a few seconds; otherwise, deposit first.'
  ));
  log.info('(0) withdraw from an empty wallet:', emptyWallet);
  await gotoMoveFlow(page, 'deposit');

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

  // (1) Over-withdraw, far above the balance and one stroop above Max to send:
  // the planner refuses both before the confirmation, naming Max to send.
  await gotoMoveFlow(page, 'withdraw');
  const maxSpend = await page.locator('#move-funds-max-spend')
    .filter({ hasText: /^0\.\d+ XLM$/ })
    .innerText({ timeout: 60_000 });
  const aboveMaxSpend = stroopsToDecimal(decimalToStroops(maxSpend.replace(/ XLM$/, '')) + 1n);
  const namesMaxSpend = (toast) => toast.message.startsWith(`You can send at most ${maxSpend}.`);
  const overWithdraw = await expectSpendRefused(page, context, 'withdraw', overAmount, namesMaxSpend);
  log.info('(1) over-withdraw:', overWithdraw);
  const justOverWithdraw = await expectSpendRefused(page, context, 'withdraw', aboveMaxSpend, namesMaxSpend);
  log.info(`(1) withdraw of ${aboveMaxSpend} XLM:`, justOverWithdraw);

  // (2) The same two refusals on a transfer to a registered recipient,
  // isolating the planner failure from recipient registration behavior.
  await gotoMoveFlow(page, 'transfer');
  await page.locator('#transfer-address').fill(recipient);
  await waitForRecipientLookup(page, { expectedText: 'Found local registration', manualVisible: false });
  const overTransfer = await expectSpendRefused(page, context, 'transfer', overAmount, namesMaxSpend);
  log.info('(2) over-transfer:', overTransfer);
  const justOverTransfer = await expectSpendRefused(page, context, 'transfer', aboveMaxSpend, namesMaxSpend);
  log.info(`(2) transfer of ${aboveMaxSpend} XLM:`, justOverTransfer);

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
  // with the fee on top, exceeds the cap by one stroop. The form refuses it
  // before any confirmation. Deployment parameters can change independently
  // of this test branch; a hard-coded amount can silently become valid.
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
  const largestDeposit = `You can deposit at most ${formatAmount(maximumDeposit - fee, 'XLM', 7)} (${formatAmount(maximumDeposit, 'XLM', 7)} with the pool fee).`;
  const aboveCap = await waitForToast(page, {
    origin: 'deposit',
    predicate: (toast) => toast.message === largestDeposit,
  });
  assert(!(await page.getByTestId('confirm-dialog').isVisible()), 'confirm dialog opened for a deposit above the maximum');
  await assertNoApproval(context, 'above-max deposit');
  await waitForOperationIdle(page, { submitSelector: '#btn-deposit' });
  log.info(`(4) above max-deposit (${aboveMaximumDeposit} XLM):`, aboveCap.message);

  // (5) A deposit below the pool's 0.001 minimum is refused in the form, which
  // names the minimum, before any confirmation or wallet approval.
  await page.locator('#deposit-amount').fill('0.0001');
  await page.locator('#btn-deposit').click();
  const belowMinimum = await waitForToast(page, {
    origin: 'deposit',
    predicate: (toast) => toast.message === 'The smallest deposit is 0.001 XLM.',
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
