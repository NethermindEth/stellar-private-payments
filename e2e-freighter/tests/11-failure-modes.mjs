// Failure-mode battery for the money flows. Each negative path proves its
// specific pre-signing failure and then finishes with a real successful
// deposit to ensure no failure left the app in a poisoned state.

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

const log = createLogger('11-failure-modes');
const APPROVAL_KINDS = ['signMessage', 'signAuthEntry', 'signTransaction'];
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const execFileAsync = promisify(execFile);
// ScVal::Vec([ScVal::Symbol("MaximumDepositAmount")]). This is the persistent
// contract-data key used by both pool contract variants.
const MAXIMUM_DEPOSIT_KEY_XDR = 'AAAAEAAAAAEAAAABAAAADwAAABRNYXhpbXVtRGVwb3NpdEFtb3VudA==';
const TESTNET_PASSPHRASE = 'Test SDF Network ; September 2015';

async function readMaximumDepositAmount(poolContractId, rpcUrl) {
  const { stdout } = await execFileAsync('stellar', [
    'contract', 'read',
    '--id', poolContractId,
    '--key-xdr', MAXIMUM_DEPOSIT_KEY_XDR,
    '--rpc-url', rpcUrl,
    '--network-passphrase', TESTNET_PASSPHRASE,
    '--output', 'json',
  ]);
  const match = stdout.match(/""u256"":\s*""(\d+)""/);
  if (!match) throw new Error(`could not read MaximumDepositAmount from ${poolContractId}`);
  return BigInt(match[1]);
}

function stroopsToDecimal(stroops) {
  const whole = stroops / 10_000_000n;
  const fraction = String(stroops % 10_000_000n).padStart(7, '0');
  return `${whole}.${fraction}`;
}

function crc16Xmodem(bytes) {
  let crc = 0;
  for (const byte of bytes) {
    crc ^= byte << 8;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc & 0x8000) ? ((crc << 1) ^ 0x1021) : (crc << 1);
      crc &= 0xffff;
    }
  }
  return crc;
}

function base32Encode(bytes) {
  let value = 0;
  let bits = 0;
  let output = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  return bits ? output + BASE32_ALPHABET[(value << (5 - bits)) & 31] : output;
}

function randomUnregisteredAddress() {
  const encoded = Buffer.alloc(35);
  encoded[0] = 6 << 3;
  randomBytes(32).copy(encoded, 1);
  const checksum = crc16Xmodem(encoded.subarray(0, 33));
  encoded[33] = checksum & 0xff;
  encoded[34] = checksum >>> 8;
  return base32Encode(encoded);
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
  const rpcUrl = process.env.E2E_RPC_URL || 'https://soroban-testnet.stellar.org';
  const recipient = process.env.E2E_ACCOUNT_D_ADDRESS;
  assert(recipient, 'E2E_ACCOUNT_D_ADDRESS is not set -- source deployments/testnet/.e2e-accounts.env first');

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

  // (4) Read the deployed pool's live cap and exceed it by one stroop.
  // Deployment parameters can change independently of this test branch; a
  // hard-coded amount can silently become valid and open a wallet approval.
  const poolContractId = process.env.E2E_POOL_CONTRACT;
  assert(poolContractId, 'E2E_POOL_CONTRACT is not set');
  const maximumDeposit = await readMaximumDepositAmount(poolContractId, rpcUrl);
  const aboveMaximumDeposit = stroopsToDecimal(maximumDeposit + 1n);
  await gotoMoveFlow(page, 'deposit');
  await page.locator('#deposit-amount').fill(aboveMaximumDeposit);
  await page.locator('#btn-deposit').click();
  await confirmOperation(page, 'Confirm deposit');
  const aboveCapOutcome = await Promise.race([
    waitForToast(page, {
      origin: 'deposit',
      predicate: (toast) => /transaction simulation failed/i.test(toast.message),
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

  const recovery = await deposit(helpers, { logTag, amount: '0.01', rpcUrl });
  assert(recovery.transactionHash !== baseline.transactionHash, 'recovery deposit somehow reused the baseline transaction hash');
  log.info('OK: all failures remained pre-signing and recovery deposit', recovery.transactionHash.slice(0, 8), 'confirmed SUCCESS');
}
