// Flagship deposit happy path. Transaction submission, Freighter approvals,
// submitted-toast identity, and RPC confirmation are owned by the reusable
// deposit operation; this scenario only describes the business assertion.

import { createLogger } from '../src/logger.mjs';
import { deposit } from '../src/moveFunds.mjs';
import { gotoMoveFunds } from '../src/navigation.mjs';
import { driveWizard } from '../src/onboarding.mjs';

const log = createLogger('02-deposit');

export async function run(helpers) {
  const { page, context, waitForFreighterApproval, approveOrWatch } = helpers;
  const logTag = '02-deposit';

  // Complete onboarding when required before exercising the transaction flow.
  await driveWizard(page, context, { waitForFreighterApproval, approveOrWatch, logTag });
  await gotoMoveFunds(page);

  const result = await deposit(helpers, {
    logTag,
    amount: '0.01',
    rpcUrl: process.env.E2E_RPC_URL || 'https://soroban-testnet.stellar.org',
  });

  log.info('OK: deposit', result.transactionHash.slice(0, 8), 'confirmed SUCCESS on-chain');
}
