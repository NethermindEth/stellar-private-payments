import { CONTRACT_ERRORS } from './ui/errors.js';

const NOTHING_YET = 'You have nothing to send yet. If you just deposited, try again in a few seconds; otherwise, deposit first.';
// The SDK planner's TRANSACTION_LIMIT.
const NOTE_LIMIT = 10;

// The warning for more notes than one transfer or withdrawal can spend, or null.
export function noteLimitWarning(noteCount) {
  return noteCount > NOTE_LIMIT
    ? `Your balance is split across ${noteCount} notes. One transfer or withdrawal can spend at most ${NOTE_LIMIT} of them, so send larger amounts in parts.`
    : null;
}

/**
 * The sentence for a refusal the SDK gave a `code`, or null. `feeIncluded` is
 * for an amount that already holds the fee, as the Advanced form's Public deposit.
 * `NOT_BALANCED` needs the Advanced form's `amounts`. `label` names the pool's
 * token in the trustline refusals. `noteCount` counts the user's unspent notes
 * in the pool.
 */
export function poolErrorMessage(error, { fee, format, feeIncluded = false, amounts, label = 'this token', noteCount }) {
  switch (error?.code) {
    case 'TRUSTLINE_MISSING':
      return `The account that pays has no trustline for ${label}. Add ${label} in your wallet, get some into the account, then deposit again.`;
    case 'INSUFFICIENT_BALANCE':
      return `The account that pays holds ${format(error.available)}, less than the ${format(error.needed)} this deposit sends${fee ? ', pool fee included' : ''}.`;
    case 'RECIPIENT_TRUSTLINE_MISSING':
      return `The recipient has no trustline for ${label}, so it can't receive this withdrawal. Ask them to add ${label} in their wallet, or choose another recipient.`;
    case 'NOT_BALANCED': {
      if (!amounts) return null;
      const { inputs, deposit, outputs, withdraw } = amounts;
      const { gap } = error;
      const excess = -gap;
      const rule = fee
        ? `Selected notes and public deposit must add up to the private outputs, public withdraw and the ${format(fee)} pool fee.`
        : 'Selected notes and public deposit must add up to the private outputs and public withdraw.';
      let fix;
      if (inputs === 0n && deposit === 0n) fix = 'Select a note or enter a public deposit.';
      else if (gap > 0n) fix = `Add ${format(gap)} to a private output.`;
      else if (outputs >= excess) fix = `Remove ${format(excess)} from a private output.`;
      else if (withdraw >= excess) fix = `Lower the public withdraw by ${format(excess)}.`;
      else fix = `Raise the public deposit by ${format(excess)}, or select more notes.`;
      return `${rule} ${fix}`;
    }
    case 'DEPOSIT_BELOW_MINIMUM':
      if (!feeIncluded) return `The smallest deposit is ${format(error.minimum)}.`;
      return fee
        ? `Public deposit must leave at least ${format(error.minimum)} after the ${format(fee)} pool fee.`
        : `Public deposit must be at least ${format(error.minimum)}.`;
    case 'DEPOSIT_ABOVE_MAXIMUM':
      if (feeIncluded) return `Public deposit can be at most ${format(error.maximum)}${fee ? ', pool fee included' : ''}.`;
      return `You can deposit at most ${format(error.largestDeposit)}${fee ? ` (${format(error.maximum)} with the pool fee)` : ''}.`;
    case 'DEPOSITS_PAUSED':
      return CONTRACT_ERRORS.pool[18];
    case 'NO_SPENDABLE_NOTES':
      return NOTHING_YET;
    case 'NO_COMBINATION':
      if (error.maxSpend === 0n) {
        return fee
          ? `You have nothing to send. Each transaction spends at most two of your notes, and its ${format(fee)} pool fee would use them up. If you just deposited, try again in a few seconds; otherwise, deposit more first.`
          : NOTHING_YET;
      }
      return [
        `You can send at most ${format(error.maxSpend)}.`,
        noteLimitWarning(noteCount) ?? (fee ? `Each transaction pays a ${format(fee)} pool fee.` : ''),
      ].filter(Boolean).join(' ');
    default:
      return null;
  }
}
