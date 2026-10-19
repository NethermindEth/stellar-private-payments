import { CONTRACT_ERRORS } from './ui/errors.js';

const NOTHING_YET = 'You have nothing to send yet. If you just deposited, try again in a few seconds; otherwise, deposit first.';

/**
 * The sentence for a refusal the SDK gave a `code`, or null. `feeIncluded` is
 * for an amount that already holds the fee, as the Advanced form's Public deposit.
 * `NOT_BALANCED` needs the Advanced form's `amounts`.
 */
export function poolErrorMessage(error, { fee, format, feeIncluded = false, amounts }) {
  switch (error?.code) {
    case 'NOT_BALANCED': {
      if (!amounts) return null;
      const { inputs, deposit, outputs, withdraw } = amounts;
      const gap = BigInt(error.gap);
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
      if (BigInt(error.maxSpend) === 0n) {
        return fee
          ? `You have nothing to send once the ${format(fee)} pool fee is paid. If you just deposited, try again in a few seconds; otherwise, deposit more first.`
          : NOTHING_YET;
      }
      return `You can send at most ${format(error.maxSpend)}.${fee ? ` Each transaction pays a ${format(fee)} pool fee.` : ''}`;
    default:
      return null;
  }
}
