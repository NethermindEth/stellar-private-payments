/**
 * Inputs and deposit less outputs, withdrawal and pool fee, in base units.
 * Zero balances; above zero the outputs are short by the gap, below zero over.
 */
export function advancedGap({ inputs, deposit, outputs, withdraw, fee }) {
  return inputs + deposit - outputs - withdraw - fee;
}

/**
 * The refusal for a form that does not balance, in the form's own words, or
 * null when it does. A form with no selected notes and no public deposit asks
 * for one. Otherwise an excess comes off the private outputs, else the public
 * withdraw, else more has to come in.
 */
export function advancedGapMessage(amounts, format) {
  const gap = advancedGap(amounts);
  if (gap === 0n) return null;
  const { inputs, deposit, outputs, withdraw, fee } = amounts;
  const rule = fee
    ? `Selected notes and public deposit must add up to the private outputs, public withdraw and the ${format(fee)} pool fee.`
    : 'Selected notes and public deposit must add up to the private outputs and public withdraw.';
  const excess = -gap;
  let fix;
  if (inputs === 0n && deposit === 0n) fix = 'Select a note or enter a public deposit.';
  else if (gap > 0n) fix = `Add ${format(gap)} to a private output.`;
  else if (outputs >= excess) fix = `Remove ${format(excess)} from a private output.`;
  else if (withdraw >= excess) fix = `Lower the public withdraw by ${format(excess)}.`;
  else fix = `Raise the public deposit by ${format(excess)}, or select more notes.`;
  return `${rule} ${fix}`;
}
