/**
 * Mirrors classify_tx in sdk/native/examples/gvk-audit.rs. A spend pays the
 * pool fee from its inputs, so it is a withdrawal only when the inputs exceed
 * the outputs plus the fee.
 */
export function classifyTx(hasRealInput, inputSum, outputSum, fee) {
  if (!hasRealInput) return 'deposit';
  return inputSum > outputSum + fee ? 'withdraw' : 'transfer';
}

/**
 * Per input PK: what went in, minus what came back as change, went on to
 * someone else, or paid the pool fee. The fee is an output with no owner, so
 * every input PK is charged for it, as for an output to a PK outside the inputs.
 */
export function withdrawalsByPk(inputTotals, spent, fee) {
  const withdrawn = new Map();
  for (const [pk, inputTotal] of inputTotals) {
    const amount = inputTotal - (spent.get(pk) ?? 0n) - fee;
    if (amount > 0n) withdrawn.set(pk, amount);
  }
  return withdrawn;
}
