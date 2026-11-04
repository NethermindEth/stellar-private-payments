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

/**
 * Adds one traceable spend to its PKs' nodes: every input PK pays the pool fee
 * and sends each output to a PK outside the inputs; `withdrawn` maps an input
 * PK to what it took out. Returns the graph's edges as `[fromPk, toPk, amount]`,
 * one per sender and output.
 */
export function chargeSpend(nodeOf, inputTotals, outputs, withdrawn, fee) {
  for (const pk of inputTotals.keys()) {
    const node = nodeOf(pk);
    node.feesPaid += fee;
    node.feeCount += 1;
  }
  const transfers = [];
  for (const [toPk, amount] of outputs) {
    if (inputTotals.has(toPk)) continue; // change, not a transfer
    for (const fromPk of inputTotals.keys()) {
      transfers.push([fromPk, toPk, amount]);
      const from = nodeOf(fromPk);
      from.transferOut += amount;
      from.transferOutCount += 1;
      const to = nodeOf(toPk);
      to.transferIn += amount;
      to.transferInCount += 1;
    }
  }
  for (const [pk, amount] of withdrawn) {
    const node = nodeOf(pk);
    node.withdrawn += amount;
    node.withdrawCount += 1;
  }
  return transfers;
}

/** A PK's graph node before any of its transactions are counted. */
export function emptyPkNode(pk) {
  return {
    pk,
    deposited: 0n, depositCount: 0,
    received: 0n, receivedCount: 0,
    withdrawn: 0n, withdrawCount: 0,
    transferIn: 0n, transferInCount: 0,
    transferOut: 0n, transferOutCount: 0,
    feesPaid: 0n, feeCount: 0,
  };
}
