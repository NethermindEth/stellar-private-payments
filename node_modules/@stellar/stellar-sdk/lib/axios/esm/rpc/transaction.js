import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/int.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/hyper.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-int.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-hyper.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/xdr-type.js';
import 'buffer';
import '../base/generated/curr_generated.js';
import '@noble/hashes/sha2.js';
import '../base/signing.js';
import '../base/keypair.js';
import 'base32.js';
import { Operation } from '../base/operation.js';
import '../base/util/bignumber.js';
import { TransactionBuilder } from '../base/transaction_builder.js';
import '../base/muxed_account.js';
import '../base/scval.js';
import '../base/numbers/uint128.js';
import '../base/numbers/uint256.js';
import '../base/numbers/int128.js';
import '../base/numbers/int256.js';
import { Api } from './api.js';
import { parseRawSimulation } from './parsers.js';

function isSorobanTransaction(tx) {
  if (tx.operations.length !== 1) {
    return false;
  }
  switch (tx.operations[0].type) {
    case "invokeHostFunction":
    case "extendFootprintTtl":
    case "restoreFootprint":
      return true;
    default:
      return false;
  }
}
function assembleTransaction(raw, simulation) {
  if ("innerTransaction" in raw) {
    return assembleTransaction(raw.innerTransaction, simulation);
  }
  if (!isSorobanTransaction(raw)) {
    throw new TypeError(
      "unsupported transaction: must contain exactly one invokeHostFunction, extendFootprintTtl, or restoreFootprint operation"
    );
  }
  const success = parseRawSimulation(simulation);
  if (!Api.isSimulationSuccess(success)) {
    throw new Error(`simulation incorrect: ${JSON.stringify(success)}`);
  }
  let classicFeeNum;
  try {
    classicFeeNum = BigInt(raw.fee);
  } catch {
    classicFeeNum = BigInt(0);
  }
  const rawSorobanData = raw.toEnvelope().v1().tx().ext().value();
  if (rawSorobanData) {
    if (classicFeeNum - rawSorobanData.resourceFee().toBigInt() > BigInt(0)) {
      classicFeeNum -= rawSorobanData.resourceFee().toBigInt();
    }
  }
  const txnBuilder = TransactionBuilder.cloneFrom(raw, {
    // automatically update the tx fee that will be set on the resulting tx to
    // the sum of 'classic' fee provided from incoming tx.fee and minResourceFee
    // provided by simulation.
    //
    // 'classic' tx fees are measured as the product of tx.fee * 'number of
    // operations', In soroban contract tx, there can only be single operation
    // in the tx, so can make simplification of total classic fees for the
    // soroban transaction will be equal to incoming tx.fee + minResourceFee.
    fee: classicFeeNum.toString(),
    // apply the pre-built Soroban Tx Data from simulation onto the Tx
    sorobanData: success.transactionData.build(),
    networkPassphrase: raw.networkPassphrase
  });
  if (raw.operations[0].type === "invokeHostFunction") {
    txnBuilder.clearOperations();
    const invokeOp = raw.operations[0];
    const existingAuth = invokeOp.auth ?? [];
    txnBuilder.addOperation(
      Operation.invokeHostFunction({
        source: invokeOp.source,
        func: invokeOp.func,
        // if auth entries are already present, we consider this "advanced
        // usage" and disregard ALL auth entries from the simulation
        //
        // the intuition is "if auth exists, this tx has probably been
        // simulated before"
        auth: existingAuth.length > 0 ? existingAuth : success.result.auth
      })
    );
  }
  return txnBuilder;
}

export { assembleTransaction };
//# sourceMappingURL=transaction.js.map
