import { Api } from '../rpc/api.js';
import { RpcServer } from '../rpc/server.js';
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
import '../base/util/continued_fraction.js';
import '../base/util/bignumber.js';
import '../base/transaction_builder.js';
import '../base/muxed_account.js';
import '../base/scval.js';
import '../base/numbers/uint128.js';
import '../base/numbers/uint256.js';
import '../base/numbers/int128.js';
import '../base/numbers/int256.js';
import { withExponentialBackoff } from './utils.js';
import { DEFAULT_TIMEOUT } from './types.js';

class SentTransaction {
  constructor(assembled) {
    this.assembled = assembled;
    const { server, allowHttp, headers, rpcUrl } = this.assembled.options;
    this.server = server ?? new RpcServer(rpcUrl, { allowHttp, headers });
  }
  assembled;
  server;
  /**
   * The result of calling `sendTransaction` to broadcast the transaction to the
   * network.
   */
  sendTransactionResponse;
  /**
   * If `sendTransaction` completes successfully (which means it has `status: 'PENDING'`),
   * then `getTransaction` will be called in a loop for
   * {@link MethodOptions.timeoutInSeconds} seconds. This array contains all
   * the results of those calls.
   */
  getTransactionResponseAll;
  /**
   * The most recent result of calling `getTransaction`, from the
   * `getTransactionResponseAll` array.
   */
  getTransactionResponse;
  static Errors = {
    SendFailed: class SendFailedError extends Error {
    },
    SendResultOnly: class SendResultOnlyError extends Error {
    },
    TransactionStillPending: class TransactionStillPendingError extends Error {
    }
  };
  /**
   * Initialize a `SentTransaction` from {@link AssembledTransaction}
   * `assembled`, passing an optional {@link Watcher} `watcher`. This will also
   * send the transaction to the network.
   */
  static init = async (assembled, watcher) => {
    const tx = new SentTransaction(assembled);
    const sent = await tx.send(watcher);
    return sent;
  };
  send = async (watcher) => {
    this.sendTransactionResponse = await this.server.sendTransaction(
      this.assembled.signed
    );
    if (this.sendTransactionResponse.status !== "PENDING") {
      throw new SentTransaction.Errors.SendFailed(
        `Sending the transaction to the network failed!
${JSON.stringify(
          this.sendTransactionResponse,
          null,
          2
        )}`
      );
    }
    if (watcher?.onSubmitted) watcher.onSubmitted(this.sendTransactionResponse);
    const { hash } = this.sendTransactionResponse;
    const timeoutInSeconds = this.assembled.options.timeoutInSeconds ?? DEFAULT_TIMEOUT;
    this.getTransactionResponseAll = await withExponentialBackoff(
      async () => {
        const tx = await this.server.getTransaction(hash);
        if (watcher?.onProgress) watcher.onProgress(tx);
        return tx;
      },
      (resp) => resp.status === Api.GetTransactionStatus.NOT_FOUND,
      timeoutInSeconds
    );
    this.getTransactionResponse = this.getTransactionResponseAll[this.getTransactionResponseAll.length - 1];
    if (this.getTransactionResponse.status === Api.GetTransactionStatus.NOT_FOUND) {
      throw new SentTransaction.Errors.TransactionStillPending(
        `Waited ${timeoutInSeconds} seconds for transaction to complete, but it did not. Returning anyway. Check the transaction status manually. Sent transaction: ${JSON.stringify(
          this.sendTransactionResponse,
          null,
          2
        )}
All attempts to get the result: ${JSON.stringify(
          this.getTransactionResponseAll,
          null,
          2
        )}`
      );
    }
    return this;
  };
  get result() {
    if ("getTransactionResponse" in this && this.getTransactionResponse) {
      if ("returnValue" in this.getTransactionResponse) {
        return this.assembled.options.parseResultXdr(
          this.getTransactionResponse.returnValue
        );
      }
      throw new Error("Transaction failed! Cannot parse result.");
    }
    if (this.sendTransactionResponse) {
      const errorResult = this.sendTransactionResponse.errorResult?.result();
      if (errorResult) {
        throw new SentTransaction.Errors.SendFailed(
          `Transaction simulation looked correct, but attempting to send the transaction failed. Check \`simulation\` and \`sendTransactionResponseAll\` to troubleshoot. Decoded \`sendTransactionResponse.errorResultXdr\`: ${errorResult}`
        );
      }
      throw new SentTransaction.Errors.SendResultOnly(
        `Transaction was sent to the network, but not yet awaited. No result to show. Await transaction completion with \`getTransaction(sendTransactionResponse.hash)\``
      );
    }
    throw new Error(
      `Sending transaction failed: ${JSON.stringify(this.assembled.signed)}`
    );
  }
}
class Watcher {
}

export { SentTransaction, Watcher };
//# sourceMappingURL=sent_transaction.js.map
