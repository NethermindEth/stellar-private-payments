import xdr from "../xdr.js";
import { PaymentOpts, PaymentResult } from "./types.js";
/**
 * Create a payment operation.
 *
 * @see https://developers.stellar.org/docs/start/list-of-operations/#payment
 *
 * @param opts - options object
 *   - `destination`: destination account ID
 *   - `asset`: asset to send
 *   - `amount`: amount to send
 *   - `source`: The source account for the payment.
 *     Defaults to the transaction's source account.
 */
export declare function payment(opts: PaymentOpts): xdr.Operation<PaymentResult>;
