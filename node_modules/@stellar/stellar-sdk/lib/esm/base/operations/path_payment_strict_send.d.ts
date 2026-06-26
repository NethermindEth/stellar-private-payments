import xdr from "../xdr.js";
import { PathPaymentStrictSendResult, PathPaymentStrictSendOpts } from "./types.js";
/**
 * Creates a PathPaymentStrictSend operation.
 *
 * A `PathPaymentStrictSend` operation sends the specified amount to the
 * destination account crediting at least `destMin` of `destAsset`, optionally
 * through a path. XLM payments create the destination account if it does not
 * exist.
 *
 * @see https://developers.stellar.org/docs/start/list-of-operations/#path-payment-strict-send
 *
 * @param opts - Options object
 *   - `sendAsset`: asset to pay with
 *   - `sendAmount`: amount of sendAsset to send (excluding fees)
 *   - `destination`: destination account to send to
 *   - `destAsset`: asset the destination will receive
 *   - `destMin`: minimum amount of destAsset to be received
 *   - `path`: array of Asset objects to use as the path
 *   - `source`: The source account for the payment. Defaults to the transaction's source account.
 */
export declare function pathPaymentStrictSend(opts: PathPaymentStrictSendOpts): xdr.Operation<PathPaymentStrictSendResult>;
