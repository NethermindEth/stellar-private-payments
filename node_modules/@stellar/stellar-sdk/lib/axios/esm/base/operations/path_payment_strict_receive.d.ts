import xdr from "../xdr.js";
import { PathPaymentStrictReceiveResult, PathPaymentStrictReceiveOpts } from "./types.js";
/**
 * Creates a PathPaymentStrictReceive operation.
 *
 * A `PathPaymentStrictReceive` operation sends the specified amount to the
 * destination account. It credits the destination with `destAmount` of
 * `destAsset`, while debiting at most `sendMax` of `sendAsset` from the source.
 * The transfer optionally occurs through a path. XLM payments create the
 * destination account if it does not exist.
 *
 * @see https://developers.stellar.org/docs/start/list-of-operations/#path-payment-strict-receive
 *
 * @param opts - Options object
 *   - `sendAsset`: asset to pay with
 *   - `sendMax`: maximum amount of sendAsset to send
 *   - `destination`: destination account to send to
 *   - `destAsset`: asset the destination will receive
 *   - `destAmount`: amount the destination receives
 *   - `path`: array of Asset objects to use as the path
 *   - `source`: The source account for the payment.
 *     Defaults to the transaction's source account.
 */
export declare function pathPaymentStrictReceive(opts: PathPaymentStrictReceiveOpts): xdr.Operation<PathPaymentStrictReceiveResult>;
