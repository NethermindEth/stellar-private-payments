import xdr from "../xdr.js";
import { ManageSellOfferResult, ManageSellOfferOpts } from "./types.js";
/**
 * Returns a XDR ManageSellOfferOp. A "manage sell offer" operation creates, updates, or
 * deletes an offer.
 * @param opts - Options object
 *   - `selling`: What you're selling.
 *   - `buying`: What you're buying.
 *   - `amount`: The total amount you're selling. If 0, deletes the offer.
 *   - `price`: Price of 1 unit of `selling` in terms of `buying`.
 *   - `price.n`: If `opts.price` is an object: the price numerator
 *   - `price.d`: If `opts.price` is an object: the price denominator
 *   - `offerId`: If `0`, will create a new offer (default). Otherwise, edits an existing offer.
 *   - `source`: The source account (defaults to transaction source).
 * @throws when the best rational approximation of `price` cannot be found.
 */
export declare function manageSellOffer(opts: ManageSellOfferOpts): xdr.Operation<ManageSellOfferResult>;
