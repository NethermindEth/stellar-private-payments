import xdr from "../xdr.js";
import { ManageBuyOfferResult, ManageBuyOfferOpts } from "./types.js";
/**
 * Returns a XDR ManageBuyOfferOp. A "manage buy offer" operation creates, updates, or
 * deletes a buy offer.
 * @param opts - Options object
 *   - `selling`: What you're selling.
 *   - `buying`: What you're buying.
 *   - `buyAmount`: The total amount you're buying. If 0, deletes the offer.
 *   - `price`: Price of 1 unit of `buying` in terms of `selling`.
 *   - `price.n`: If `opts.price` is an object: the price numerator
 *   - `price.d`: If `opts.price` is an object: the price denominator
 *   - `offerId`: If `0`, will create a new offer (default). Otherwise, edits an existing offer.
 *   - `source`: The source account (defaults to transaction source).
 * @throws when the best rational approximation of `price` cannot be found.
 */
export declare function manageBuyOffer(opts: ManageBuyOfferOpts): xdr.Operation<ManageBuyOfferResult>;
