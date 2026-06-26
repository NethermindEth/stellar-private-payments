import xdr from "../xdr.js";
import { CreatePassiveSellOfferResult, CreatePassiveSellOfferOpts } from "./types.js";
/**
 * A "create passive offer" operation creates an offer that won't consume a
 * counter offer that exactly matches this offer. This is useful for offers
 * just used as 1:1 exchanges for path payments. Use manage offer to manage
 * this offer after using this operation to create it.
 * @param opts - Options object
 *   - `selling`: What you're selling.
 *   - `buying`: What you're buying.
 *   - `amount`: The total amount you're selling. If 0, deletes the offer.
 *   - `price`: Price of 1 unit of `selling` in terms of `buying`.
 *   - `price.n`: If `opts.price` is an object: the price numerator
 *   - `price.d`: If `opts.price` is an object: the price denominator
 *   - `source`: The source account (defaults to transaction source).
 * @throws when the best rational approximation of `price` cannot be found.
 */
export declare function createPassiveSellOffer(opts: CreatePassiveSellOfferOpts): xdr.Operation<CreatePassiveSellOfferResult>;
