import { Asset } from './asset.js';
import { LiquidityPoolAsset } from './liquidity_pool_asset.js';
import { Claimant } from './claimant.js';
import { StrKey } from './strkey.js';
import { LiquidityPoolId } from './liquidity_pool_id.js';
import types from './generated/curr_generated.js';
import { trimEnd } from './util/util.js';
import { encodeMuxedAccountToAddress } from './util/decode_encode_muxed_account.js';
import { manageSellOffer } from './operations/manage_sell_offer.js';
import { createPassiveSellOffer } from './operations/create_passive_sell_offer.js';
import { accountMerge } from './operations/account_merge.js';
import { allowTrust } from './operations/allow_trust.js';
import { bumpSequence } from './operations/bump_sequence.js';
import { changeTrust } from './operations/change_trust.js';
import { createAccount } from './operations/create_account.js';
import { createClaimableBalance } from './operations/create_claimable_balance.js';
import { claimClaimableBalance } from './operations/claim_claimable_balance.js';
import { clawbackClaimableBalance } from './operations/clawback_claimable_balance.js';
import { inflation } from './operations/inflation.js';
import { manageData } from './operations/manage_data.js';
import { manageBuyOffer } from './operations/manage_buy_offer.js';
import { pathPaymentStrictReceive } from './operations/path_payment_strict_receive.js';
import { pathPaymentStrictSend } from './operations/path_payment_strict_send.js';
import { payment } from './operations/payment.js';
import { setOptions } from './operations/set_options.js';
import { beginSponsoringFutureReserves } from './operations/begin_sponsoring_future_reserves.js';
import { endSponsoringFutureReserves } from './operations/end_sponsoring_future_reserves.js';
import { revokeAccountSponsorship, revokeTrustlineSponsorship, revokeOfferSponsorship, revokeDataSponsorship, revokeClaimableBalanceSponsorship, revokeLiquidityPoolSponsorship, revokeSignerSponsorship } from './operations/revoke_sponsorship.js';
import { clawback } from './operations/clawback.js';
import { setTrustLineFlags } from './operations/set_trustline_flags.js';
import { liquidityPoolDeposit } from './operations/liquidity_pool_deposit.js';
import { liquidityPoolWithdraw } from './operations/liquidity_pool_withdraw.js';
import { invokeHostFunction, createStellarAssetContract, invokeContractFunction, createCustomContract, uploadContractWasm } from './operations/invoke_host_function.js';
import { extendFootprintTtl } from './operations/extend_footprint_ttl.js';
import { restoreFootprint } from './operations/restore_footprint.js';
import { fromXDRAmount, fromXDRPrice } from './util/operations.js';

const AuthRequiredFlag = 1 << 0;
const AuthRevocableFlag = 1 << 1;
const AuthImmutableFlag = 1 << 2;
const AuthClawbackEnabledFlag = 1 << 3;
class Operation {
  /**
   * Deconstructs the raw XDR operation object into the structured object that
   * was used to create the operation (i.e. the `opts` parameter to most ops).
   *
   * @param operation - An XDR Operation.
   */
  static fromXDRObject(operation) {
    const result = {};
    const sourceAccount = operation.sourceAccount();
    if (sourceAccount) {
      result.source = encodeMuxedAccountToAddress(sourceAccount);
    }
    const attrs = operation.body().value();
    const operationName = operation.body().switch().name;
    switch (operationName) {
      case "createAccount": {
        result.type = "createAccount";
        result.destination = accountIdtoAddress(attrs.destination());
        result.startingBalance = fromXDRAmount(attrs.startingBalance());
        break;
      }
      case "payment": {
        result.type = "payment";
        result.destination = encodeMuxedAccountToAddress(attrs.destination());
        result.asset = Asset.fromOperation(attrs.asset());
        result.amount = fromXDRAmount(attrs.amount());
        break;
      }
      case "pathPaymentStrictReceive": {
        result.type = "pathPaymentStrictReceive";
        result.sendAsset = Asset.fromOperation(attrs.sendAsset());
        result.sendMax = fromXDRAmount(attrs.sendMax());
        result.destination = encodeMuxedAccountToAddress(attrs.destination());
        result.destAsset = Asset.fromOperation(attrs.destAsset());
        result.destAmount = fromXDRAmount(attrs.destAmount());
        result.path = [];
        const path = attrs.path();
        Object.keys(path).forEach((pathKey) => {
          result.path.push(Asset.fromOperation(path[pathKey]));
        });
        break;
      }
      case "pathPaymentStrictSend": {
        result.type = "pathPaymentStrictSend";
        result.sendAsset = Asset.fromOperation(attrs.sendAsset());
        result.sendAmount = fromXDRAmount(attrs.sendAmount());
        result.destination = encodeMuxedAccountToAddress(attrs.destination());
        result.destAsset = Asset.fromOperation(attrs.destAsset());
        result.destMin = fromXDRAmount(attrs.destMin());
        result.path = [];
        const path = attrs.path();
        Object.keys(path).forEach((pathKey) => {
          result.path.push(Asset.fromOperation(path[pathKey]));
        });
        break;
      }
      case "changeTrust": {
        result.type = "changeTrust";
        switch (attrs.line().switch()) {
          case types.AssetType.assetTypePoolShare():
            result.line = LiquidityPoolAsset.fromOperation(attrs.line());
            break;
          default:
            result.line = Asset.fromOperation(attrs.line());
            break;
        }
        result.limit = fromXDRAmount(attrs.limit());
        break;
      }
      case "allowTrust": {
        result.type = "allowTrust";
        result.trustor = accountIdtoAddress(attrs.trustor());
        result.assetCode = attrs.asset().value().toString();
        result.assetCode = trimEnd(result.assetCode, "\0");
        result.authorize = attrs.authorize();
        break;
      }
      case "setOptions": {
        result.type = "setOptions";
        if (attrs.inflationDest()) {
          result.inflationDest = accountIdtoAddress(attrs.inflationDest());
        }
        result.clearFlags = attrs.clearFlags();
        result.setFlags = attrs.setFlags();
        result.masterWeight = attrs.masterWeight();
        result.lowThreshold = attrs.lowThreshold();
        result.medThreshold = attrs.medThreshold();
        result.highThreshold = attrs.highThreshold();
        result.homeDomain = attrs.homeDomain() !== void 0 ? attrs.homeDomain().toString("ascii") : void 0;
        if (attrs.signer()) {
          const signer = {};
          const arm = attrs.signer().key().arm();
          if (arm === "ed25519") {
            signer.ed25519PublicKey = accountIdtoAddress(attrs.signer().key());
          } else if (arm === "preAuthTx") {
            signer.preAuthTx = attrs.signer().key().preAuthTx();
          } else if (arm === "hashX") {
            signer.sha256Hash = attrs.signer().key().hashX();
          } else if (arm === "ed25519SignedPayload") {
            const signedPayload = attrs.signer().key().ed25519SignedPayload();
            signer.ed25519SignedPayload = StrKey.encodeSignedPayload(
              signedPayload.toXDR()
            );
          }
          signer.weight = attrs.signer().weight();
          result.signer = signer;
        }
        break;
      }
      // the next case intentionally falls through!
      case "manageOffer":
      case "manageSellOffer": {
        result.type = "manageSellOffer";
        result.selling = Asset.fromOperation(attrs.selling());
        result.buying = Asset.fromOperation(attrs.buying());
        result.amount = fromXDRAmount(attrs.amount());
        result.price = fromXDRPrice(attrs.price());
        result.offerId = attrs.offerId().toString();
        break;
      }
      case "manageBuyOffer": {
        result.type = "manageBuyOffer";
        result.selling = Asset.fromOperation(attrs.selling());
        result.buying = Asset.fromOperation(attrs.buying());
        result.buyAmount = fromXDRAmount(attrs.buyAmount());
        result.price = fromXDRPrice(attrs.price());
        result.offerId = attrs.offerId().toString();
        break;
      }
      // the next case intentionally falls through!
      case "createPassiveOffer":
      case "createPassiveSellOffer": {
        result.type = "createPassiveSellOffer";
        result.selling = Asset.fromOperation(attrs.selling());
        result.buying = Asset.fromOperation(attrs.buying());
        result.amount = fromXDRAmount(attrs.amount());
        result.price = fromXDRPrice(attrs.price());
        break;
      }
      case "accountMerge": {
        result.type = "accountMerge";
        result.destination = encodeMuxedAccountToAddress(attrs);
        break;
      }
      case "manageData": {
        result.type = "manageData";
        result.name = attrs.dataName().toString("ascii");
        result.value = attrs.dataValue();
        break;
      }
      case "inflation": {
        result.type = "inflation";
        break;
      }
      case "bumpSequence": {
        result.type = "bumpSequence";
        result.bumpTo = attrs.bumpTo().toString();
        break;
      }
      case "createClaimableBalance": {
        result.type = "createClaimableBalance";
        result.asset = Asset.fromOperation(attrs.asset());
        result.amount = fromXDRAmount(attrs.amount());
        result.claimants = [];
        attrs.claimants().forEach((claimant) => {
          result.claimants.push(Claimant.fromXDR(claimant));
        });
        break;
      }
      case "claimClaimableBalance": {
        result.type = "claimClaimableBalance";
        result.balanceId = attrs.toXDR("hex");
        break;
      }
      case "beginSponsoringFutureReserves": {
        result.type = "beginSponsoringFutureReserves";
        result.sponsoredId = accountIdtoAddress(attrs.sponsoredId());
        break;
      }
      case "endSponsoringFutureReserves": {
        result.type = "endSponsoringFutureReserves";
        break;
      }
      case "revokeSponsorship": {
        extractRevokeSponshipDetails(attrs, result);
        break;
      }
      case "clawback": {
        result.type = "clawback";
        result.amount = fromXDRAmount(attrs.amount());
        result.from = encodeMuxedAccountToAddress(attrs.from());
        result.asset = Asset.fromOperation(attrs.asset());
        break;
      }
      case "clawbackClaimableBalance": {
        result.type = "clawbackClaimableBalance";
        result.balanceId = attrs.toXDR("hex");
        break;
      }
      case "setTrustLineFlags": {
        result.type = "setTrustLineFlags";
        result.asset = Asset.fromOperation(attrs.asset());
        result.trustor = accountIdtoAddress(attrs.trustor());
        const clears = attrs.clearFlags();
        const sets = attrs.setFlags();
        const mapping = {
          authorized: types.TrustLineFlags.authorizedFlag(),
          authorizedToMaintainLiabilities: types.TrustLineFlags.authorizedToMaintainLiabilitiesFlag(),
          clawbackEnabled: types.TrustLineFlags.trustlineClawbackEnabledFlag()
        };
        const getFlagValue = (key) => {
          const bit = mapping[key]?.value ?? 0;
          if (sets & bit) {
            return true;
          }
          if (clears & bit) {
            return false;
          }
          return void 0;
        };
        const flags = {};
        Object.keys(mapping).forEach((flagName) => {
          flags[flagName] = getFlagValue(flagName);
        });
        result.flags = flags;
        break;
      }
      case "liquidityPoolDeposit": {
        result.type = "liquidityPoolDeposit";
        result.liquidityPoolId = attrs.liquidityPoolId().toString("hex");
        result.maxAmountA = fromXDRAmount(attrs.maxAmountA());
        result.maxAmountB = fromXDRAmount(attrs.maxAmountB());
        result.minPrice = fromXDRPrice(attrs.minPrice());
        result.maxPrice = fromXDRPrice(attrs.maxPrice());
        break;
      }
      case "liquidityPoolWithdraw": {
        result.type = "liquidityPoolWithdraw";
        result.liquidityPoolId = attrs.liquidityPoolId().toString("hex");
        result.amount = fromXDRAmount(attrs.amount());
        result.minAmountA = fromXDRAmount(attrs.minAmountA());
        result.minAmountB = fromXDRAmount(attrs.minAmountB());
        break;
      }
      case "invokeHostFunction": {
        result.type = "invokeHostFunction";
        result.func = attrs.hostFunction();
        result.auth = attrs.auth() ?? [];
        break;
      }
      case "extendFootprintTtl": {
        result.type = "extendFootprintTtl";
        result.extendTo = attrs.extendTo();
        break;
      }
      case "restoreFootprint": {
        result.type = "restoreFootprint";
        break;
      }
      default: {
        throw new Error(`Unknown operation: ${operationName}`);
      }
    }
    return result;
  }
  // Attach all imported operations as static methods on the Operation class
  static accountMerge = accountMerge;
  static allowTrust = allowTrust;
  static bumpSequence = bumpSequence;
  static changeTrust = changeTrust;
  static createAccount = createAccount;
  static createClaimableBalance = createClaimableBalance;
  static claimClaimableBalance = claimClaimableBalance;
  static clawbackClaimableBalance = clawbackClaimableBalance;
  static createPassiveSellOffer = createPassiveSellOffer;
  static inflation = inflation;
  static manageData = manageData;
  static manageSellOffer = manageSellOffer;
  static manageBuyOffer = manageBuyOffer;
  static pathPaymentStrictReceive = pathPaymentStrictReceive;
  static pathPaymentStrictSend = pathPaymentStrictSend;
  static payment = payment;
  static setOptions = setOptions;
  static beginSponsoringFutureReserves = beginSponsoringFutureReserves;
  static endSponsoringFutureReserves = endSponsoringFutureReserves;
  static revokeAccountSponsorship = revokeAccountSponsorship;
  static revokeTrustlineSponsorship = revokeTrustlineSponsorship;
  static revokeOfferSponsorship = revokeOfferSponsorship;
  static revokeDataSponsorship = revokeDataSponsorship;
  static revokeClaimableBalanceSponsorship = revokeClaimableBalanceSponsorship;
  static revokeLiquidityPoolSponsorship = revokeLiquidityPoolSponsorship;
  static revokeSignerSponsorship = revokeSignerSponsorship;
  static clawback = clawback;
  static setTrustLineFlags = setTrustLineFlags;
  static liquidityPoolDeposit = liquidityPoolDeposit;
  static liquidityPoolWithdraw = liquidityPoolWithdraw;
  static invokeHostFunction = invokeHostFunction;
  static extendFootprintTtl = extendFootprintTtl;
  static restoreFootprint = restoreFootprint;
  // These are not `xdr.Operation`s directly, but proxies for common
  // versions of `Operation.invokeHostFunction`
  static createStellarAssetContract = createStellarAssetContract;
  static invokeContractFunction = invokeContractFunction;
  static createCustomContract = createCustomContract;
  static uploadContractWasm = uploadContractWasm;
}
function extractRevokeSponshipDetails(attrs, result) {
  switch (attrs.switch().name) {
    case "revokeSponsorshipLedgerEntry": {
      const ledgerKey = attrs.ledgerKey();
      switch (ledgerKey.switch().name) {
        case types.LedgerEntryType.account().name: {
          result.type = "revokeAccountSponsorship";
          result.account = accountIdtoAddress(ledgerKey.account().accountId());
          break;
        }
        case types.LedgerEntryType.trustline().name: {
          result.type = "revokeTrustlineSponsorship";
          result.account = accountIdtoAddress(
            ledgerKey.trustLine().accountId()
          );
          const xdrAsset = ledgerKey.trustLine().asset();
          switch (xdrAsset.switch()) {
            case types.AssetType.assetTypePoolShare():
              result.asset = LiquidityPoolId.fromOperation(xdrAsset);
              break;
            default:
              result.asset = Asset.fromOperation(xdrAsset);
              break;
          }
          break;
        }
        case types.LedgerEntryType.offer().name: {
          result.type = "revokeOfferSponsorship";
          result.seller = accountIdtoAddress(ledgerKey.offer().sellerId());
          result.offerId = ledgerKey.offer().offerId().toString();
          break;
        }
        case types.LedgerEntryType.data().name: {
          result.type = "revokeDataSponsorship";
          result.account = accountIdtoAddress(ledgerKey.data().accountId());
          result.name = ledgerKey.data().dataName().toString("ascii");
          break;
        }
        case types.LedgerEntryType.claimableBalance().name: {
          result.type = "revokeClaimableBalanceSponsorship";
          result.balanceId = ledgerKey.claimableBalance().balanceId().toXDR("hex");
          break;
        }
        case types.LedgerEntryType.liquidityPool().name: {
          result.type = "revokeLiquidityPoolSponsorship";
          result.liquidityPoolId = ledgerKey.liquidityPool().liquidityPoolId().toString("hex");
          break;
        }
        default: {
          throw new Error(`Unknown ledgerKey: ${attrs.switch().name}`);
        }
      }
      break;
    }
    case "revokeSponsorshipSigner": {
      result.type = "revokeSignerSponsorship";
      result.account = accountIdtoAddress(attrs.signer().accountId());
      result.signer = convertXDRSignerKeyToObject(attrs.signer().signerKey());
      break;
    }
    default: {
      throw new Error(`Unknown revokeSponsorship: ${attrs.switch().name}`);
    }
  }
}
function convertXDRSignerKeyToObject(signerKey) {
  const attrs = {};
  switch (signerKey.switch().name) {
    case types.SignerKeyType.signerKeyTypeEd25519().name: {
      attrs.ed25519PublicKey = StrKey.encodeEd25519PublicKey(
        signerKey.ed25519()
      );
      break;
    }
    case types.SignerKeyType.signerKeyTypePreAuthTx().name: {
      attrs.preAuthTx = signerKey.preAuthTx().toString("hex");
      break;
    }
    case types.SignerKeyType.signerKeyTypeHashX().name: {
      attrs.sha256Hash = signerKey.hashX().toString("hex");
      break;
    }
    case types.SignerKeyType.signerKeyTypeEd25519SignedPayload().name: {
      const signedPayload = signerKey.ed25519SignedPayload();
      attrs.ed25519SignedPayload = StrKey.encodeSignedPayload(
        signedPayload.toXDR()
      );
      break;
    }
    default: {
      throw new Error(`Unknown signerKey: ${signerKey.switch().name}`);
    }
  }
  return attrs;
}
function accountIdtoAddress(accountId) {
  return StrKey.encodeEd25519PublicKey(accountId.ed25519());
}

export { AuthClawbackEnabledFlag, AuthImmutableFlag, AuthRequiredFlag, AuthRevocableFlag, Operation };
//# sourceMappingURL=operation.js.map
