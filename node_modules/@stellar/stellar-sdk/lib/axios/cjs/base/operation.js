'use strict';

var asset = require('./asset.js');
var liquidity_pool_asset = require('./liquidity_pool_asset.js');
var claimant = require('./claimant.js');
var strkey = require('./strkey.js');
var liquidity_pool_id = require('./liquidity_pool_id.js');
var curr_generated = require('./generated/curr_generated.js');
var util = require('./util/util.js');
var decode_encode_muxed_account = require('./util/decode_encode_muxed_account.js');
var manage_sell_offer = require('./operations/manage_sell_offer.js');
var create_passive_sell_offer = require('./operations/create_passive_sell_offer.js');
var account_merge = require('./operations/account_merge.js');
var allow_trust = require('./operations/allow_trust.js');
var bump_sequence = require('./operations/bump_sequence.js');
var change_trust = require('./operations/change_trust.js');
var create_account = require('./operations/create_account.js');
var create_claimable_balance = require('./operations/create_claimable_balance.js');
var claim_claimable_balance = require('./operations/claim_claimable_balance.js');
var clawback_claimable_balance = require('./operations/clawback_claimable_balance.js');
var inflation = require('./operations/inflation.js');
var manage_data = require('./operations/manage_data.js');
var manage_buy_offer = require('./operations/manage_buy_offer.js');
var path_payment_strict_receive = require('./operations/path_payment_strict_receive.js');
var path_payment_strict_send = require('./operations/path_payment_strict_send.js');
var payment = require('./operations/payment.js');
var set_options = require('./operations/set_options.js');
var begin_sponsoring_future_reserves = require('./operations/begin_sponsoring_future_reserves.js');
var end_sponsoring_future_reserves = require('./operations/end_sponsoring_future_reserves.js');
var revoke_sponsorship = require('./operations/revoke_sponsorship.js');
var clawback = require('./operations/clawback.js');
var set_trustline_flags = require('./operations/set_trustline_flags.js');
var liquidity_pool_deposit = require('./operations/liquidity_pool_deposit.js');
var liquidity_pool_withdraw = require('./operations/liquidity_pool_withdraw.js');
var invoke_host_function = require('./operations/invoke_host_function.js');
var extend_footprint_ttl = require('./operations/extend_footprint_ttl.js');
var restore_footprint = require('./operations/restore_footprint.js');
var operations = require('./util/operations.js');

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
      result.source = decode_encode_muxed_account.encodeMuxedAccountToAddress(sourceAccount);
    }
    const attrs = operation.body().value();
    const operationName = operation.body().switch().name;
    switch (operationName) {
      case "createAccount": {
        result.type = "createAccount";
        result.destination = accountIdtoAddress(attrs.destination());
        result.startingBalance = operations.fromXDRAmount(attrs.startingBalance());
        break;
      }
      case "payment": {
        result.type = "payment";
        result.destination = decode_encode_muxed_account.encodeMuxedAccountToAddress(attrs.destination());
        result.asset = asset.Asset.fromOperation(attrs.asset());
        result.amount = operations.fromXDRAmount(attrs.amount());
        break;
      }
      case "pathPaymentStrictReceive": {
        result.type = "pathPaymentStrictReceive";
        result.sendAsset = asset.Asset.fromOperation(attrs.sendAsset());
        result.sendMax = operations.fromXDRAmount(attrs.sendMax());
        result.destination = decode_encode_muxed_account.encodeMuxedAccountToAddress(attrs.destination());
        result.destAsset = asset.Asset.fromOperation(attrs.destAsset());
        result.destAmount = operations.fromXDRAmount(attrs.destAmount());
        result.path = [];
        const path = attrs.path();
        Object.keys(path).forEach((pathKey) => {
          result.path.push(asset.Asset.fromOperation(path[pathKey]));
        });
        break;
      }
      case "pathPaymentStrictSend": {
        result.type = "pathPaymentStrictSend";
        result.sendAsset = asset.Asset.fromOperation(attrs.sendAsset());
        result.sendAmount = operations.fromXDRAmount(attrs.sendAmount());
        result.destination = decode_encode_muxed_account.encodeMuxedAccountToAddress(attrs.destination());
        result.destAsset = asset.Asset.fromOperation(attrs.destAsset());
        result.destMin = operations.fromXDRAmount(attrs.destMin());
        result.path = [];
        const path = attrs.path();
        Object.keys(path).forEach((pathKey) => {
          result.path.push(asset.Asset.fromOperation(path[pathKey]));
        });
        break;
      }
      case "changeTrust": {
        result.type = "changeTrust";
        switch (attrs.line().switch()) {
          case curr_generated.default.AssetType.assetTypePoolShare():
            result.line = liquidity_pool_asset.LiquidityPoolAsset.fromOperation(attrs.line());
            break;
          default:
            result.line = asset.Asset.fromOperation(attrs.line());
            break;
        }
        result.limit = operations.fromXDRAmount(attrs.limit());
        break;
      }
      case "allowTrust": {
        result.type = "allowTrust";
        result.trustor = accountIdtoAddress(attrs.trustor());
        result.assetCode = attrs.asset().value().toString();
        result.assetCode = util.trimEnd(result.assetCode, "\0");
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
            signer.ed25519SignedPayload = strkey.StrKey.encodeSignedPayload(
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
        result.selling = asset.Asset.fromOperation(attrs.selling());
        result.buying = asset.Asset.fromOperation(attrs.buying());
        result.amount = operations.fromXDRAmount(attrs.amount());
        result.price = operations.fromXDRPrice(attrs.price());
        result.offerId = attrs.offerId().toString();
        break;
      }
      case "manageBuyOffer": {
        result.type = "manageBuyOffer";
        result.selling = asset.Asset.fromOperation(attrs.selling());
        result.buying = asset.Asset.fromOperation(attrs.buying());
        result.buyAmount = operations.fromXDRAmount(attrs.buyAmount());
        result.price = operations.fromXDRPrice(attrs.price());
        result.offerId = attrs.offerId().toString();
        break;
      }
      // the next case intentionally falls through!
      case "createPassiveOffer":
      case "createPassiveSellOffer": {
        result.type = "createPassiveSellOffer";
        result.selling = asset.Asset.fromOperation(attrs.selling());
        result.buying = asset.Asset.fromOperation(attrs.buying());
        result.amount = operations.fromXDRAmount(attrs.amount());
        result.price = operations.fromXDRPrice(attrs.price());
        break;
      }
      case "accountMerge": {
        result.type = "accountMerge";
        result.destination = decode_encode_muxed_account.encodeMuxedAccountToAddress(attrs);
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
        result.asset = asset.Asset.fromOperation(attrs.asset());
        result.amount = operations.fromXDRAmount(attrs.amount());
        result.claimants = [];
        attrs.claimants().forEach((claimant$1) => {
          result.claimants.push(claimant.Claimant.fromXDR(claimant$1));
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
        result.amount = operations.fromXDRAmount(attrs.amount());
        result.from = decode_encode_muxed_account.encodeMuxedAccountToAddress(attrs.from());
        result.asset = asset.Asset.fromOperation(attrs.asset());
        break;
      }
      case "clawbackClaimableBalance": {
        result.type = "clawbackClaimableBalance";
        result.balanceId = attrs.toXDR("hex");
        break;
      }
      case "setTrustLineFlags": {
        result.type = "setTrustLineFlags";
        result.asset = asset.Asset.fromOperation(attrs.asset());
        result.trustor = accountIdtoAddress(attrs.trustor());
        const clears = attrs.clearFlags();
        const sets = attrs.setFlags();
        const mapping = {
          authorized: curr_generated.default.TrustLineFlags.authorizedFlag(),
          authorizedToMaintainLiabilities: curr_generated.default.TrustLineFlags.authorizedToMaintainLiabilitiesFlag(),
          clawbackEnabled: curr_generated.default.TrustLineFlags.trustlineClawbackEnabledFlag()
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
        result.maxAmountA = operations.fromXDRAmount(attrs.maxAmountA());
        result.maxAmountB = operations.fromXDRAmount(attrs.maxAmountB());
        result.minPrice = operations.fromXDRPrice(attrs.minPrice());
        result.maxPrice = operations.fromXDRPrice(attrs.maxPrice());
        break;
      }
      case "liquidityPoolWithdraw": {
        result.type = "liquidityPoolWithdraw";
        result.liquidityPoolId = attrs.liquidityPoolId().toString("hex");
        result.amount = operations.fromXDRAmount(attrs.amount());
        result.minAmountA = operations.fromXDRAmount(attrs.minAmountA());
        result.minAmountB = operations.fromXDRAmount(attrs.minAmountB());
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
  static accountMerge = account_merge.accountMerge;
  static allowTrust = allow_trust.allowTrust;
  static bumpSequence = bump_sequence.bumpSequence;
  static changeTrust = change_trust.changeTrust;
  static createAccount = create_account.createAccount;
  static createClaimableBalance = create_claimable_balance.createClaimableBalance;
  static claimClaimableBalance = claim_claimable_balance.claimClaimableBalance;
  static clawbackClaimableBalance = clawback_claimable_balance.clawbackClaimableBalance;
  static createPassiveSellOffer = create_passive_sell_offer.createPassiveSellOffer;
  static inflation = inflation.inflation;
  static manageData = manage_data.manageData;
  static manageSellOffer = manage_sell_offer.manageSellOffer;
  static manageBuyOffer = manage_buy_offer.manageBuyOffer;
  static pathPaymentStrictReceive = path_payment_strict_receive.pathPaymentStrictReceive;
  static pathPaymentStrictSend = path_payment_strict_send.pathPaymentStrictSend;
  static payment = payment.payment;
  static setOptions = set_options.setOptions;
  static beginSponsoringFutureReserves = begin_sponsoring_future_reserves.beginSponsoringFutureReserves;
  static endSponsoringFutureReserves = end_sponsoring_future_reserves.endSponsoringFutureReserves;
  static revokeAccountSponsorship = revoke_sponsorship.revokeAccountSponsorship;
  static revokeTrustlineSponsorship = revoke_sponsorship.revokeTrustlineSponsorship;
  static revokeOfferSponsorship = revoke_sponsorship.revokeOfferSponsorship;
  static revokeDataSponsorship = revoke_sponsorship.revokeDataSponsorship;
  static revokeClaimableBalanceSponsorship = revoke_sponsorship.revokeClaimableBalanceSponsorship;
  static revokeLiquidityPoolSponsorship = revoke_sponsorship.revokeLiquidityPoolSponsorship;
  static revokeSignerSponsorship = revoke_sponsorship.revokeSignerSponsorship;
  static clawback = clawback.clawback;
  static setTrustLineFlags = set_trustline_flags.setTrustLineFlags;
  static liquidityPoolDeposit = liquidity_pool_deposit.liquidityPoolDeposit;
  static liquidityPoolWithdraw = liquidity_pool_withdraw.liquidityPoolWithdraw;
  static invokeHostFunction = invoke_host_function.invokeHostFunction;
  static extendFootprintTtl = extend_footprint_ttl.extendFootprintTtl;
  static restoreFootprint = restore_footprint.restoreFootprint;
  // These are not `xdr.Operation`s directly, but proxies for common
  // versions of `Operation.invokeHostFunction`
  static createStellarAssetContract = invoke_host_function.createStellarAssetContract;
  static invokeContractFunction = invoke_host_function.invokeContractFunction;
  static createCustomContract = invoke_host_function.createCustomContract;
  static uploadContractWasm = invoke_host_function.uploadContractWasm;
}
function extractRevokeSponshipDetails(attrs, result) {
  switch (attrs.switch().name) {
    case "revokeSponsorshipLedgerEntry": {
      const ledgerKey = attrs.ledgerKey();
      switch (ledgerKey.switch().name) {
        case curr_generated.default.LedgerEntryType.account().name: {
          result.type = "revokeAccountSponsorship";
          result.account = accountIdtoAddress(ledgerKey.account().accountId());
          break;
        }
        case curr_generated.default.LedgerEntryType.trustline().name: {
          result.type = "revokeTrustlineSponsorship";
          result.account = accountIdtoAddress(
            ledgerKey.trustLine().accountId()
          );
          const xdrAsset = ledgerKey.trustLine().asset();
          switch (xdrAsset.switch()) {
            case curr_generated.default.AssetType.assetTypePoolShare():
              result.asset = liquidity_pool_id.LiquidityPoolId.fromOperation(xdrAsset);
              break;
            default:
              result.asset = asset.Asset.fromOperation(xdrAsset);
              break;
          }
          break;
        }
        case curr_generated.default.LedgerEntryType.offer().name: {
          result.type = "revokeOfferSponsorship";
          result.seller = accountIdtoAddress(ledgerKey.offer().sellerId());
          result.offerId = ledgerKey.offer().offerId().toString();
          break;
        }
        case curr_generated.default.LedgerEntryType.data().name: {
          result.type = "revokeDataSponsorship";
          result.account = accountIdtoAddress(ledgerKey.data().accountId());
          result.name = ledgerKey.data().dataName().toString("ascii");
          break;
        }
        case curr_generated.default.LedgerEntryType.claimableBalance().name: {
          result.type = "revokeClaimableBalanceSponsorship";
          result.balanceId = ledgerKey.claimableBalance().balanceId().toXDR("hex");
          break;
        }
        case curr_generated.default.LedgerEntryType.liquidityPool().name: {
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
    case curr_generated.default.SignerKeyType.signerKeyTypeEd25519().name: {
      attrs.ed25519PublicKey = strkey.StrKey.encodeEd25519PublicKey(
        signerKey.ed25519()
      );
      break;
    }
    case curr_generated.default.SignerKeyType.signerKeyTypePreAuthTx().name: {
      attrs.preAuthTx = signerKey.preAuthTx().toString("hex");
      break;
    }
    case curr_generated.default.SignerKeyType.signerKeyTypeHashX().name: {
      attrs.sha256Hash = signerKey.hashX().toString("hex");
      break;
    }
    case curr_generated.default.SignerKeyType.signerKeyTypeEd25519SignedPayload().name: {
      const signedPayload = signerKey.ed25519SignedPayload();
      attrs.ed25519SignedPayload = strkey.StrKey.encodeSignedPayload(
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
  return strkey.StrKey.encodeEd25519PublicKey(accountId.ed25519());
}

exports.AuthClawbackEnabledFlag = AuthClawbackEnabledFlag;
exports.AuthImmutableFlag = AuthImmutableFlag;
exports.AuthRequiredFlag = AuthRequiredFlag;
exports.AuthRevocableFlag = AuthRevocableFlag;
exports.Operation = Operation;
//# sourceMappingURL=operation.js.map
