'use strict';

var buffer = require('buffer');
var curr_generated = require('../generated/curr_generated.js');
var strkey = require('../strkey.js');
var keypair = require('../keypair.js');
var asset = require('../asset.js');
var liquidity_pool_id = require('../liquidity_pool_id.js');
var operations = require('../util/operations.js');

function revokeAccountSponsorship(opts = {}) {
  if (!strkey.StrKey.isValidEd25519PublicKey(opts.account)) {
    throw new Error("account is invalid");
  }
  const ledgerKey = curr_generated.default.LedgerKey.account(
    new curr_generated.default.LedgerKeyAccount({
      accountId: keypair.Keypair.fromPublicKey(opts.account).xdrAccountId()
    })
  );
  const op = curr_generated.default.RevokeSponsorshipOp.revokeSponsorshipLedgerEntry(ledgerKey);
  const opAttributes = {
    sourceAccount: null,
    body: curr_generated.default.OperationBody.revokeSponsorship(op)
  };
  operations.setSourceAccount(opAttributes, opts);
  return new curr_generated.default.Operation(opAttributes);
}
function revokeTrustlineSponsorship(opts = {}) {
  if (!strkey.StrKey.isValidEd25519PublicKey(opts.account)) {
    throw new Error("account is invalid");
  }
  let asset$1;
  if (opts.asset instanceof asset.Asset) {
    asset$1 = opts.asset.toTrustLineXDRObject();
  } else if (opts.asset instanceof liquidity_pool_id.LiquidityPoolId) {
    asset$1 = opts.asset.toXDRObject();
  } else {
    throw new TypeError("asset must be an Asset or LiquidityPoolId");
  }
  const ledgerKey = curr_generated.default.LedgerKey.trustline(
    new curr_generated.default.LedgerKeyTrustLine({
      accountId: keypair.Keypair.fromPublicKey(opts.account).xdrAccountId(),
      asset: asset$1
    })
  );
  const op = curr_generated.default.RevokeSponsorshipOp.revokeSponsorshipLedgerEntry(ledgerKey);
  const opAttributes = {
    sourceAccount: null,
    body: curr_generated.default.OperationBody.revokeSponsorship(op)
  };
  operations.setSourceAccount(opAttributes, opts);
  return new curr_generated.default.Operation(opAttributes);
}
function revokeOfferSponsorship(opts = {}) {
  if (!strkey.StrKey.isValidEd25519PublicKey(opts.seller)) {
    throw new Error("seller is invalid");
  }
  if (typeof opts.offerId !== "string") {
    throw new Error("offerId is invalid");
  }
  const ledgerKey = curr_generated.default.LedgerKey.offer(
    new curr_generated.default.LedgerKeyOffer({
      sellerId: keypair.Keypair.fromPublicKey(opts.seller).xdrAccountId(),
      offerId: curr_generated.default.Int64.fromString(opts.offerId)
    })
  );
  const op = curr_generated.default.RevokeSponsorshipOp.revokeSponsorshipLedgerEntry(ledgerKey);
  const opAttributes = {
    sourceAccount: null,
    body: curr_generated.default.OperationBody.revokeSponsorship(op)
  };
  operations.setSourceAccount(opAttributes, opts);
  return new curr_generated.default.Operation(opAttributes);
}
function revokeDataSponsorship(opts = {}) {
  if (!strkey.StrKey.isValidEd25519PublicKey(opts.account)) {
    throw new Error("account is invalid");
  }
  if (typeof opts.name !== "string" || opts.name.length > 64) {
    throw new Error("name must be a string, up to 64 characters");
  }
  const ledgerKey = curr_generated.default.LedgerKey.data(
    new curr_generated.default.LedgerKeyData({
      accountId: keypair.Keypair.fromPublicKey(opts.account).xdrAccountId(),
      dataName: opts.name
    })
  );
  const op = curr_generated.default.RevokeSponsorshipOp.revokeSponsorshipLedgerEntry(ledgerKey);
  const opAttributes = {
    sourceAccount: null,
    body: curr_generated.default.OperationBody.revokeSponsorship(op)
  };
  operations.setSourceAccount(opAttributes, opts);
  return new curr_generated.default.Operation(opAttributes);
}
function revokeClaimableBalanceSponsorship(opts = {}) {
  if (typeof opts.balanceId !== "string") {
    throw new Error("balanceId is invalid");
  }
  const ledgerKey = curr_generated.default.LedgerKey.claimableBalance(
    new curr_generated.default.LedgerKeyClaimableBalance({
      balanceId: curr_generated.default.ClaimableBalanceId.fromXDR(opts.balanceId, "hex")
    })
  );
  const op = curr_generated.default.RevokeSponsorshipOp.revokeSponsorshipLedgerEntry(ledgerKey);
  const opAttributes = {
    sourceAccount: null,
    body: curr_generated.default.OperationBody.revokeSponsorship(op)
  };
  operations.setSourceAccount(opAttributes, opts);
  return new curr_generated.default.Operation(opAttributes);
}
function revokeLiquidityPoolSponsorship(opts = {}) {
  if (typeof opts.liquidityPoolId !== "string") {
    throw new Error("liquidityPoolId is invalid");
  }
  const ledgerKey = curr_generated.default.LedgerKey.liquidityPool(
    new curr_generated.default.LedgerKeyLiquidityPool({
      liquidityPoolId: buffer.Buffer.from(
        opts.liquidityPoolId,
        "hex"
      )
    })
  );
  const op = curr_generated.default.RevokeSponsorshipOp.revokeSponsorshipLedgerEntry(ledgerKey);
  const opAttributes = {
    sourceAccount: null,
    body: curr_generated.default.OperationBody.revokeSponsorship(op)
  };
  operations.setSourceAccount(opAttributes, opts);
  return new curr_generated.default.Operation(opAttributes);
}
function revokeSignerSponsorship(opts = {}) {
  if (!strkey.StrKey.isValidEd25519PublicKey(opts.account)) {
    throw new Error("account is invalid");
  }
  let key;
  if (opts.signer.ed25519PublicKey) {
    if (!strkey.StrKey.isValidEd25519PublicKey(opts.signer.ed25519PublicKey)) {
      throw new Error("signer.ed25519PublicKey is invalid.");
    }
    const rawKey = strkey.StrKey.decodeEd25519PublicKey(opts.signer.ed25519PublicKey);
    key = curr_generated.default.SignerKey.signerKeyTypeEd25519(rawKey);
  } else if (opts.signer.preAuthTx) {
    let buffer$1;
    if (typeof opts.signer.preAuthTx === "string") {
      buffer$1 = buffer.Buffer.from(opts.signer.preAuthTx, "hex");
    } else {
      buffer$1 = opts.signer.preAuthTx;
    }
    if (!(buffer.Buffer.isBuffer(buffer$1) && buffer$1.length === 32)) {
      throw new Error("signer.preAuthTx must be 32 bytes Buffer.");
    }
    key = curr_generated.default.SignerKey.signerKeyTypePreAuthTx(buffer$1);
  } else if (opts.signer.sha256Hash) {
    let buffer$1;
    if (typeof opts.signer.sha256Hash === "string") {
      buffer$1 = buffer.Buffer.from(opts.signer.sha256Hash, "hex");
    } else {
      buffer$1 = opts.signer.sha256Hash;
    }
    if (!(buffer.Buffer.isBuffer(buffer$1) && buffer$1.length === 32)) {
      throw new Error("signer.sha256Hash must be 32 bytes Buffer.");
    }
    key = curr_generated.default.SignerKey.signerKeyTypeHashX(buffer$1);
  } else if (opts.signer.ed25519SignedPayload) {
    if (!strkey.StrKey.isValidSignedPayload(opts.signer.ed25519SignedPayload)) {
      throw new Error("signer.ed25519SignedPayload is invalid.");
    }
    const rawPayload = strkey.StrKey.decodeSignedPayload(
      opts.signer.ed25519SignedPayload
    );
    const signedPayloadXdr = curr_generated.default.SignerKeyEd25519SignedPayload.fromXDR(rawPayload);
    key = curr_generated.default.SignerKey.signerKeyTypeEd25519SignedPayload(signedPayloadXdr);
  } else {
    throw new Error("signer is invalid");
  }
  const signer = new curr_generated.default.RevokeSponsorshipOpSigner({
    accountId: keypair.Keypair.fromPublicKey(opts.account).xdrAccountId(),
    signerKey: key
  });
  const op = curr_generated.default.RevokeSponsorshipOp.revokeSponsorshipSigner(signer);
  const opAttributes = {
    sourceAccount: null,
    body: curr_generated.default.OperationBody.revokeSponsorship(op)
  };
  operations.setSourceAccount(opAttributes, opts);
  return new curr_generated.default.Operation(opAttributes);
}

exports.revokeAccountSponsorship = revokeAccountSponsorship;
exports.revokeClaimableBalanceSponsorship = revokeClaimableBalanceSponsorship;
exports.revokeDataSponsorship = revokeDataSponsorship;
exports.revokeLiquidityPoolSponsorship = revokeLiquidityPoolSponsorship;
exports.revokeOfferSponsorship = revokeOfferSponsorship;
exports.revokeSignerSponsorship = revokeSignerSponsorship;
exports.revokeTrustlineSponsorship = revokeTrustlineSponsorship;
//# sourceMappingURL=revoke_sponsorship.js.map
