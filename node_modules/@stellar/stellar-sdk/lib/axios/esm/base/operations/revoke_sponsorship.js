import { Buffer } from 'buffer';
import types from '../generated/curr_generated.js';
import { StrKey } from '../strkey.js';
import { Keypair } from '../keypair.js';
import { Asset } from '../asset.js';
import { LiquidityPoolId } from '../liquidity_pool_id.js';
import { setSourceAccount } from '../util/operations.js';

function revokeAccountSponsorship(opts = {}) {
  if (!StrKey.isValidEd25519PublicKey(opts.account)) {
    throw new Error("account is invalid");
  }
  const ledgerKey = types.LedgerKey.account(
    new types.LedgerKeyAccount({
      accountId: Keypair.fromPublicKey(opts.account).xdrAccountId()
    })
  );
  const op = types.RevokeSponsorshipOp.revokeSponsorshipLedgerEntry(ledgerKey);
  const opAttributes = {
    sourceAccount: null,
    body: types.OperationBody.revokeSponsorship(op)
  };
  setSourceAccount(opAttributes, opts);
  return new types.Operation(opAttributes);
}
function revokeTrustlineSponsorship(opts = {}) {
  if (!StrKey.isValidEd25519PublicKey(opts.account)) {
    throw new Error("account is invalid");
  }
  let asset;
  if (opts.asset instanceof Asset) {
    asset = opts.asset.toTrustLineXDRObject();
  } else if (opts.asset instanceof LiquidityPoolId) {
    asset = opts.asset.toXDRObject();
  } else {
    throw new TypeError("asset must be an Asset or LiquidityPoolId");
  }
  const ledgerKey = types.LedgerKey.trustline(
    new types.LedgerKeyTrustLine({
      accountId: Keypair.fromPublicKey(opts.account).xdrAccountId(),
      asset
    })
  );
  const op = types.RevokeSponsorshipOp.revokeSponsorshipLedgerEntry(ledgerKey);
  const opAttributes = {
    sourceAccount: null,
    body: types.OperationBody.revokeSponsorship(op)
  };
  setSourceAccount(opAttributes, opts);
  return new types.Operation(opAttributes);
}
function revokeOfferSponsorship(opts = {}) {
  if (!StrKey.isValidEd25519PublicKey(opts.seller)) {
    throw new Error("seller is invalid");
  }
  if (typeof opts.offerId !== "string") {
    throw new Error("offerId is invalid");
  }
  const ledgerKey = types.LedgerKey.offer(
    new types.LedgerKeyOffer({
      sellerId: Keypair.fromPublicKey(opts.seller).xdrAccountId(),
      offerId: types.Int64.fromString(opts.offerId)
    })
  );
  const op = types.RevokeSponsorshipOp.revokeSponsorshipLedgerEntry(ledgerKey);
  const opAttributes = {
    sourceAccount: null,
    body: types.OperationBody.revokeSponsorship(op)
  };
  setSourceAccount(opAttributes, opts);
  return new types.Operation(opAttributes);
}
function revokeDataSponsorship(opts = {}) {
  if (!StrKey.isValidEd25519PublicKey(opts.account)) {
    throw new Error("account is invalid");
  }
  if (typeof opts.name !== "string" || opts.name.length > 64) {
    throw new Error("name must be a string, up to 64 characters");
  }
  const ledgerKey = types.LedgerKey.data(
    new types.LedgerKeyData({
      accountId: Keypair.fromPublicKey(opts.account).xdrAccountId(),
      dataName: opts.name
    })
  );
  const op = types.RevokeSponsorshipOp.revokeSponsorshipLedgerEntry(ledgerKey);
  const opAttributes = {
    sourceAccount: null,
    body: types.OperationBody.revokeSponsorship(op)
  };
  setSourceAccount(opAttributes, opts);
  return new types.Operation(opAttributes);
}
function revokeClaimableBalanceSponsorship(opts = {}) {
  if (typeof opts.balanceId !== "string") {
    throw new Error("balanceId is invalid");
  }
  const ledgerKey = types.LedgerKey.claimableBalance(
    new types.LedgerKeyClaimableBalance({
      balanceId: types.ClaimableBalanceId.fromXDR(opts.balanceId, "hex")
    })
  );
  const op = types.RevokeSponsorshipOp.revokeSponsorshipLedgerEntry(ledgerKey);
  const opAttributes = {
    sourceAccount: null,
    body: types.OperationBody.revokeSponsorship(op)
  };
  setSourceAccount(opAttributes, opts);
  return new types.Operation(opAttributes);
}
function revokeLiquidityPoolSponsorship(opts = {}) {
  if (typeof opts.liquidityPoolId !== "string") {
    throw new Error("liquidityPoolId is invalid");
  }
  const ledgerKey = types.LedgerKey.liquidityPool(
    new types.LedgerKeyLiquidityPool({
      liquidityPoolId: Buffer.from(
        opts.liquidityPoolId,
        "hex"
      )
    })
  );
  const op = types.RevokeSponsorshipOp.revokeSponsorshipLedgerEntry(ledgerKey);
  const opAttributes = {
    sourceAccount: null,
    body: types.OperationBody.revokeSponsorship(op)
  };
  setSourceAccount(opAttributes, opts);
  return new types.Operation(opAttributes);
}
function revokeSignerSponsorship(opts = {}) {
  if (!StrKey.isValidEd25519PublicKey(opts.account)) {
    throw new Error("account is invalid");
  }
  let key;
  if (opts.signer.ed25519PublicKey) {
    if (!StrKey.isValidEd25519PublicKey(opts.signer.ed25519PublicKey)) {
      throw new Error("signer.ed25519PublicKey is invalid.");
    }
    const rawKey = StrKey.decodeEd25519PublicKey(opts.signer.ed25519PublicKey);
    key = types.SignerKey.signerKeyTypeEd25519(rawKey);
  } else if (opts.signer.preAuthTx) {
    let buffer;
    if (typeof opts.signer.preAuthTx === "string") {
      buffer = Buffer.from(opts.signer.preAuthTx, "hex");
    } else {
      buffer = opts.signer.preAuthTx;
    }
    if (!(Buffer.isBuffer(buffer) && buffer.length === 32)) {
      throw new Error("signer.preAuthTx must be 32 bytes Buffer.");
    }
    key = types.SignerKey.signerKeyTypePreAuthTx(buffer);
  } else if (opts.signer.sha256Hash) {
    let buffer;
    if (typeof opts.signer.sha256Hash === "string") {
      buffer = Buffer.from(opts.signer.sha256Hash, "hex");
    } else {
      buffer = opts.signer.sha256Hash;
    }
    if (!(Buffer.isBuffer(buffer) && buffer.length === 32)) {
      throw new Error("signer.sha256Hash must be 32 bytes Buffer.");
    }
    key = types.SignerKey.signerKeyTypeHashX(buffer);
  } else if (opts.signer.ed25519SignedPayload) {
    if (!StrKey.isValidSignedPayload(opts.signer.ed25519SignedPayload)) {
      throw new Error("signer.ed25519SignedPayload is invalid.");
    }
    const rawPayload = StrKey.decodeSignedPayload(
      opts.signer.ed25519SignedPayload
    );
    const signedPayloadXdr = types.SignerKeyEd25519SignedPayload.fromXDR(rawPayload);
    key = types.SignerKey.signerKeyTypeEd25519SignedPayload(signedPayloadXdr);
  } else {
    throw new Error("signer is invalid");
  }
  const signer = new types.RevokeSponsorshipOpSigner({
    accountId: Keypair.fromPublicKey(opts.account).xdrAccountId(),
    signerKey: key
  });
  const op = types.RevokeSponsorshipOp.revokeSponsorshipSigner(signer);
  const opAttributes = {
    sourceAccount: null,
    body: types.OperationBody.revokeSponsorship(op)
  };
  setSourceAccount(opAttributes, opts);
  return new types.Operation(opAttributes);
}

export { revokeAccountSponsorship, revokeClaimableBalanceSponsorship, revokeDataSponsorship, revokeLiquidityPoolSponsorship, revokeOfferSponsorship, revokeSignerSponsorship, revokeTrustlineSponsorship };
//# sourceMappingURL=revoke_sponsorship.js.map
