'use strict';

var buffer = require('buffer');
var curr_generated = require('./generated/curr_generated.js');
var keypair = require('./keypair.js');
var strkey = require('./strkey.js');
var hashing = require('./hashing.js');
var address = require('./address.js');
var scval = require('./scval.js');

function toBuffer(value) {
  if (value instanceof ArrayBuffer) {
    return buffer.Buffer.from(new Uint8Array(value));
  }
  return buffer.Buffer.from(value);
}
async function authorizeEntry(entry, signer, validUntilLedgerSeq, networkPassphrase, forAddress) {
  if (entry.credentials().switch().value === curr_generated.default.SorobanCredentialsType.sorobanCredentialsSourceAccount().value) {
    return entry;
  }
  const clone = curr_generated.default.SorobanAuthorizationEntry.fromXDR(entry.toXDR());
  const credentials = clone.credentials();
  const addrAuth = getAddressCredentials(credentials);
  if (addrAuth === null) {
    throw new Error(`unsupported credential type ${credentials.switch().name}`);
  }
  addrAuth.signatureExpirationLedger(validUntilLedgerSeq);
  const preimage = buildAuthorizationEntryPreimage(
    clone,
    validUntilLedgerSeq,
    networkPassphrase
  );
  const payload = hashing.hash(preimage.toXDR());
  let signature;
  let publicKey;
  if (typeof signer === "function") {
    const sigResult = await signer(preimage);
    if (sigResult !== null && typeof sigResult === "object" && "signature" in sigResult) {
      signature = toBuffer(sigResult.signature);
      publicKey = sigResult.publicKey;
    } else {
      signature = toBuffer(sigResult);
      publicKey = address.Address.fromScAddress(addrAuth.address()).toString();
    }
  } else {
    signature = toBuffer(signer.sign(payload));
    publicKey = signer.publicKey();
  }
  if (!keypair.Keypair.fromPublicKey(publicKey).verify(payload, signature)) {
    throw new Error(`signature doesn't match payload`);
  }
  const sigScVal = scval.nativeToScVal(
    {
      public_key: strkey.StrKey.decodeEd25519PublicKey(publicKey),
      signature
    },
    {
      type: {
        public_key: ["symbol", null],
        signature: ["symbol", null]
      }
    }
  );
  const signatureScVal = curr_generated.default.ScVal.scvVec([sigScVal]);
  const targets = forAddress === void 0 ? [addrAuth] : collectSignatureNodes(credentials).filter(
    (node) => address.Address.fromScAddress(node.address()).toString() === forAddress
  );
  if (targets.length === 0) {
    throw new Error(
      `the authorization entry has no credential node for address ${forAddress}`
    );
  }
  targets.forEach((node) => node.signature(signatureScVal));
  return clone;
}
function authorizeInvocation(params) {
  const {
    signer,
    validUntilLedgerSeq,
    invocation,
    networkPassphrase,
    publicKey = "",
    authV2 = false
  } = params;
  const kp = keypair.Keypair.random().rawPublicKey();
  const nonce = new curr_generated.default.Int64(bytesToInt64(kp));
  const pk = publicKey || (signer instanceof keypair.Keypair ? signer.publicKey() : null);
  if (!pk) {
    throw new Error(`authorizeInvocation requires publicKey parameter`);
  }
  const addressCredentials = new curr_generated.default.SorobanAddressCredentials({
    address: new address.Address(pk).toScAddress(),
    nonce,
    signatureExpirationLedger: 0,
    // replaced
    signature: curr_generated.default.ScVal.scvVec([])
    // replaced
  });
  const entry = new curr_generated.default.SorobanAuthorizationEntry({
    rootInvocation: invocation,
    credentials: authV2 ? curr_generated.default.SorobanCredentials.sorobanCredentialsAddressV2(addressCredentials) : curr_generated.default.SorobanCredentials.sorobanCredentialsAddress(addressCredentials)
  });
  return authorizeEntry(entry, signer, validUntilLedgerSeq, networkPassphrase);
}
function buildAuthorizationEntryPreimage(entry, validUntilLedgerSeq, networkPassphrase) {
  const credentials = entry.credentials();
  const addrAuth = getAddressCredentials(credentials);
  if (addrAuth === null) {
    throw new Error(
      `cannot build a signature payload for credential type ${credentials.switch().name}`
    );
  }
  const networkId = hashing.hash(buffer.Buffer.from(networkPassphrase));
  switch (credentials.switch().value) {
    // legacy address credentials are not address-bound
    case curr_generated.default.SorobanCredentialsType.sorobanCredentialsAddress().value:
      return curr_generated.default.HashIdPreimage.envelopeTypeSorobanAuthorization(
        new curr_generated.default.HashIdPreimageSorobanAuthorization({
          networkId,
          nonce: addrAuth.nonce(),
          invocation: entry.rootInvocation(),
          signatureExpirationLedger: validUntilLedgerSeq
        })
      );
    // ADDRESS_V2 and ADDRESS_WITH_DELEGATES bind the address into the signed
    // payload via the WithAddress preimage (CAP-71)
    case curr_generated.default.SorobanCredentialsType.sorobanCredentialsAddressV2().value:
    case curr_generated.default.SorobanCredentialsType.sorobanCredentialsAddressWithDelegates().value:
      return curr_generated.default.HashIdPreimage.envelopeTypeSorobanAuthorizationWithAddress(
        new curr_generated.default.HashIdPreimageSorobanAuthorizationWithAddress({
          networkId,
          nonce: addrAuth.nonce(),
          invocation: entry.rootInvocation(),
          address: addrAuth.address(),
          signatureExpirationLedger: validUntilLedgerSeq
        })
      );
    default:
      throw new Error(
        `unsupported credential type ${credentials.switch().name}`
      );
  }
}
function buildWithDelegatesEntry(params) {
  const { entry, validUntilLedgerSeq, delegates, signature } = params;
  const credentials = entry.credentials();
  const addrAuth = getAddressCredentials(credentials);
  if (addrAuth === null || credentials.switch().value === curr_generated.default.SorobanCredentialsType.sorobanCredentialsAddressWithDelegates().value) {
    throw new Error(
      `buildWithDelegatesEntry expects ADDRESS or ADDRESS_V2 credentials, got ${credentials.switch().name}`
    );
  }
  return new curr_generated.default.SorobanAuthorizationEntry({
    rootInvocation: entry.rootInvocation(),
    credentials: curr_generated.default.SorobanCredentials.sorobanCredentialsAddressWithDelegates(
      new curr_generated.default.SorobanAddressCredentialsWithDelegates({
        addressCredentials: new curr_generated.default.SorobanAddressCredentials({
          address: addrAuth.address(),
          nonce: addrAuth.nonce(),
          signatureExpirationLedger: validUntilLedgerSeq,
          signature: signature ?? curr_generated.default.ScVal.scvVoid()
        }),
        delegates: buildDelegateNodes(delegates)
      })
    )
  });
}
function buildDelegateNodes(delegates) {
  const nodes = delegates.map(
    (delegate) => new curr_generated.default.SorobanDelegateSignature({
      address: new address.Address(delegate.address).toScAddress(),
      signature: delegate.signature ?? curr_generated.default.ScVal.scvVoid(),
      nestedDelegates: buildDelegateNodes(delegate.nestedDelegates ?? [])
    })
  );
  nodes.sort(
    (a, b) => buffer.Buffer.compare(a.address().toXDR(), b.address().toXDR())
  );
  for (let i = 1; i < nodes.length; i++) {
    if (buffer.Buffer.compare(
      nodes[i - 1].address().toXDR(),
      nodes[i].address().toXDR()
    ) === 0) {
      throw new Error(
        `duplicate delegate address ${address.Address.fromScAddress(
          nodes[i].address()
        ).toString()}`
      );
    }
  }
  return nodes;
}
function getAddressCredentials(credentials) {
  switch (credentials.switch().value) {
    case curr_generated.default.SorobanCredentialsType.sorobanCredentialsAddress().value:
      return credentials.address();
    case curr_generated.default.SorobanCredentialsType.sorobanCredentialsAddressV2().value:
      return credentials.addressV2();
    case curr_generated.default.SorobanCredentialsType.sorobanCredentialsAddressWithDelegates().value:
      return credentials.addressWithDelegates().addressCredentials();
    default:
      return null;
  }
}
function collectSignatureNodes(credentials) {
  switch (credentials.switch().value) {
    case curr_generated.default.SorobanCredentialsType.sorobanCredentialsAddress().value:
      return [credentials.address()];
    case curr_generated.default.SorobanCredentialsType.sorobanCredentialsAddressV2().value:
      return [credentials.addressV2()];
    case curr_generated.default.SorobanCredentialsType.sorobanCredentialsAddressWithDelegates().value: {
      const withDelegates = credentials.addressWithDelegates();
      const nodes = [withDelegates.addressCredentials()];
      const walk = (delegates) => {
        delegates.forEach((delegate) => {
          nodes.push(delegate);
          walk(delegate.nestedDelegates());
        });
      };
      walk(withDelegates.delegates());
      return nodes;
    }
    default:
      return [];
  }
}
function bytesToInt64(bytes) {
  const buf = bytes.subarray(0, 8);
  if (buf.length < 8) {
    throw new Error(
      `need at least 8 bytes to convert to Int64, got ${bytes.length}`
    );
  }
  const view = new DataView(buf.buffer, buf.byteOffset, 8);
  const value = view.getBigInt64(0, false);
  return value;
}

exports.authorizeEntry = authorizeEntry;
exports.authorizeInvocation = authorizeInvocation;
exports.buildAuthorizationEntryPreimage = buildAuthorizationEntryPreimage;
exports.buildWithDelegatesEntry = buildWithDelegatesEntry;
exports.getAddressCredentials = getAddressCredentials;
//# sourceMappingURL=auth.js.map
