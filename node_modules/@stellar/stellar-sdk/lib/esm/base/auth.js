import { Buffer } from 'buffer';
import types from './generated/curr_generated.js';
import { Keypair } from './keypair.js';
import { StrKey } from './strkey.js';
import { hash } from './hashing.js';
import { Address } from './address.js';
import { nativeToScVal } from './scval.js';

function toBuffer(value) {
  if (value instanceof ArrayBuffer) {
    return Buffer.from(new Uint8Array(value));
  }
  return Buffer.from(value);
}
async function authorizeEntry(entry, signer, validUntilLedgerSeq, networkPassphrase, forAddress) {
  if (entry.credentials().switch().value === types.SorobanCredentialsType.sorobanCredentialsSourceAccount().value) {
    return entry;
  }
  const clone = types.SorobanAuthorizationEntry.fromXDR(entry.toXDR());
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
  const payload = hash(preimage.toXDR());
  let signature;
  let publicKey;
  if (typeof signer === "function") {
    const sigResult = await signer(preimage);
    if (sigResult !== null && typeof sigResult === "object" && "signature" in sigResult) {
      signature = toBuffer(sigResult.signature);
      publicKey = sigResult.publicKey;
    } else {
      signature = toBuffer(sigResult);
      publicKey = Address.fromScAddress(addrAuth.address()).toString();
    }
  } else {
    signature = toBuffer(signer.sign(payload));
    publicKey = signer.publicKey();
  }
  if (!Keypair.fromPublicKey(publicKey).verify(payload, signature)) {
    throw new Error(`signature doesn't match payload`);
  }
  const sigScVal = nativeToScVal(
    {
      public_key: StrKey.decodeEd25519PublicKey(publicKey),
      signature
    },
    {
      type: {
        public_key: ["symbol", null],
        signature: ["symbol", null]
      }
    }
  );
  const signatureScVal = types.ScVal.scvVec([sigScVal]);
  const targets = forAddress === void 0 ? [addrAuth] : collectSignatureNodes(credentials).filter(
    (node) => Address.fromScAddress(node.address()).toString() === forAddress
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
  const kp = Keypair.random().rawPublicKey();
  const nonce = new types.Int64(bytesToInt64(kp));
  const pk = publicKey || (signer instanceof Keypair ? signer.publicKey() : null);
  if (!pk) {
    throw new Error(`authorizeInvocation requires publicKey parameter`);
  }
  const addressCredentials = new types.SorobanAddressCredentials({
    address: new Address(pk).toScAddress(),
    nonce,
    signatureExpirationLedger: 0,
    // replaced
    signature: types.ScVal.scvVec([])
    // replaced
  });
  const entry = new types.SorobanAuthorizationEntry({
    rootInvocation: invocation,
    credentials: authV2 ? types.SorobanCredentials.sorobanCredentialsAddressV2(addressCredentials) : types.SorobanCredentials.sorobanCredentialsAddress(addressCredentials)
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
  const networkId = hash(Buffer.from(networkPassphrase));
  switch (credentials.switch().value) {
    // legacy address credentials are not address-bound
    case types.SorobanCredentialsType.sorobanCredentialsAddress().value:
      return types.HashIdPreimage.envelopeTypeSorobanAuthorization(
        new types.HashIdPreimageSorobanAuthorization({
          networkId,
          nonce: addrAuth.nonce(),
          invocation: entry.rootInvocation(),
          signatureExpirationLedger: validUntilLedgerSeq
        })
      );
    // ADDRESS_V2 and ADDRESS_WITH_DELEGATES bind the address into the signed
    // payload via the WithAddress preimage (CAP-71)
    case types.SorobanCredentialsType.sorobanCredentialsAddressV2().value:
    case types.SorobanCredentialsType.sorobanCredentialsAddressWithDelegates().value:
      return types.HashIdPreimage.envelopeTypeSorobanAuthorizationWithAddress(
        new types.HashIdPreimageSorobanAuthorizationWithAddress({
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
  if (addrAuth === null || credentials.switch().value === types.SorobanCredentialsType.sorobanCredentialsAddressWithDelegates().value) {
    throw new Error(
      `buildWithDelegatesEntry expects ADDRESS or ADDRESS_V2 credentials, got ${credentials.switch().name}`
    );
  }
  return new types.SorobanAuthorizationEntry({
    rootInvocation: entry.rootInvocation(),
    credentials: types.SorobanCredentials.sorobanCredentialsAddressWithDelegates(
      new types.SorobanAddressCredentialsWithDelegates({
        addressCredentials: new types.SorobanAddressCredentials({
          address: addrAuth.address(),
          nonce: addrAuth.nonce(),
          signatureExpirationLedger: validUntilLedgerSeq,
          signature: signature ?? types.ScVal.scvVoid()
        }),
        delegates: buildDelegateNodes(delegates)
      })
    )
  });
}
function buildDelegateNodes(delegates) {
  const nodes = delegates.map(
    (delegate) => new types.SorobanDelegateSignature({
      address: new Address(delegate.address).toScAddress(),
      signature: delegate.signature ?? types.ScVal.scvVoid(),
      nestedDelegates: buildDelegateNodes(delegate.nestedDelegates ?? [])
    })
  );
  nodes.sort(
    (a, b) => Buffer.compare(a.address().toXDR(), b.address().toXDR())
  );
  for (let i = 1; i < nodes.length; i++) {
    if (Buffer.compare(
      nodes[i - 1].address().toXDR(),
      nodes[i].address().toXDR()
    ) === 0) {
      throw new Error(
        `duplicate delegate address ${Address.fromScAddress(
          nodes[i].address()
        ).toString()}`
      );
    }
  }
  return nodes;
}
function getAddressCredentials(credentials) {
  switch (credentials.switch().value) {
    case types.SorobanCredentialsType.sorobanCredentialsAddress().value:
      return credentials.address();
    case types.SorobanCredentialsType.sorobanCredentialsAddressV2().value:
      return credentials.addressV2();
    case types.SorobanCredentialsType.sorobanCredentialsAddressWithDelegates().value:
      return credentials.addressWithDelegates().addressCredentials();
    default:
      return null;
  }
}
function collectSignatureNodes(credentials) {
  switch (credentials.switch().value) {
    case types.SorobanCredentialsType.sorobanCredentialsAddress().value:
      return [credentials.address()];
    case types.SorobanCredentialsType.sorobanCredentialsAddressV2().value:
      return [credentials.addressV2()];
    case types.SorobanCredentialsType.sorobanCredentialsAddressWithDelegates().value: {
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

export { authorizeEntry, authorizeInvocation, buildAuthorizationEntryPreimage, buildWithDelegatesEntry, getAddressCredentials };
//# sourceMappingURL=auth.js.map
