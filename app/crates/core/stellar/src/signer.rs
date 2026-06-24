//! Transaction signing for pool submit flows.
//!
//! # Procedure
//!
//! After [`crate::tx_prepare`] simulates a contract call, [`PreparedSorobanTx`]
//! holds an unsigned v1 envelope plus base64 auth entries from recording-mode
//! simulation. Signing completes two steps (see
//! [`LocalSigner::sign_prepared_transaction`]):
//!
//! 1. **Auth entries** — build `HashIdPreimage::SorobanAuthorization`, sign the
//!    XDR preimage, patch `SorobanAddressCredentials.signature`.
//! 2. **Transaction envelope** — sign the unsigned v1 envelope (local: hash +
//!    append `DecoratedSignature`; wallet: `signTransaction` on tx XDR).
//!
//! Wallet signing is async at the platform boundary; this module provides sync
//! orchestration via [`auth_sign_steps`], [`unsigned_tx_for_signing`], and
//! [`LocalSigner`].

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature as DalekSignature, Signer as _, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use stellar_strkey::ed25519::{self, PrivateKey};
use stellar_xdr::curr::{
    self as xdr, DecoratedSignature, Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization,
    Limits, OperationBody, ReadXdr, ScBytes, ScMap, ScSymbol, ScVal, SorobanAuthorizationEntry,
    SorobanCredentials, TransactionEnvelope, VecM, WriteXdr,
};

use crate::{contract_state::PreparedSorobanTx, conversions::scval_to_address_string};

/// Auth validity
///
/// Matches js-stellar-sdk's default (~8.3 minutes at ~5s/ledger).
const AUTH_EXPIRATION_LEDGERS: u32 = 100;

fn network_id(network_passphrase: &str) -> [u8; 32] {
    Sha256::digest(network_passphrase.as_bytes()).into()
}

/// Ed25519 signature (64 bytes).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Signature([u8; 64]);

impl Signature {
    pub const LEN: usize = 64;

    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    pub fn from_base64(s: &str) -> Result<Self> {
        let bytes = STANDARD.decode(s).context("base64 decode failed")?;
        let sig: [u8; 64] = bytes
            .as_slice()
            .try_into()
            .context("signature must be 64 bytes")?;
        Ok(Self::from_bytes(sig))
    }

    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

/// In-process Ed25519 signer (secret key).
pub struct LocalSigner {
    public_key: String,
    signing_key: SigningKey,
}

impl LocalSigner {
    pub fn from_secret(secret: &str) -> Result<Self> {
        let private_key: PrivateKey = secret
            .parse()
            .map_err(|e| anyhow!("invalid secret key: {e}"))?;
        let signing_key = SigningKey::from_bytes(&private_key.0);
        let verifying_key = signing_key.verifying_key();
        let public_key = ed25519::PublicKey(verifying_key.to_bytes())
            .to_string()
            .to_string();
        Ok(Self {
            public_key,
            signing_key,
        })
    }

    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    /// Ed25519 signature over a 32-byte digest (already hashed).
    pub fn sign_digest(&self, digest: &[u8; 32]) -> Signature {
        Signature::from_bytes(self.signing_key.sign(digest).to_bytes())
    }

    /// SHA-256 hash of `data`, then [`Self::sign_digest`].
    pub fn sign(&self, data: &[u8]) -> Signature {
        let hash: [u8; 32] = Sha256::digest(data).into();
        self.sign_digest(&hash)
    }

    /// Signs a Soroban auth preimage.
    pub fn sign_auth_preimage(&self, preimage: &HashIdPreimage) -> Result<Signature> {
        let bytes = preimage
            .to_xdr(Limits::none())
            .context("encode auth preimage xdr")?;
        Ok(self.sign(&bytes))
    }

    /// Signs a v1 transaction envelope and appends a `DecoratedSignature`.
    pub fn sign_transaction(
        &self,
        mut envelope: TransactionEnvelope,
        network_passphrase: &str,
    ) -> Result<TransactionEnvelope> {
        let tx_hash = envelope
            .hash(network_id(network_passphrase))
            .context("hash transaction envelope")?;
        let signature = self.sign_digest(&tx_hash);
        let public_key: ed25519::PublicKey = self
            .public_key()
            .parse()
            .context("invalid signer public key strkey")?;
        let hint: xdr::SignatureHint = public_key.0[28..32]
            .try_into()
            .map_err(|_| anyhow!("invalid signature hint"))?;
        let decorated = DecoratedSignature {
            hint,
            signature: xdr::Signature(
                (*signature.as_bytes())
                    .try_into()
                    .map_err(|_| anyhow!("invalid signature length"))?,
            ),
        };

        match &mut envelope {
            TransactionEnvelope::Tx(v1) => {
                let mut signatures = v1.signatures.to_vec();
                signatures.push(decorated);
                v1.signatures = VecM::try_from(signatures).context("attach tx signature")?;
            }
            _ => bail!("unsupported transaction envelope (expected v1)"),
        }

        Ok(envelope)
    }

    /// Signs a prepared transaction (auth entries + envelope).
    pub fn sign_prepared_transaction(
        &self,
        prepared: &PreparedSorobanTx,
        network_passphrase: &str,
        user_address: &str,
    ) -> Result<TransactionEnvelope> {
        if self.public_key() != user_address {
            bail!("secret key does not match user_address");
        }
        let steps = auth_sign_steps(prepared, network_passphrase, user_address)?;
        let mut auth_signatures = Vec::with_capacity(steps.len());
        for step in &steps {
            auth_signatures.push((step.entry_index, self.sign_auth_preimage(&step.preimage)?));
        }
        let tx_b64 = unsigned_tx_for_signing(prepared, user_address, &auth_signatures)?;
        let envelope = TransactionEnvelope::from_xdr_base64(&tx_b64, Limits::none())
            .context("invalid tx xdr")?;
        self.sign_transaction(envelope, network_passphrase)
    }
}

/// One Soroban auth preimage the wallet must sign (`signAuthEntry`).
#[derive(Debug, Clone)]
pub struct AuthSignStep {
    pub entry_index: usize,
    preimage: HashIdPreimage,
}

impl AuthSignStep {
    /// Base64 XDR for Freighter `signAuthEntry`.
    pub fn wallet_preimage_b64(&self) -> Result<String> {
        self.preimage
            .to_xdr_base64(Limits::none())
            .context("encode auth preimage xdr")
    }
}

/// Auth preimage steps required for `user_address` on a prepared transaction.
pub fn auth_sign_steps(
    prepared: &PreparedSorobanTx,
    network_passphrase: &str,
    user_address: &str,
) -> Result<Vec<AuthSignStep>> {
    let expiration = auth_expiration_ledger(prepared);
    let mut steps = Vec::new();
    for (entry_index, entry_b64) in prepared.auth_entries.iter().enumerate() {
        let entry = SorobanAuthorizationEntry::from_xdr_base64(entry_b64, Limits::none())
            .context("invalid auth entry xdr")?;
        if needs_wallet_auth(&entry, user_address)? {
            steps.push(AuthSignStep {
                entry_index,
                preimage: soroban_auth_preimage(&entry, network_passphrase, expiration)?,
            });
        }
    }
    Ok(steps)
}

/// Unsigned transaction envelope (base64) with signed auth entries attached.
pub fn unsigned_tx_for_signing(
    prepared: &PreparedSorobanTx,
    user_address: &str,
    auth_signatures: &[(usize, Signature)],
) -> Result<String> {
    let expiration = auth_expiration_ledger(prepared);
    let public_key: ed25519::PublicKey = user_address
        .parse()
        .context("invalid user address strkey")?;
    let mut sigs_by_index: std::collections::BTreeMap<usize, Signature> =
        auth_signatures.iter().copied().collect();

    let mut needs_patch = false;
    let mut signed_auth = Vec::with_capacity(prepared.auth_entries.len());
    for (entry_index, entry_b64) in prepared.auth_entries.iter().enumerate() {
        let mut entry = SorobanAuthorizationEntry::from_xdr_base64(entry_b64, Limits::none())
            .context("invalid auth entry xdr")?;
        if needs_wallet_auth(&entry, user_address)? {
            needs_patch = true;
            let signature = sigs_by_index
                .remove(&entry_index)
                .with_context(|| format!("missing auth signature for entry index {entry_index}"))?;
            apply_address_auth_signature(&mut entry, &public_key.0, &signature, expiration)?;
        }
        signed_auth.push(entry);
    }
    if !sigs_by_index.is_empty() {
        bail!("unexpected auth signatures for non-wallet auth entries");
    }

    let mut tx_xdr = prepared.tx_xdr.clone();
    if needs_patch {
        let mut envelope = TransactionEnvelope::from_xdr_base64(&tx_xdr, Limits::none())
            .context("invalid prepared tx xdr")?;
        patch_auth_entries(&mut envelope, signed_auth)?;
        tx_xdr = envelope
            .to_xdr_base64(Limits::none())
            .context("encode patched tx xdr")?;
    }
    Ok(tx_xdr)
}

fn auth_expiration_ledger(prepared: &PreparedSorobanTx) -> u32 {
    prepared
        .latest_ledger
        .saturating_add(AUTH_EXPIRATION_LEDGERS)
}

fn soroban_auth_preimage(
    entry: &SorobanAuthorizationEntry,
    network_passphrase: &str,
    expiration_ledger: u32,
) -> Result<HashIdPreimage> {
    let SorobanCredentials::Address(creds) = &entry.credentials else {
        bail!("soroban_auth_preimage requires address credentials");
    };
    Ok(HashIdPreimage::SorobanAuthorization(
        HashIdPreimageSorobanAuthorization {
            network_id: Hash(network_id(network_passphrase)),
            nonce: creds.nonce,
            signature_expiration_ledger: expiration_ledger,
            invocation: entry.root_invocation.clone(),
        },
    ))
}

/// Patches address credentials with a wallet-produced Ed25519 signature.
fn apply_address_auth_signature(
    entry: &mut SorobanAuthorizationEntry,
    public_key: &[u8; 32],
    signature: &Signature,
    expiration_ledger: u32,
) -> Result<()> {
    let SorobanCredentials::Address(creds) = &mut entry.credentials else {
        bail!("apply_address_auth_signature requires address credentials");
    };
    if !matches!(creds.signature, ScVal::Void) {
        bail!("auth entry already signed");
    }
    creds.signature_expiration_ledger = expiration_ledger;
    creds.signature = address_credentials_signature(public_key, signature)?;
    Ok(())
}

fn needs_wallet_auth(entry: &SorobanAuthorizationEntry, address: &str) -> Result<bool> {
    let SorobanCredentials::Address(creds) = &entry.credentials else {
        return Ok(false);
    };
    if !matches!(creds.signature, ScVal::Void) {
        return Ok(false);
    }
    Ok(scval_to_address_string(&ScVal::Address(creds.address.clone()))? == address)
}

fn address_credentials_signature(public_key: &[u8; 32], signature: &Signature) -> Result<ScVal> {
    let public_key_bytes: xdr::BytesM = public_key
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("public key bytes"))?;
    let signature_bytes: xdr::BytesM = signature
        .as_bytes()
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("signature bytes"))?;

    let ed25519_sig = ScVal::Map(Some(
        ScMap::sorted_from([
            (
                ScVal::Symbol(
                    ScSymbol::try_from("public_key").map_err(|()| anyhow!("public_key symbol"))?,
                ),
                ScVal::Bytes(ScBytes(public_key_bytes)),
            ),
            (
                ScVal::Symbol(
                    ScSymbol::try_from("signature").map_err(|()| anyhow!("signature symbol"))?,
                ),
                ScVal::Bytes(ScBytes(signature_bytes)),
            ),
        ])
        .context("auth signature map")?,
    ));

    let sc_vec = xdr::ScVec::try_from(vec![ed25519_sig]).context("auth signature vec")?;
    Ok(ScVal::Vec(Some(sc_vec)))
}

fn patch_auth_entries(
    envelope: &mut TransactionEnvelope,
    signed_auth: Vec<SorobanAuthorizationEntry>,
) -> Result<()> {
    let xdr::TransactionEnvelope::Tx(v1) = envelope else {
        bail!("unsupported transaction envelope (expected v1)");
    };

    for op in v1.tx.operations.iter_mut() {
        let OperationBody::InvokeHostFunction(invoke) = &mut op.body else {
            continue;
        };
        invoke.auth = VecM::try_from(signed_auth).context("attach signed auth entries")?;
        return Ok(());
    }

    bail!("no invokeHostFunction operation found to attach auth entries");
}

/// Hash signed over when the signature at `signature_index` was created.
fn tx_hash_for_signature(
    signed_envelope: &TransactionEnvelope,
    network_passphrase: &str,
    signature_index: usize,
) -> Result<[u8; 32]> {
    let mut envelope = signed_envelope.clone();
    let xdr::TransactionEnvelope::Tx(v1) = &mut envelope else {
        bail!("expected v1 envelope");
    };
    let prior_signatures: Vec<_> = v1
        .signatures
        .iter()
        .take(signature_index)
        .cloned()
        .collect();
    v1.signatures = VecM::try_from(prior_signatures).context("prior signatures")?;
    envelope
        .hash(network_id(network_passphrase))
        .context("hash transaction envelope")
}

/// Verifies the Ed25519 signature at `signature_index` in a signed v1 envelope.
pub fn verify_tx(
    envelope: &TransactionEnvelope,
    network_passphrase: &str,
    signer_public_key: &str,
    signature_index: usize,
) -> Result<()> {
    let xdr::TransactionEnvelope::Tx(v1) = envelope else {
        bail!("expected v1 envelope");
    };
    let decorated = v1
        .signatures
        .get(signature_index)
        .context("signature index out of range")?;

    let tx_hash = tx_hash_for_signature(envelope, network_passphrase, signature_index)?;

    let public_key: ed25519::PublicKey = signer_public_key
        .parse()
        .context("invalid signer public key strkey")?;
    let hint: [u8; 4] = public_key.0[28..32]
        .try_into()
        .map_err(|_| anyhow!("invalid signature hint"))?;
    if decorated.hint.0 != hint {
        bail!("signature hint mismatch");
    }

    let signature = DalekSignature::from_bytes(
        decorated
            .signature
            .0
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("invalid signature length"))?,
    );
    let verifying_key = VerifyingKey::from_bytes(&public_key.0)
        .map_err(|e| anyhow!("invalid verifying key: {e}"))?;
    verifying_key
        .verify(&tx_hash, &signature)
        .map_err(|e| anyhow!("transaction signature invalid: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx_assemble::test_fixtures;
    use ed25519_dalek::SigningKey;

    const TEST_PASSPHRASE: &str = "Test SDF Network ; September 2015";

    fn test_signer() -> LocalSigner {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let secret = PrivateKey(signing_key.to_bytes()).to_string().to_string();
        LocalSigner::from_secret(&secret).expect("fixture signer")
    }

    fn test_prepared_tx(user_address: &str) -> PreparedSorobanTx {
        use stellar_xdr::curr::{
            AccountId, InvokeContractArgs, PublicKey, ScAddress, ScSymbol,
            SorobanAddressCredentials, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
            SorobanAuthorizedInvocation, SorobanCredentials, Uint256, VecM, WriteXdr,
        };

        let public_key: ed25519::PublicKey = user_address.parse().expect("parse address");
        let wallet = ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
            public_key.0,
        ))));
        let entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: wallet,
                nonce: 0,
                signature_expiration_ledger: 0,
                signature: ScVal::Void,
            }),
            root_invocation: SorobanAuthorizedInvocation {
                function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                    contract_address: ScAddress::Contract(xdr::ContractId(xdr::Hash([2u8; 32]))),
                    function_name: ScSymbol::try_from("transact").expect("symbol"),
                    args: VecM::default(),
                }),
                sub_invocations: VecM::default(),
            },
        };

        PreparedSorobanTx {
            tx_xdr: test_fixtures::empty_envelope()
                .to_xdr_base64(Limits::none())
                .expect("tx xdr"),
            auth_entries: vec![entry.to_xdr_base64(Limits::none()).expect("auth entry xdr")],
            latest_ledger: 100,
        }
    }

    #[test]
    fn from_base64_roundtrip() {
        let bytes = [42u8; 64];
        let b64 = STANDARD.encode(bytes);
        let sig = Signature::from_base64(&b64).expect("decode");
        assert_eq!(sig, Signature::from_bytes(bytes));
    }

    #[test]
    fn from_base64_rejects_wrong_length() {
        let b64 = STANDARD.encode([1u8; 32]);
        assert!(Signature::from_base64(&b64).is_err());
    }

    #[test]
    fn sign_deterministic() {
        let signer = test_signer();
        let payload = [7u8; 32];
        let sig1 = signer.sign_digest(&payload);
        let sig2 = signer.sign_digest(&payload);
        assert_eq!(sig1, sig2);
        assert_ne!(sig1, Signature::from_bytes([0u8; 64]));
    }

    #[test]
    fn sign_verify() {
        let signer = test_signer();
        let envelope = test_fixtures::empty_envelope();
        let signed = signer
            .sign_transaction(envelope, TEST_PASSPHRASE)
            .expect("sign tx");
        verify_tx(&signed, TEST_PASSPHRASE, signer.public_key(), 0).expect("verify tx");
    }

    #[test]
    fn sign_prepared_transaction() {
        let signer = test_signer();
        let user_address = signer.public_key().to_string();
        let prepared = test_prepared_tx(&user_address);

        let steps = auth_sign_steps(&prepared, TEST_PASSPHRASE, &user_address).expect("auth steps");
        assert_eq!(steps.len(), 1);

        let signed = signer
            .sign_prepared_transaction(&prepared, TEST_PASSPHRASE, &user_address)
            .expect("sign prepared tx");
        verify_tx(&signed, TEST_PASSPHRASE, &user_address, 0).expect("verify tx");

        let xdr::TransactionEnvelope::Tx(v1) = &signed else {
            panic!("expected v1 envelope");
        };
        let OperationBody::InvokeHostFunction(invoke) = &v1.tx.operations[0].body else {
            panic!("expected invoke");
        };
        assert_eq!(invoke.auth.len(), 1);
        let SorobanCredentials::Address(creds) = &invoke.auth[0].credentials else {
            panic!("expected address credentials");
        };
        assert!(!matches!(creds.signature, ScVal::Void));
        assert_eq!(
            creds.signature_expiration_ledger,
            prepared.latest_ledger + AUTH_EXPIRATION_LEDGERS
        );
    }
}
