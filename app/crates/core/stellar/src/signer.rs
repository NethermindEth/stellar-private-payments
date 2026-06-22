//! Transaction signing for pool submit flows.
//!
//! # Procedure
//!
//! After [`crate::tx_prepare`] simulates a contract call, [`PreparedSorobanTx`]
//! holds an unsigned v1 envelope plus base64 auth entries from recording-mode
//! simulation. Signing completes two steps (see [`sign_prepared_tx_with`]):
//!
//! 1. **Auth entries** — build `HashIdPreimage::SorobanAuthorization`, sign the
//!    XDR preimage, patch `SorobanAddressCredentials.signature`.
//! 2. **Transaction envelope** — sign the unsigned v1 envelope (local: hash +
//!    append `DecoratedSignature`; wallet: `signTransaction` on tx XDR).
//!
//! Wallet signing is async at the platform boundary; this module provides sync
//! orchestration via [`sign_prepared_tx_with`] and [`LocalSigner`].

use anyhow::{Context, Result, anyhow, bail};
use ed25519_dalek::{Signature as DalekSignature, Signer as _, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use stellar_strkey::ed25519::{self, PrivateKey};
use stellar_xdr::curr::{
    self as xdr, DecoratedSignature, Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization,
    Limits, OperationBody, ReadXdr, ScBytes, ScMap, ScSymbol, ScVal, SorobanAuthorizationEntry,
    SorobanCredentials, TransactionEnvelope, VecM, WriteXdr,
};

use crate::{contract_state::PreparedSorobanTx, conversions::scval_to_address_string};

pub const AUTH_EXPIRATION_LEDGERS: u32 = 100;

pub fn network_id(network_passphrase: &str) -> [u8; 32] {
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

    /// Signs a Soroban auth preimage XDR (base64).
    pub fn sign_auth_preimage_b64(&self, preimage_b64: &str) -> Result<Signature> {
        let payload: HashIdPreimage = HashIdPreimage::from_xdr_base64(preimage_b64, Limits::none())
            .context("invalid preimage")?;
        let bytes = payload
            .to_xdr(Limits::none())
            .context("encode auth preimage xdr")?;
        Ok(self.sign(&bytes))
    }

    /// Signs a v1 transaction envelope and appends a `DecoratedSignature`.
    pub fn sign_transaction_envelope(
        &self,
        envelope: &mut TransactionEnvelope,
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

        match envelope {
            TransactionEnvelope::Tx(v1) => {
                let mut signatures = v1.signatures.to_vec();
                signatures.push(decorated);
                v1.signatures = VecM::try_from(signatures).context("attach tx signature")?;
            }
            _ => bail!("unsupported transaction envelope (expected v1)"),
        }

        Ok(envelope.clone())
    }

    /// Signs an unsigned transaction envelope XDR (base64).
    pub fn sign_transaction_xdr(
        &self,
        tx_xdr_b64: &str,
        network_passphrase: &str,
    ) -> Result<TransactionEnvelope> {
        let mut envelope = TransactionEnvelope::from_xdr_base64(tx_xdr_b64, Limits::none())
            .context("invalid tx xdr")?;
        self.sign_transaction_envelope(&mut envelope, network_passphrase)
    }

    /// Signs a prepared transaction (auth entries + envelope).
    pub fn sign_prepared_tx(
        &self,
        prepared: &PreparedSorobanTx,
        network_passphrase: &str,
        user_address: &str,
    ) -> Result<TransactionEnvelope> {
        if self.public_key() != user_address {
            bail!("secret key does not match user_address");
        }
        sign_prepared_tx_with(
            prepared,
            network_passphrase,
            user_address,
            |preimage_b64| self.sign_auth_preimage_b64(preimage_b64),
            |tx_xdr_b64| self.sign_transaction_xdr(tx_xdr_b64, network_passphrase),
        )
    }
}

/// One Soroban auth preimage the wallet must sign (`signAuthEntry`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthSignStep {
    pub entry_index: usize,
    pub preimage_b64: String,
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
                preimage_b64: soroban_auth_preimage_b64(&entry, network_passphrase, expiration)?,
            });
        }
    }
    Ok(steps)
}

/// Unsigned transaction envelope XDR (base64) with signed auth entries
/// attached.
pub fn unsigned_tx_xdr_for_signing(
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

/// Signs a prepared transaction using platform-specific auth and tx signing
/// hooks.
pub fn sign_prepared_tx_with(
    prepared: &PreparedSorobanTx,
    network_passphrase: &str,
    user_address: &str,
    sign_auth_preimage_b64: impl Fn(&str) -> Result<Signature>,
    sign_transaction_xdr_b64: impl FnOnce(&str) -> Result<TransactionEnvelope>,
) -> Result<TransactionEnvelope> {
    let steps = auth_sign_steps(prepared, network_passphrase, user_address)?;
    let mut auth_signatures = Vec::with_capacity(steps.len());
    for step in &steps {
        auth_signatures.push((
            step.entry_index,
            sign_auth_preimage_b64(&step.preimage_b64)?,
        ));
    }
    let tx_xdr = unsigned_tx_xdr_for_signing(prepared, user_address, &auth_signatures)?;
    sign_transaction_xdr_b64(&tx_xdr)
}

fn auth_expiration_ledger(prepared: &PreparedSorobanTx) -> u32 {
    prepared
        .latest_ledger
        .saturating_add(AUTH_EXPIRATION_LEDGERS)
}

/// Base64 XDR of `HashIdPreimage::SorobanAuthorization` for wallet
/// `signAuthEntry`.
pub fn soroban_auth_preimage_b64(
    entry: &SorobanAuthorizationEntry,
    network_passphrase: &str,
    expiration_ledger: u32,
) -> Result<String> {
    let SorobanCredentials::Address(creds) = &entry.credentials else {
        bail!("soroban_auth_preimage_b64 requires address credentials");
    };
    let payload = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: Hash(network_id(network_passphrase)),
        nonce: creds.nonce,
        signature_expiration_ledger: expiration_ledger,
        invocation: entry.root_invocation.clone(),
    });
    payload
        .to_xdr_base64(Limits::none())
        .context("encode auth preimage xdr")
}

/// Patches address credentials with a wallet-produced Ed25519 signature.
pub fn apply_address_auth_signature(
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

pub fn needs_wallet_auth(entry: &SorobanAuthorizationEntry, address: &str) -> Result<bool> {
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

pub fn patch_auth_entries(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx_assemble::test_fixtures;
    use ed25519_dalek::SigningKey;

    const TEST_PASSPHRASE: &str = "Test SDF Network ; September 2015";

    fn fixture_signer() -> LocalSigner {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let secret = PrivateKey(signing_key.to_bytes()).to_string().to_string();
        LocalSigner::from_secret(&secret).expect("fixture signer")
    }

    #[test]
    fn sign_deterministic() {
        let signer = fixture_signer();
        let payload = [7u8; 32];
        let sig1 = signer.sign_digest(&payload);
        let sig2 = signer.sign_digest(&payload);
        assert_eq!(sig1, sig2);
        assert_ne!(sig1, Signature::from_bytes([0u8; 64]));
    }

    #[test]
    fn sign_verify() {
        let signer = fixture_signer();
        let mut envelope = test_fixtures::empty_envelope();
        let signed = signer
            .sign_transaction_envelope(&mut envelope, TEST_PASSPHRASE)
            .expect("sign tx");
        verify_tx(&signed, TEST_PASSPHRASE, signer.public_key(), 0).expect("verify tx");
    }
}
