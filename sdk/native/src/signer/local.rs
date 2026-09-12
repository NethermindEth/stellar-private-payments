use crate::chain::{Limits, LocalSigner as StellarSigner, PreparedSorobanTx, WriteXdr};

use super::Signer;
use crate::{
    PreparedTransaction,
    error::Error,
    types::{KeyDerivationSignature, SignedTransaction, SignerAddress},
};

/// SEP-53 message prefix, matching the Stellar CLI and browser wallets
/// (`stellar message sign`, Freighter's `signMessage`).
const SEP53_PREFIX: &str = "Stellar Signed Message:\n";

/// In-process Ed25519 signer for native CLI and tests.
pub struct LocalSigner {
    stellar: StellarSigner,
    network_passphrase: String,
    signer_address: SignerAddress,
}

impl LocalSigner {
    pub fn new(
        secret_key: &str,
        network_passphrase: impl Into<String>,
        signer_address: SignerAddress,
    ) -> Result<Self, Error> {
        Ok(Self {
            stellar: StellarSigner::from_secret(secret_key)
                .map_err(|e| Error::Other(format!("signer: {e:#}")))?,
            network_passphrase: network_passphrase.into(),
            signer_address,
        })
    }

    pub fn stellar_signer(&self) -> &StellarSigner {
        &self.stellar
    }

    pub fn network_passphrase(&self) -> &str {
        &self.network_passphrase
    }

    pub fn signer_address(&self) -> &SignerAddress {
        &self.signer_address
    }
}

#[async_trait::async_trait(?Send)]
impl Signer for LocalSigner {
    async fn sign_transaction(
        &self,
        prepared: &PreparedTransaction,
    ) -> Result<SignedTransaction, Error> {
        self.sign_soroban_transaction(&prepared.soroban_tx).await
    }

    async fn sign_soroban_transaction(
        &self,
        prepared: &PreparedSorobanTx,
    ) -> Result<SignedTransaction, Error> {
        let envelope = self
            .stellar
            .sign_prepared_transaction(prepared, &self.network_passphrase, &self.signer_address)
            .map_err(|e| Error::Other(format!("sign transaction: {e:#}")))?;
        let signed_xdr = envelope
            .to_xdr_base64(Limits::none())
            .map_err(|e| Error::Other(format!("encode signed transaction xdr: {e}")))?;
        Ok(SignedTransaction { signed_xdr })
    }

    async fn sign_message(&self, message: &str) -> Result<KeyDerivationSignature, Error> {
        let prefixed = format!("{SEP53_PREFIX}{message}");
        let signature = self.stellar.sign(prefixed.as_bytes());
        Ok(KeyDerivationSignature(signature.as_bytes().to_vec()))
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    /// Cross-check against a real `stellar message sign` invocation:
    ///
    /// ```text
    /// stellar keys add sep53test --secret-key <<< SADQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQP54X
    /// stellar message sign "Privacy Pool Key Derivation [v1]" --sign-with-key sep53test
    /// ```
    const SECRET: &str = "SADQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQP54X";
    const PUBLIC: &str = "GDVEU3DD4KOFECV66VIHWEZOYX4ZKR3WV27L464SIIPOU2IUI3JCZA57";
    const MESSAGE: &str = "Privacy Pool Key Derivation [v1]";
    const EXPECTED_SIGNATURE_B64: &str =
        "sVN7t6f95HnWra/b23AqHVVhEXlS2wEBd2Sng7yqHjRKoieWbmbGNnFQST+L08ON4YrUYp9NMaJhdMT0w6jHDg==";

    #[tokio::test]
    async fn sep53_known_answer() {
        let signer = LocalSigner::new(
            SECRET,
            "Test SDF Network ; September 2015",
            SignerAddress::new(PUBLIC),
        )
        .expect("build signer");
        let signature = signer.sign_message(MESSAGE).await.expect("sign message");
        assert_eq!(
            STANDARD.encode(&signature.0),
            EXPECTED_SIGNATURE_B64,
            "must match the SEP-53 signature produced by the real stellar CLI"
        );
    }
}
