use anyhow::{Context, Result, bail};
use sep5::SeedPhrase;
use stellar_private_payments_sdk::chain::LocalSigner;

/// Stellar account credentials resolved from `--secret` or `--mnemonic`.
#[derive(Debug, Clone)]
pub struct WalletCredentials {
    pub address: String,
    pub secret_key: String,
}

pub fn resolve_wallet(
    secret: Option<&str>,
    mnemonic: Option<&str>,
    mnemonic_passphrase: Option<&str>,
    account: Option<&str>,
    account_index: u32,
) -> Result<Option<WalletCredentials>> {
    match (secret, mnemonic) {
        (Some(_), Some(_)) => bail!("use either --secret or --mnemonic, not both"),
        (None, None) => Ok(None),
        (Some(secret), None) => {
            let wallet = wallet_from_secret(secret)?;
            ensure_account_matches(account, &wallet.address)?;
            Ok(Some(wallet))
        }
        (None, Some(mnemonic)) => {
            let wallet = wallet_from_mnemonic(mnemonic, mnemonic_passphrase, account_index)?;
            ensure_account_matches(account, &wallet.address)?;
            Ok(Some(wallet))
        }
    }
}

fn wallet_from_secret(secret: &str) -> Result<WalletCredentials> {
    let signer = LocalSigner::from_secret(secret).context("invalid --secret")?;
    Ok(WalletCredentials {
        address: signer.public_key().to_string(),
        secret_key: secret.to_string(),
    })
}

fn wallet_from_mnemonic(
    mnemonic: &str,
    mnemonic_passphrase: Option<&str>,
    account_index: u32,
) -> Result<WalletCredentials> {
    let seed_phrase = SeedPhrase::from_seed_phrase(mnemonic).context("invalid --mnemonic")?;
    let keypair = seed_phrase
        .from_path_index(
            usize::try_from(account_index).context("invalid --account-index")?,
            mnemonic_passphrase,
        )
        .with_context(|| format!("derive Stellar key m/44'/148'/{account_index}'"))?;
    Ok(WalletCredentials {
        address: keypair.public().to_string().to_string(),
        secret_key: keypair.private().to_string().to_string(),
    })
}

fn ensure_account_matches(expected: Option<&str>, derived: &str) -> Result<()> {
    if let Some(expected) = expected
        && expected != derived
    {
        bail!("--account {expected} does not match derived address {derived}");
    }
    Ok(())
}
