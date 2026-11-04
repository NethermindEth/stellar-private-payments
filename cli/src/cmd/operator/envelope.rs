//! `envelope` — collect signatures on an admin call file and send it.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Subcommand;
use serde::Serialize;
use stellar_private_payments::{blocking::Envelopes, operator::SigningStatus};

use super::write::{print_call_of, read_envelope, signing_alias, submit, write_envelope};
use crate::{config::CliConfig, output, stellar_cli};

#[derive(Debug, Subcommand)]
pub enum EnvelopeCommands {
    /// Show the call an envelope file makes and who has signed it
    Describe {
        /// Envelope file, as `--out` writes it
        file: PathBuf,
    },
    /// Add a signature to an envelope file, in place
    Sign {
        /// Envelope file, as `--out` writes it
        file: PathBuf,
        /// `stellar keys` alias to sign with (default: --sign-as, then
        /// --account)
        #[arg(long = "as")]
        alias: Option<String>,
    },
    /// Send an envelope file once it carries enough signatures, and wait
    /// until it lands
    Submit {
        /// Envelope file, as `--out` writes it
        file: PathBuf,
    },
}

pub fn run(config: &CliConfig, command: EnvelopeCommands, json: bool) -> Result<()> {
    let network = config.resolve_network()?;
    let envelopes = Envelopes::open(&network.rpc_url, &network.passphrase)?;
    match command {
        EnvelopeCommands::Describe { file } => {
            let envelope = read_envelope(&file)?;
            let call = envelopes.describe(&envelope)?;
            let status = envelopes.signing_status(&envelope)?;
            if json {
                #[derive(Serialize)]
                struct Described {
                    method: String,
                    contract_id: String,
                    args: Vec<String>,
                    source: String,
                    fee: u32,
                    valid_until: u64,
                    signatures: StatusRow,
                }
                return output::emit(
                    &Described {
                        args: call.args_text(),
                        method: call.method,
                        contract_id: call.contract_id,
                        source: call.source,
                        fee: call.fee,
                        valid_until: call.valid_until,
                        signatures: StatusRow::from(&status),
                    },
                    true,
                );
            }
            print_call_of(&call);
            print_status(&status);
            Ok(())
        }
        EnvelopeCommands::Sign { file, alias } => {
            let envelope = read_envelope(&file)?;
            let call = envelopes.describe(&envelope)?;
            let alias = signing_alias(config, alias.as_deref())?;
            let signer = stellar_cli::public_key(alias, config.stellar_config_dir.as_deref())?;
            if let Some(refusal) =
                sign_refusal(&envelopes.signing_status(&envelope)?, &signer, &call.source)
            {
                bail!("`{alias}` must not sign: {refusal}");
            }
            let signed = stellar_cli::sign_tx(
                alias,
                &envelope,
                &network.rpc_url,
                &network.passphrase,
                config.stellar_config_dir.as_deref(),
            )
            .with_context(|| format!("sign {} as `{alias}`", file.display()))?;
            write_envelope(&file, &signed)?;
            let status = envelopes.signing_status(&signed)?;
            if json {
                return output::emit(&StatusRow::from(&status), true);
            }
            print_status(&status);
            Ok(())
        }
        EnvelopeCommands::Submit { file } => {
            let envelope = read_envelope(&file)?;
            let call = envelopes.describe(&envelope)?;
            let status = envelopes.signing_status(&envelope)?;
            if !status.is_ready() {
                bail!(
                    "the envelope carries weight {} of the {} its source needs; add signatures \
                     with `spp envelope sign`",
                    status.signed_weight,
                    status.threshold
                );
            }
            submit(&envelopes, &envelope, &call, json)
        }
    }
}

#[derive(Serialize)]
struct StatusRow {
    threshold: u32,
    signed_weight: u32,
    ready: bool,
    signers: Vec<SignerRow>,
}

#[derive(Serialize)]
struct SignerRow {
    key: String,
    weight: u32,
    signed: bool,
}

impl From<&SigningStatus> for StatusRow {
    fn from(status: &SigningStatus) -> Self {
        Self {
            threshold: status.threshold,
            signed_weight: status.signed_weight,
            ready: status.is_ready(),
            signers: status
                .signers
                .iter()
                .map(|signer| SignerRow {
                    key: signer.key.clone(),
                    weight: signer.weight,
                    signed: signer.signed,
                })
                .collect(),
        }
    }
}

/// Why `signer` must not sign, or `None`. A signature the call does not use
/// fails it with `tx_bad_auth_extra` and cannot be removed.
fn sign_refusal(status: &SigningStatus, signer: &str, source: &str) -> Option<String> {
    let Some(entry) = status
        .signers
        .iter()
        .find(|s| s.key == signer && s.weight > 0)
    else {
        return Some(format!("{signer} is not a signer of {source}"));
    };
    if status.is_ready() {
        return Some("the envelope already carries the signatures it needs; submit it".into());
    }
    entry
        .signed
        .then(|| format!("{signer} has already signed the envelope"))
}

fn print_status(status: &SigningStatus) {
    output::print_kv(
        "signatures",
        format!(
            "weight {} of {} ({})",
            status.signed_weight,
            status.threshold,
            if status.is_ready() {
                "ready to submit"
            } else {
                "needs more signatures"
            }
        ),
    );
    for signer in &status.signers {
        output::print_kv(
            &format!("  {}", signer.key),
            format!(
                "weight {}, {}",
                signer.weight,
                if signer.signed {
                    "signed"
                } else {
                    "not signed"
                }
            ),
        );
    }
}

#[cfg(test)]
mod tests {
    use stellar_private_payments::operator::SignerWeight;

    use super::*;

    fn status(threshold: u32, signers: &[(&str, u32, bool)]) -> SigningStatus {
        let signers: Vec<SignerWeight> = signers
            .iter()
            .map(|&(key, weight, signed)| SignerWeight {
                key: key.to_string(),
                weight,
                signed,
            })
            .collect();
        let signed_weight = signers.iter().filter(|s| s.signed).map(|s| s.weight).sum();
        SigningStatus {
            threshold,
            signers,
            signed_weight,
        }
    }

    #[test]
    fn a_signer_short_of_the_threshold_may_sign() {
        let status = status(2, &[("A", 0, false), ("B", 1, true), ("C", 1, false)]);
        assert_eq!(sign_refusal(&status, "C", "A"), None);
    }

    #[test]
    fn refuses_a_key_without_weight() {
        let status = status(2, &[("A", 0, false), ("B", 1, false)]);
        assert!(
            sign_refusal(&status, "A", "A")
                .expect("refusal")
                .contains("not a signer")
        );
        assert!(
            sign_refusal(&status, "X", "A")
                .expect("refusal")
                .contains("not a signer")
        );
    }

    #[test]
    fn refuses_a_second_signature_and_one_past_the_threshold() {
        let pending = status(2, &[("B", 1, true), ("C", 1, false)]);
        assert!(
            sign_refusal(&pending, "B", "A")
                .expect("refusal")
                .contains("already signed")
        );
        let ready = status(1, &[("B", 1, true), ("C", 1, false)]);
        assert!(
            sign_refusal(&ready, "C", "A")
                .expect("refusal")
                .contains("submit it")
        );
    }
}
