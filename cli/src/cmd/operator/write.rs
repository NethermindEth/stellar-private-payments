//! How a write command hands over its admin call: sent at once, or written to
//! a file for the admin's signers.

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use serde::Serialize;
use stellar_private_payments::{
    blocking::Envelopes,
    operator::{CallState, CallStatus, OperatorCall, UnsignedOperatorCall, result_code},
};

use crate::{config::CliConfig, output, stellar_cli, stellar_cli::StellarNetwork};

const CONFIRM_ATTEMPTS: u32 = 60;

#[derive(Debug, Args)]
pub struct WriteArgs {
    /// Write the unsigned envelope here for the admin's signers (`spp
    /// envelope sign`) instead of signing it with --sign-as or --account and
    /// sending it
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// Continue past a check that asks for confirmation, without asking
    #[arg(long)]
    pub yes: bool,
}

/// Admin transfer of one contract.
#[derive(Debug, Subcommand)]
pub enum AdminCommands {
    /// Propose a new admin, who takes over once it runs `admin accept`
    Propose {
        /// The proposed admin (G… or C…)
        #[arg(long)]
        new_admin: String,
        #[command(flatten)]
        write: WriteArgs,
    },
    /// Withdraw the pending admin transfer
    Cancel {
        #[command(flatten)]
        write: WriteArgs,
    },
    /// Complete the pending admin transfer, signed by the pending admin
    Accept {
        #[command(flatten)]
        write: WriteArgs,
    },
}

impl AdminCommands {
    pub fn write(&self) -> &WriteArgs {
        match self {
            Self::Propose { write, .. } | Self::Cancel { write } | Self::Accept { write } => write,
        }
    }
}

#[derive(Serialize)]
struct CallRow<'a> {
    method: &'a str,
    contract_id: &'a str,
    args: Vec<String>,
    source: &'a str,
    fee: u32,
    valid_until: u64,
}

impl<'a> From<&'a OperatorCall> for CallRow<'a> {
    fn from(call: &'a OperatorCall) -> Self {
        Self {
            method: &call.method,
            contract_id: &call.contract_id,
            args: call.args_text(),
            source: &call.source,
            fee: call.fee,
            valid_until: call.valid_until,
        }
    }
}

/// Writes `built` to `--out`, or signs it and sends it when that signature
/// alone meets the source's threshold.
pub fn deliver(
    config: &CliConfig,
    network: &StellarNetwork,
    built: UnsignedOperatorCall,
    args: &WriteArgs,
    json: bool,
) -> Result<()> {
    if let Some(path) = &args.out {
        write_envelope(path, &built.envelope_xdr)?;
        #[derive(Serialize)]
        struct Written<'a> {
            envelope_file: String,
            #[serde(flatten)]
            call: CallRow<'a>,
        }
        let written = Written {
            envelope_file: path.display().to_string(),
            call: CallRow::from(&built.call),
        };
        if json {
            return output::emit(&written, true);
        }
        print_call(&written.call);
        output::print_kv("envelope_file", &written.envelope_file);
        return Ok(());
    }

    let alias = signing_alias(config, None)?;
    let signed = stellar_cli::sign_tx(
        alias,
        &built.envelope_xdr,
        &network.rpc_url,
        &network.passphrase,
        config.stellar_config_dir.as_deref(),
    )
    .with_context(|| format!("sign the {} call as `{alias}`", built.call.method))?;
    let envelopes = Envelopes::open(&network.rpc_url, &network.passphrase)?;
    let status = envelopes.signing_status(&signed)?;
    if !status.is_ready() {
        bail!(
            "`{alias}` carries weight {} of the {} the admin {} needs; build the call with --out \
             and collect the other signatures with `spp envelope sign`",
            status.signed_weight,
            status.threshold,
            built.call.source
        );
    }
    submit(&envelopes, &signed, &built.call, json)
}

/// Sends a signed envelope and waits until it lands.
pub fn submit(envelopes: &Envelopes, signed: &str, call: &OperatorCall, json: bool) -> Result<()> {
    let hash = envelopes.submit(signed)?;
    for _ in 0..CONFIRM_ATTEMPTS {
        match envelopes.confirm(&hash)? {
            CallStatus::Success => return report_sent(&hash, call, json),
            CallStatus::Failed {
                result_xdr,
                host_error,
            } => bail!(
                "{} {hash} failed: {}",
                call.method,
                failure(result_xdr.as_deref(), host_error.as_deref())
            ),
            CallStatus::Pending => std::thread::sleep(Duration::from_secs(1)),
        }
    }
    bail!(
        "{} {hash} did not land within {CONFIRM_ATTEMPTS} seconds",
        call.method
    )
}

/// Prints the call that landed in `hash`.
pub fn report_sent(hash: &str, call: &OperatorCall, json: bool) -> Result<()> {
    #[derive(Serialize)]
    struct Sent<'a> {
        hash: &'a str,
        #[serde(flatten)]
        call: CallRow<'a>,
    }
    let sent = Sent {
        hash,
        call: CallRow::from(call),
    };
    if json {
        return output::emit(&sent, true);
    }
    print_call(&sent.call);
    output::print_kv("hash", hash);
    Ok(())
}

/// Why a call in `state` can no longer land, or `None` while it can.
pub fn dead_call(state: &CallState, method: &str) -> Option<String> {
    match state {
        CallState::Live => None,
        CallState::Landed { hash } => Some(format!("{method} already landed in {hash}")),
        CallState::Failed {
            hash,
            result_xdr,
            host_error,
        } => Some(format!(
            "{method} already landed in {hash} and failed: {}",
            failure(result_xdr.as_deref(), host_error.as_deref())
        )),
        CallState::SequenceUsed => Some(
            "the call is out of date: its source sent another transaction first; build it again \
             if it is still needed"
                .to_string(),
        ),
        CallState::Expired => Some("the call has expired; build it again".to_string()),
    }
}

/// The result code of a failed call, or its raw result when that does not
/// decode, followed by the error that stopped it.
fn failure(result_xdr: Option<&str>, host_error: Option<&str>) -> String {
    let code = match result_xdr {
        Some(xdr) => result_code(xdr).unwrap_or_else(|| format!("resultXdr {xdr}")),
        None => "no result returned".to_string(),
    };
    match host_error {
        Some(error) => format!("{code}, {error}"),
        None => code,
    }
}

/// `alias`, else --sign-as, else --account.
pub fn signing_alias<'a>(config: &'a CliConfig, alias: Option<&'a str>) -> Result<&'a str> {
    let alias = alias
        .or(config.sign_as.as_deref())
        .or(config.account.as_deref())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "signing an admin call needs a `stellar keys` alias: pass --sign-as or --account"
            )
        })?;
    stellar_cli::validate_alias("--sign-as", alias)?;
    Ok(alias)
}

pub fn read_envelope(path: &Path) -> Result<String> {
    Ok(std::fs::read_to_string(path)
        .with_context(|| format!("read envelope {}", path.display()))?
        .trim()
        .to_string())
}

pub fn write_envelope(path: &Path, envelope_xdr: &str) -> Result<()> {
    std::fs::write(path, format!("{envelope_xdr}\n"))
        .with_context(|| format!("write envelope {}", path.display()))
}

fn print_call(call: &CallRow) {
    output::print_kv("method", call.method);
    output::print_kv("contract_id", call.contract_id);
    for (index, arg) in call.args.iter().enumerate() {
        output::print_kv(&format!("arg[{index}]"), arg);
    }
    output::print_kv("source", call.source);
    output::print_kv("fee", format!("{} stroops at most", call.fee));
    output::print_kv(
        "valid_until",
        format!("{} (Unix seconds)", call.valid_until),
    );
}

pub(super) fn print_call_of(call: &OperatorCall) {
    print_call(&CallRow::from(call));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_live_call_can_still_land() {
        assert_eq!(dead_call(&CallState::Live, "pause_deposits"), None);
        let landed = CallState::Landed {
            hash: "ab".to_string(),
        };
        assert_eq!(
            dead_call(&landed, "pause_deposits").as_deref(),
            Some("pause_deposits already landed in ab")
        );
        for state in [CallState::SequenceUsed, CallState::Expired] {
            assert!(
                dead_call(&state, "pause_deposits")
                    .is_some_and(|reason| reason.contains("build it again")),
                "{state:?}"
            );
        }
    }

    #[test]
    fn a_failure_names_its_code_and_the_error_that_stopped_it() {
        assert_eq!(failure(Some("zz"), None), "resultXdr zz");
        assert_eq!(
            failure(None, Some("Error(Contract, #6)")),
            "no result returned, Error(Contract, #6)"
        );
    }
}
