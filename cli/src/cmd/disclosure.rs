//! Generate and verify selective-disclosure receipts.

use std::{path::Path, str::FromStr};

use anyhow::{Context, Result, bail};
use serde::Serialize;
use stellar_private_payments::{
    DisclosureRequest,
    disclosure::find_circuit,
    types::{DisclosureReceipt, DisclosureVerificationReport, Field, correlation_id_or_new},
};

use crate::{
    config::{CliConfig, validate_pool},
    onboard, output,
    session::{ClientSession, disclosure_prover},
};

#[tracing::instrument(
    name = "cmd_disclosure_generate",
    skip_all,
    fields(correlation_id = %correlation_id_or_new(), commitment_count = commitments.len())
)]
#[allow(clippy::too_many_arguments)]
pub fn generate(
    config: &CliConfig,
    pool: &str,
    commitments: &[String],
    authority_label: &str,
    authority_identity: &str,
    purpose: &str,
    nonce: Option<&str>,
    receipt_output: Option<&Path>,
    json: bool,
) -> Result<()> {
    if commitments.is_empty() || commitments.len() > 4 {
        bail!("provide between one and four commitment values");
    }
    validate_pool(pool, &config.deployment)?;

    let selected_commitments = commitments
        .iter()
        .map(|raw| Field::from_str(raw).with_context(|| format!("invalid note commitment {raw}")))
        .collect::<Result<Vec<_>>>()?;
    let context_nonce = match nonce {
        Some(raw) => Field::from_str(raw).context("invalid --nonce")?,
        None => stellar_private_payments::zk::encryption::generate_random_blinding()
            .context("generate disclosure nonce")?,
    };

    let account = config.require_account()?;
    onboard::ensure_ready(config, &account)?;
    let network = config.resolve_network()?;
    let pool_session = ClientSession::new_disclosure(config, &account, &network)?.pool(pool)?;
    let receipt = pool_session
        .disclose(DisclosureRequest {
            selected_commitments,
            authority_label: authority_label.to_string(),
            authority_identity_payload_hex: authority_identity.to_string(),
            purpose: purpose.to_string(),
            context_nonce,
        })
        .map_err(|e| anyhow::anyhow!("generate disclosure receipt: {e}"))?
        .ok_or_else(|| {
            anyhow::anyhow!("account is not registered. register or deposit before disclosing")
        })?;

    write_receipt(&receipt, receipt_output, json)
}

#[tracing::instrument(
    name = "cmd_disclosure_verify",
    skip_all,
    fields(correlation_id = %correlation_id_or_new())
)]
pub fn verify(
    config: &CliConfig,
    receipt_path: &Path,
    expected_vk_hash: Option<&str>,
    require_unspent: bool,
    json: bool,
) -> Result<()> {
    let raw = read_receipt(receipt_path)?;
    let receipt: DisclosureReceipt =
        serde_json::from_str(&raw).context("parse disclosure receipt JSON")?;
    let circuit = find_circuit(&receipt.circuit.name)
        .ok_or_else(|| anyhow::anyhow!("unknown disclosure circuit: {}", receipt.circuit.name))?;
    let expected_vk_hash = expected_vk_hash.unwrap_or(circuit.canonical_vk_hash);

    let network = config.resolve_network()?;
    let prover = disclosure_prover(config)?;
    let report = stellar_private_payments::blocking::verify_disclosure_receipt(
        &network.rpc_url,
        config.deployment.clone(),
        &prover,
        &receipt,
        expected_vk_hash,
    )
    .map_err(|e| anyhow::anyhow!("verify disclosure receipt: {e}"))?;
    print_verification(&report, json)?;

    if !report.is_cryptographically_valid() {
        bail!("disclosure receipt failed cryptographic, context, or root verification");
    }
    if require_unspent && !report.nullifiers_unspent {
        bail!("one or more disclosed notes have already been spent");
    }
    Ok(())
}

fn write_receipt(receipt: &DisclosureReceipt, path: Option<&Path>, json: bool) -> Result<()> {
    let serialized = serde_json::to_string_pretty(receipt)?;
    let Some(path) = path else {
        println!("{serialized}");
        return Ok(());
    };

    std::fs::write(path, format!("{serialized}\n"))
        .with_context(|| format!("write disclosure receipt to {}", path.display()))?;

    #[derive(Serialize)]
    struct ReceiptWritten<'a> {
        receipt_file: String,
        circuit: &'a str,
        note_count: u32,
        vk_hash: &'a str,
    }
    let payload = ReceiptWritten {
        receipt_file: path.display().to_string(),
        circuit: &receipt.circuit.name,
        note_count: receipt.circuit.n_notes,
        vk_hash: &receipt.circuit.vk_hash,
    };
    if json {
        output::emit(&payload, true)
    } else {
        output::print_section("Disclosure receipt generated");
        output::print_kv("receipt_file", &payload.receipt_file);
        output::print_kv("circuit", payload.circuit);
        output::print_kv("note_count", payload.note_count);
        output::print_kv("vk_hash", payload.vk_hash);
        Ok(())
    }
}

fn read_receipt(path: &Path) -> Result<String> {
    std::fs::read_to_string(path)
        .with_context(|| format!("read disclosure receipt from {}", path.display()))
}

fn print_verification(report: &DisclosureVerificationReport, json: bool) -> Result<()> {
    if json {
        return output::emit(report, true);
    }
    output::print_section("Disclosure verification");
    output::print_kv("proof_verified", report.proof_verified);
    output::print_kv("context_verified", report.context_verified);
    output::print_kv("known_root_status", report.known_root_status);
    output::print_kv("nullifiers_unspent", report.nullifiers_unspent);
    if !report.spent_nullifier_indices.is_empty() {
        let indices = report
            .spent_nullifier_indices
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        output::print_kv("spent_nullifier_indices", indices);
    }
    output::print_kv(
        "cryptographically_valid",
        report.is_cryptographically_valid(),
    );
    Ok(())
}
