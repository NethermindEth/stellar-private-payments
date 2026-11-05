//! Submit and confirm Soroban transactions via RPC.

use anyhow::{Context, Result, bail};
use stellar_xdr::{self as xdr, Limits, ReadXdr, TransactionEnvelope};

use crate::chain::rpc::Client;

/// Submits a signed transaction; returns the transaction hash.
#[tracing::instrument(name = "submit_tx", level = "info", skip_all, fields(correlation_id = %crate::types::correlation_id_or_new()))]
pub(crate) async fn submit_tx(rpc: &Client, signed_tx: &TransactionEnvelope) -> Result<String> {
    let send = rpc
        .send_transaction(signed_tx)
        .await
        .context("sendTransaction failed")?;
    let hash = send.hash;
    if hash.is_empty() {
        bail!("sendTransaction returned empty hash");
    }
    tracing::info!(hash = %hash, "transaction_submitted");
    Ok(hash)
}

/// Names the code of a base64 `TransactionResult`, with each operation's code
/// when the transaction failed in one: `TxBadSeq`, or `TxFailed:
/// InvokeHostFunctionTrapped`. `None` when it does not decode.
pub(crate) fn result_code(result_xdr: &str) -> Option<String> {
    let result = xdr::TransactionResult::from_xdr_base64(result_xdr, Limits::none()).ok()?;
    let code = result.result.name();
    let xdr::TransactionResultResult::TxFailed(operations) = &result.result else {
        return Some(code.to_string());
    };
    let operations: Vec<String> = operations
        .iter()
        .map(|operation| match operation {
            xdr::OperationResult::OpInner(
                inner @ xdr::OperationResultTr::InvokeHostFunction(result),
            ) => format!("{}{}", inner.name(), result.name()),
            xdr::OperationResult::OpInner(inner) => inner.name().to_string(),
            other => other.name().to_string(),
        })
        .collect();
    Some(format!("{code}: {}", operations.join(", ")))
}

/// The error a `host_fn_failed` diagnostic event carries, worded as a failed
/// simulation words it: `Error(Contract, #6)` or `Error(Auth,
/// InvalidAction)`. A transaction that failed on chain reports it only there.
pub(crate) fn host_error(diagnostic_events_xdr: &[String]) -> Option<String> {
    diagnostic_events_xdr.iter().find_map(|event_xdr| {
        let event = xdr::DiagnosticEvent::from_xdr_base64(event_xdr, Limits::none()).ok()?;
        let xdr::ContractEventBody::V0(body) = &event.event.body;
        let [xdr::ScVal::Symbol(name), xdr::ScVal::Error(error), ..] = body.topics.as_slice()
        else {
            return None;
        };
        if name.as_slice() != b"host_fn_failed" {
            return None;
        }
        let code = match error {
            xdr::ScError::Contract(code) => return Some(format!("Error(Contract, #{code})")),
            xdr::ScError::WasmVm(code)
            | xdr::ScError::Context(code)
            | xdr::ScError::Storage(code)
            | xdr::ScError::Object(code)
            | xdr::ScError::Crypto(code)
            | xdr::ScError::Events(code)
            | xdr::ScError::Budget(code)
            | xdr::ScError::Value(code)
            | xdr::ScError::Auth(code) => code,
        };
        Some(format!("Error({}, {})", error.name(), code.name()))
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TxConfirmStatus {
    Success,
    Failed {
        result_xdr: Option<String>,
        host_error: Option<String>,
    },
    Pending,
}

/// Polls transaction status once.
#[tracing::instrument(name = "confirm_tx", level = "info", skip_all, fields(correlation_id = %crate::types::correlation_id_or_new(), hash = %hash))]
pub(crate) async fn confirm_tx(rpc: &Client, hash: &str) -> Result<TxConfirmStatus> {
    let status = rpc
        .get_transaction(hash)
        .await
        .with_context(|| format!("getTransaction failed for {hash}"))?;
    match status.status.as_str() {
        "SUCCESS" => {
            tracing::info!(hash = %hash, status = "SUCCESS", "transaction_confirmed");
            Ok(TxConfirmStatus::Success)
        }
        "FAILED" => {
            tracing::warn!(hash = %hash, status = "FAILED", "transaction_failed");
            Ok(TxConfirmStatus::Failed {
                host_error: host_error(status.diagnostic_events()),
                result_xdr: status.result_xdr,
            })
        }
        _ => {
            tracing::debug!(hash = %hash, "transaction_pending");
            Ok(TxConfirmStatus::Pending)
        }
    }
}

#[cfg(test)]
mod tests {
    use stellar_xdr::WriteXdr;

    use super::*;

    fn encoded(result: xdr::TransactionResultResult) -> String {
        xdr::TransactionResult {
            fee_charged: 100,
            result,
            ext: xdr::TransactionResultExt::V0,
        }
        .to_xdr_base64(Limits::none())
        .expect("result xdr")
    }

    #[test]
    fn result_codes_name_the_transaction_and_its_operations() {
        assert_eq!(
            result_code(&encoded(xdr::TransactionResultResult::TxBadSeq)).as_deref(),
            Some("TxBadSeq")
        );
        let trapped = xdr::OperationResult::OpInner(xdr::OperationResultTr::InvokeHostFunction(
            xdr::InvokeHostFunctionResult::Trapped,
        ));
        assert_eq!(
            result_code(&encoded(xdr::TransactionResultResult::TxFailed(
                vec![trapped].try_into().expect("operations")
            )))
            .as_deref(),
            Some("TxFailed: InvokeHostFunctionTrapped")
        );
        assert_eq!(result_code("not xdr"), None);
    }

    fn host_fn_failed(error: xdr::ScError) -> String {
        xdr::DiagnosticEvent {
            in_successful_contract_call: false,
            event: xdr::ContractEvent {
                ext: xdr::ExtensionPoint::V0,
                contract_id: None,
                type_: xdr::ContractEventType::Diagnostic,
                body: xdr::ContractEventBody::V0(xdr::ContractEventV0 {
                    topics: vec![
                        xdr::ScVal::Symbol("host_fn_failed".try_into().expect("symbol")),
                        xdr::ScVal::Error(error),
                    ]
                    .try_into()
                    .expect("topics"),
                    data: xdr::ScVal::Void,
                }),
            },
        }
        .to_xdr_base64(Limits::none())
        .expect("event xdr")
    }

    #[test]
    fn host_errors_are_worded_as_a_simulation_words_them() {
        assert_eq!(
            host_error(&[host_fn_failed(xdr::ScError::Contract(20))]).as_deref(),
            Some("Error(Contract, #20)")
        );
        assert_eq!(
            host_error(&[
                "not xdr".to_string(),
                host_fn_failed(xdr::ScError::Auth(xdr::ScErrorCode::InvalidAction))
            ])
            .as_deref(),
            Some("Error(Auth, InvalidAction)")
        );
        assert_eq!(host_error(&[]), None);
    }
}
