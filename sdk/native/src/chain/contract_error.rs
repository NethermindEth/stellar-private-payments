//! Human-readable Soroban contract error translation.
//!
//! Soroban surfaces a failing contract invocation as `Error(Contract, #N)` —
//! a bare numeric code with no indication of which contract raised it. `#N`
//! is only meaningful together with that contract: `#2` is
//! [`ContractKind::Pool`]'s `MerkleTreeFull`, but
//! [`ContractKind::AspNonMembership`]'s `KeyNotFound`. This module recovers
//! both the code and the raising contract id from the RPC simulation error
//! text (`parse_contract_error`), then, given a deployment
//! [`ContractConfig`], resolves the contract id to a [`ContractKind`] and
//! looks up a human message (`resolve` / `translate`).

use crate::types::{ContractConfig, ContractKind};

/// A Soroban contract error recovered from RPC simulation error text.
///
/// `code` and `contract_id` come from [`parse_contract_error`] alone.
/// `kind`/`name`/`message` are filled in by [`resolve`] (or [`translate`]),
/// which need a deployment [`ContractConfig`] to know which contract's error
/// table `code` should be read against.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub struct ContractErrorInfo {
    /// The raw numeric code from `Error(Contract, #N)`.
    pub code: u32,
    /// Contract id recovered from the event log, if any.
    pub contract_id: Option<String>,
    /// Which contract's error table `code` was resolved against, once known.
    pub kind: Option<ContractKind>,
    /// `#[contracterror]` variant name for `code`, once resolved.
    pub name: Option<&'static str>,
    /// Human-readable message for `code`, once resolved.
    pub message: Option<&'static str>,
}

// `thiserror::Error` still derives `std::error::Error` here; without an
// `#[error(...)]` attribute it leaves `Display` to us, since the wording
// depends on how much of the error we could resolve.
impl std::fmt::Display for ContractErrorInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.kind, self.name, self.message) {
            (Some(kind), Some(name), Some(message)) => write!(
                f,
                "{message} (contract error #{}: {}::{name})",
                self.code,
                kind.as_str()
            ),
            (Some(kind), ..) => {
                write!(
                    f,
                    "unrecognized {} contract error #{}",
                    kind.as_str(),
                    self.code
                )
            }
            (None, ..) => match &self.contract_id {
                Some(contract_id) => write!(f, "contract error #{} from {contract_id}", self.code),
                None => write!(f, "contract error #{}", self.code),
            },
        }
    }
}

/// One row of a contract's error table: the numeric code, its
/// `#[contracterror]` variant name, and a message written for whoever is
/// reading a failed transaction.
///
/// Naming the `'static` lifetimes here is what lets the tables be looked up
/// and returned directly; an anonymous `&str` would be inferred afresh at
/// each call site and could not outlive it.
type CodeEntry = (u32, &'static str, &'static str);

/// Mirrors the `Error` enum in `contracts/pool/src/pool.rs`.
const POOL_CODES: &[CodeEntry] = &[
    (
        1,
        "NotAuthorized",
        "The caller is not authorized to perform this operation.",
    ),
    (
        2,
        "MerkleTreeFull",
        "This pool is full: its Merkle tree has reached capacity and cannot accept new \
         commitments. Retrying will not help — a new pool must be deployed.",
    ),
    (
        3,
        "AlreadyInitialized",
        "The contract has already been initialized.",
    ),
    (
        4,
        "WrongLevels",
        "The configured Merkle tree depth is invalid (must be 1-32).",
    ),
    (
        5,
        "NextIndexNotEven",
        "Internal pool error: the next leaf index is not even.",
    ),
    (
        6,
        "WrongExtAmount",
        "The external amount is invalid: it is negative or exceeds the maximum of 2^248.",
    ),
    (
        7,
        "InvalidProof",
        "Proof verification failed. The pool state may have changed while the proof was \
         being generated — sync and try again.",
    ),
    (
        8,
        "UnknownRoot",
        "The Merkle root is not in the pool's recent history. Your local state is stale or \
         too far behind — sync and try again.",
    ),
    (
        9,
        "AlreadySpentNullifier",
        "One of these notes has already been spent. Sync your notes and retry with different \
         inputs.",
    ),
    (
        10,
        "WrongExtHash",
        "The external data hash does not match the transaction data.",
    ),
    (
        11,
        "NotInitialized",
        "The contract has not been initialized.",
    ),
    (12, "Overflow", "Arithmetic overflow in the contract."),
    (
        13,
        "NonCanonicalPublicInput",
        "A public input is not canonical in the BN254 scalar field.",
    ),
    (
        14,
        "InvalidPolicyFlags",
        "Unsupported ASP policy flag bits.",
    ),
];

/// (code, name, message) for the 3 codes `contracts/pool-gvk` adds on top of
/// [`POOL_CODES`] — mirrors the tail of the `Error` enum in
/// `contracts/pool-gvk/src/pool_gvk.rs`.
const POOL_GVK_EXTRA_CODES: &[CodeEntry] = &[
    (15, "InvalidGvkMode", "Unsupported global view key mode."),
    (
        16,
        "WrongGvkCiphertextCount",
        "Wrong number of global view key ciphertexts for the configured mode.",
    ),
    (
        17,
        "InvalidAdminViewKey",
        "The admin view key is unusable as a circuit public input.",
    ),
];

/// Mirrors the `Error` enum in `contracts/asp-membership/src/lib.rs`.
const ASP_MEMBERSHIP_CODES: &[CodeEntry] = &[
    (
        1,
        "NotAuthorized",
        "The caller is not authorized to perform this operation.",
    ),
    (2, "MerkleTreeFull", "The ASP membership tree is full."),
    (
        3,
        "WrongLevels",
        "The configured Merkle tree depth is invalid.",
    ),
    (
        4,
        "NotInitialized",
        "The ASP membership contract has not been initialized.",
    ),
    (5, "Overflow", "Arithmetic overflow in the contract."),
];

/// Mirrors the `Error` enum in `contracts/asp-non-membership/src/lib.rs`.
const ASP_NON_MEMBERSHIP_CODES: &[CodeEntry] = &[
    (
        1,
        "NotAuthorized",
        "The caller is not authorized to perform this operation.",
    ),
    (
        2,
        "KeyNotFound",
        "The key was not found in the ASP non-membership tree.",
    ),
    (
        3,
        "KeyAlreadyExists",
        "The key already exists in the ASP non-membership tree.",
    ),
    (
        4,
        "InvalidProof",
        "ASP non-membership proof verification failed.",
    ),
    (
        5,
        "NotInitialized",
        "The ASP non-membership contract has not been initialized.",
    ),
    (6, "Overflow", "Arithmetic overflow in the contract."),
];

/// Mirrors the `Groth16Error` enum in `contracts/types/src/lib.rs`.
const GROTH16_VERIFIER_CODES: &[CodeEntry] = &[
    (
        0,
        "InvalidProof",
        "The proof did not satisfy the pairing check.",
    ),
    (
        1,
        "MalformedPublicInputs",
        "The number of public inputs does not match the verification key.",
    ),
    (2, "MalformedProof", "The proof bytes are malformed."),
];

/// Looks up `code` in `kind`'s error table.
///
/// [`ContractKind::PoolGvk`] checks [`POOL_CODES`] first — the 14 codes it
/// shares with [`ContractKind::Pool`] — then falls back to
/// [`POOL_GVK_EXTRA_CODES`], so the shared codes are written out once.
fn describe(kind: ContractKind, code: u32) -> Option<(&'static str, &'static str)> {
    let hit = |table: &[CodeEntry]| table.iter().copied().find(|(c, ..)| *c == code);
    let (_, name, message) = match kind {
        ContractKind::Pool => hit(POOL_CODES),
        ContractKind::PoolGvk => hit(POOL_CODES).or_else(|| hit(POOL_GVK_EXTRA_CODES)),
        ContractKind::AspMembership => hit(ASP_MEMBERSHIP_CODES),
        ContractKind::AspNonMembership => hit(ASP_NON_MEMBERSHIP_CODES),
        ContractKind::Groth16Verifier => hit(GROTH16_VERIFIER_CODES),
    }?;
    Some((name, message))
}

/// Marker Soroban prints ahead of the numeric code, e.g. `Error(Contract, #2)`.
const ERROR_MARKER: &str = "Error(Contract,";

/// Reads the `#N` code immediately following [`ERROR_MARKER`] in `raw`.
fn parse_code(raw: &str) -> Option<u32> {
    let start = raw.find(ERROR_MARKER)?;
    let rest = raw[start..].strip_prefix(ERROR_MARKER)?;
    let rest = rest.trim_start_matches(' ');
    let rest = rest.strip_prefix('#')?;

    let digits_len = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    let (digits, after) = rest.split_at(digits_len);
    if digits.is_empty() || !after.starts_with(')') {
        return None;
    }
    digits.parse::<u32>().ok()
}

/// Topic Soroban stamps on the diagnostic event of a frame that failed.
const ERROR_TOPIC: &str = "topics:[error";

/// Reads the `contract:C…` id out of a single event log line.
fn parse_contract_id(line: &str) -> Option<String> {
    let after = line.split("contract:").nth(1)?;
    let id: String = after
        .chars()
        .take_while(char::is_ascii_alphanumeric)
        .collect();
    (id.starts_with('C') && id.len() == 56).then_some(id)
}

/// Reads one `error` diagnostic event.
///
/// The code and the contract are taken from the *same* line, so a nested
/// call can never pair a code raised by one contract with the id of another.
fn parse_error_frame(line: &str) -> Option<ContractErrorInfo> {
    if !line.contains(ERROR_TOPIC) {
        return None;
    }
    Some(ContractErrorInfo {
        code: parse_code(line)?,
        contract_id: parse_contract_id(line),
        kind: None,
        name: None,
        message: None,
    })
}

/// Recovers a bare (unresolved) contract error from RPC simulation error
/// text: the numeric code from `Error(Contract, #N)`, and the contract id
/// that raised it. Resolving `code` to a [`ContractKind`]
/// happens separately in [`resolve`], since that needs a deployment config.
///
/// Returns `None` if `raw` contains no recognizable `Error(Contract, #N)`.
pub fn parse_contract_error(raw: &str) -> Option<ContractErrorInfo> {
    if let Some(frame) = raw.lines().find_map(parse_error_frame) {
        return Some(frame);
    }
    Some(ContractErrorInfo {
        code: parse_code(raw)?,
        contract_id: None,
        kind: None,
        name: None,
        message: None,
    })
}

/// Classifies `info` against `kind` and, when [`describe`] recognizes the
/// code, fills in `name`/`message`. No-op (beyond recording `kind`) if the
/// code is unrecognized or `kind` is `None`.
pub fn resolve(info: &mut ContractErrorInfo, kind: Option<ContractKind>) {
    info.kind = kind;
    if let Some(kind) = kind
        && let Some((name, message)) = describe(kind, info.code)
    {
        info.name = Some(name);
        info.message = Some(message);
    }
}

/// Parses `raw`, classifies the raising contract against `config` (when both
/// a config and a recovered contract id are available), and resolves the
/// code to a name/message. Pass `config: None` when no deployment is in
/// scope — the result is still a parsed, if unresolved, error.
pub fn translate(raw: &str, config: Option<&ContractConfig>) -> Option<ContractErrorInfo> {
    let mut info = parse_contract_error(raw)?;
    let kind = match (config, &info.contract_id) {
        (Some(config), Some(contract_id)) => config.classify_contract(contract_id),
        _ => None,
    };
    resolve(&mut info, kind);
    Some(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pool `#2` (`MerkleTreeFull`) simulation failure, trimmed to the
    /// shape the parser reads: the `HostError` header and the
    /// `topics:[error, ...]` diagnostic event naming the pool.
    ///
    /// The surrounding events are kept short but real — including one naming
    /// the verifier, so the tests show the pool is chosen because it raised
    /// the error, not merely because it is the only contract mentioned.
    const POOL_ERROR_WITH_EVENT_LOG: &str = r#"Error: simulate transaction: transaction simulation failed: HostError: Error(Contract, #2)

Event log (newest first):
   0: [Diagnostic Event] contract:CBQRNDBA7P7XUABULIZEMUP7NLKDZUECGLSOJPMX6LB5NOUCGXCJSXQQ, topics:[error, Error(Contract, #2)], data:"escalating Ok(ScErrorType::Contract) frame-exit to Err"
   1: [Contract Event] contract:CBQRNDBA7P7XUABULIZEMUP7NLKDZUECGLSOJPMX6LB5NOUCGXCJSXQQ, topics:[new_nullifier_event, 6280451338868492752671156339895579541324923628591032519637967657233742246669], data:{}
   2: [Diagnostic Event] contract:CB2O4B67OKQC6J26KBNM3JK5J7SO63MCSRDCTPPNDTZM7HG5NKIASSV3, topics:[fn_return, verify], data:true
   3: [Diagnostic Event] topics:[fn_call, CBQRNDBA7P7XUABULIZEMUP7NLKDZUECGLSOJPMX6LB5NOUCGXCJSXQQ, transact], data:[...]
"#;

    #[test]
    fn parses_code_and_contract_id_from_an_event_log() {
        let info = parse_contract_error(POOL_ERROR_WITH_EVENT_LOG)
            .expect("recognizable Error(Contract, #N)");
        assert_eq!(info.code, 2);
        assert_eq!(
            info.contract_id,
            Some("CBQRNDBA7P7XUABULIZEMUP7NLKDZUECGLSOJPMX6LB5NOUCGXCJSXQQ".to_string())
        );
    }

    /// The same code (`#2`) must resolve to unrelated errors depending on
    /// which contract raised it — this is the whole reason `kind` exists.
    #[test]
    fn same_code_means_different_things_per_contract_kind() {
        let mut as_pool = parse_contract_error(POOL_ERROR_WITH_EVENT_LOG).expect("parses");
        resolve(&mut as_pool, Some(ContractKind::Pool));
        assert_eq!(as_pool.name, Some("MerkleTreeFull"));
        assert!(as_pool.message.expect("resolved").contains("pool is full"));

        let mut as_asp_non_membership =
            parse_contract_error(POOL_ERROR_WITH_EVENT_LOG).expect("parses");
        resolve(
            &mut as_asp_non_membership,
            Some(ContractKind::AspNonMembership),
        );
        assert_eq!(as_asp_non_membership.name, Some("KeyNotFound"));
    }

    #[test]
    fn groth16_verifier_code_zero_is_invalid_proof() {
        assert_eq!(
            describe(ContractKind::Groth16Verifier, 0),
            Some((
                "InvalidProof",
                "The proof did not satisfy the pairing check."
            ))
        );
    }

    #[test]
    fn pool_gvk_checks_the_shared_table_before_its_own_extra_codes() {
        assert_eq!(
            describe(ContractKind::PoolGvk, 7),
            describe(ContractKind::Pool, 7)
        );
        assert_eq!(
            describe(ContractKind::PoolGvk, 15),
            Some(("InvalidGvkMode", "Unsupported global view key mode."))
        );
        assert_eq!(describe(ContractKind::Pool, 15), None);
    }

    #[test]
    fn no_contract_error_marker_returns_none() {
        assert_eq!(parse_contract_error("connection reset by peer"), None);
    }

    #[test]
    fn malformed_code_returns_none() {
        assert_eq!(parse_contract_error("Error(Contract, #abc)"), None);
    }

    #[test]
    fn display_fully_resolved() {
        let info = ContractErrorInfo {
            code: 2,
            contract_id: Some("CTEST".to_string()),
            kind: Some(ContractKind::Pool),
            name: Some("MerkleTreeFull"),
            message: Some("This pool is full."),
        };
        assert_eq!(
            info.to_string(),
            "This pool is full. (contract error #2: pool::MerkleTreeFull)"
        );
    }

    #[test]
    fn display_kind_known_but_code_unmapped() {
        let info = ContractErrorInfo {
            code: 99,
            contract_id: None,
            kind: Some(ContractKind::Pool),
            name: None,
            message: None,
        };
        assert_eq!(info.to_string(), "unrecognized pool contract error #99");
    }

    #[test]
    fn display_unknown_kind_with_contract_id() {
        let info = ContractErrorInfo {
            code: 2,
            contract_id: Some("CTEST".to_string()),
            kind: None,
            name: None,
            message: None,
        };
        assert_eq!(info.to_string(), "contract error #2 from CTEST");
    }

    #[test]
    fn display_bare_code() {
        let info = ContractErrorInfo {
            code: 2,
            contract_id: None,
            kind: None,
            name: None,
            message: None,
        };
        assert_eq!(info.to_string(), "contract error #2");
    }

    /// The `topics:[error, ...]` diagnostic event names the contract that
    /// actually escalated the failure; an earlier `contract:` mention (e.g.
    /// a callee invoked before the failure) must not win.
    #[test]
    fn prefers_the_error_topics_line_over_an_earlier_unrelated_contract_mention() {
        let raw = r#"0: [Diagnostic Event] contract:CB2O4B67OKQC6J26KBNM3JK5J7SO63MCSRDCTPPNDTZM7HG5NKIASSV3, topics:[fn_return, verify], data:true
1: [Diagnostic Event] contract:CBQRNDBA7P7XUABULIZEMUP7NLKDZUECGLSOJPMX6LB5NOUCGXCJSXQQ, topics:[error, Error(Contract, #2)], data:"escalating Ok(ScErrorType::Contract) frame-exit to Err"
"#;
        let info = parse_contract_error(raw).expect("parses");
        assert_eq!(
            info.contract_id,
            Some("CBQRNDBA7P7XUABULIZEMUP7NLKDZUECGLSOJPMX6LB5NOUCGXCJSXQQ".to_string())
        );
    }

    /// A pool call that fails because its verifier failed produces one `error`
    /// frame per contract. The code and the id must come from the same frame:
    /// pairing the pool's `#7` with the verifier's id would name `#7` against
    /// the verifier's table, which does not define it.
    #[test]
    fn nested_frames_pair_the_code_with_its_own_contract() {
        let raw = r#"HostError: Error(Contract, #7)

Event log (newest first):
   0: [Diagnostic Event] contract:CBQRNDBA7P7XUABULIZEMUP7NLKDZUECGLSOJPMX6LB5NOUCGXCJSXQQ, topics:[error, Error(Contract, #7)], data:"escalating Ok(ScErrorType::Contract) frame-exit to Err"
   1: [Diagnostic Event] contract:CB2O4B67OKQC6J26KBNM3JK5J7SO63MCSRDCTPPNDTZM7HG5NKIASSV3, topics:[error, Error(Contract, #0)], data:"escalating Ok(ScErrorType::Contract) frame-exit to Err"
"#;
        let info = parse_contract_error(raw).expect("parses");
        assert_eq!(info.code, 7);
        assert_eq!(
            info.contract_id,
            Some("CBQRNDBA7P7XUABULIZEMUP7NLKDZUECGLSOJPMX6LB5NOUCGXCJSXQQ".to_string())
        );
    }

    /// Without an event log the code is still recoverable, but nothing names
    /// the contract, so it must not be guessed.
    #[test]
    fn bare_header_yields_code_without_a_contract_id() {
        let info = parse_contract_error("HostError: Error(Contract, #9)").expect("parses");
        assert_eq!(info.code, 9);
        assert_eq!(info.contract_id, None);
    }
}
