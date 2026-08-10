use types::ContractConfig;

// TODO make it dependent on the network during the compilation
const DEPLOYMENT: &str = include_str!("../../../deployments/testnet/deployments.json");

/// Returns the statically-embedded contracts deployment configuration.
///
/// This is intentionally compiled-in (via `include_str!`) to prevent runtime
/// misconfiguration of critical identifiers like contract IDs and the
/// deployment ledger.
pub(crate) fn deployment_config() -> anyhow::Result<ContractConfig> {
    Ok(serde_json::from_str(DEPLOYMENT)?)
}

/// Stable storage namespace for a contract set + genesis ledger.
///
/// Pages and indexer KV are keyed by this id so redeployments can share one DB
/// without colliding with older contract history.
///
/// Format: `v1:{min_ledger}:{sorted 4-char contract prefixes concatenated}`.
pub fn deployment_storage_id(contract_ids: &[String], min_deployment_ledger: u32) -> String {
    let mut prefixes: Vec<String> = contract_ids
        .iter()
        .map(|id| id.chars().take(4).collect())
        .collect();
    prefixes.sort();
    format!("v1:{min_deployment_ledger}:{}", prefixes.concat())
}

/// Storage id for the compiled-in deployment config.
pub fn current_deployment_storage_id() -> anyhow::Result<String> {
    let deployment = deployment_config()?;
    Ok(deployment_storage_id(
        &deployment.all_contract_ids(),
        deployment.min_deployment_ledger()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::deployment_storage_id;

    #[test]
    fn storage_id_sorts_contract_prefixes() {
        let a = deployment_storage_id(&["BBBBXXXX".into(), "AAAAYYYY".into()], 10);
        let b = deployment_storage_id(&["AAAAYYYY".into(), "BBBBXXXX".into()], 10);
        assert_eq!(a, b);
        assert_eq!(a, "v1:10:AAAABBBB");
    }

    #[test]
    fn storage_id_changes_with_ledger_or_contracts() {
        let base = deployment_storage_id(&["AAAAYYYY".into()], 10);
        assert_ne!(base, deployment_storage_id(&["AAAAYYYY".into()], 11));
        assert_ne!(
            base,
            deployment_storage_id(&["AAAAYYYY".into(), "BBBBXXXX".into()], 10)
        );
    }

    #[test]
    fn storage_id_uses_four_char_prefixes() {
        let id = deployment_storage_id(
            &[
                "CBF4Y4PC72JI23H3VJMO7WNZH5BJRGA2HD2HUQANZPXB4BXRVSKUOS6U".into(),
                "CBQRNDBA7P7XUABULIZEMUP7NLKDZUECGLSOJPMX6LB5NOUCGXCJSXQQ".into(),
            ],
            3_742_083,
        );
        assert_eq!(id, "v1:3742083:CBF4CBQR");
    }
}
