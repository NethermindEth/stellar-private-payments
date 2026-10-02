use stellar_private_payments::types::ContractConfig;

const DEPLOYMENT: &str = include_str!(concat!(env!("OUT_DIR"), "/deployments.json"));

/// Returns the statically-embedded contracts deployment configuration.
///
/// This is intentionally compiled-in (via `include_str!`) to prevent runtime
/// misconfiguration of critical identifiers like contract IDs and the
/// deployment ledger.
pub(crate) fn deployment_config() -> anyhow::Result<ContractConfig> {
    Ok(serde_json::from_str(DEPLOYMENT)?)
}

/// Network-isolated v2 namespace. v1 caches are rebuilt, never reused.
pub fn deployment_storage_id(
    contract_ids: &[String],
    min_deployment_ledger: u32,
    passphrase: &str,
) -> String {
    use sha2::{Digest, Sha256};
    let network_hash = Sha256::digest(passphrase.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let mut ids = contract_ids.to_vec();
    ids.sort();
    let contracts_hash = Sha256::digest(ids.join(":").as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("v2:{network_hash}:{min_deployment_ledger}:{contracts_hash}")
}

pub fn current_deployment_storage_id() -> anyhow::Result<String> {
    let deployment = deployment_config()?;
    let passphrase = deployment.network_passphrase.as_deref().unwrap_or_default();
    deployment.validate_network(passphrase)?;
    Ok(deployment_storage_id(
        &deployment.all_contract_ids(),
        deployment.min_deployment_ledger()?,
        passphrase,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn namespace_is_order_independent_and_network_isolated() {
        let ids = vec!["AAAAX".into(), "BBBBY".into()];
        let base = deployment_storage_id(&ids, 10, "network A");
        assert!(base.starts_with("v2:"));
        assert_eq!(
            base,
            deployment_storage_id(&[ids[1].clone(), ids[0].clone()], 10, "network A")
        );
        assert_ne!(base, deployment_storage_id(&ids, 10, "network B"));
        assert_ne!(base, deployment_storage_id(&ids, 11, "network A"));
        assert_ne!(
            base,
            deployment_storage_id(&["AAAAZ".into(), "BBBBY".into()], 10, "network A")
        );
    }
}
