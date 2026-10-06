use stellar_private_payments::types::ContractConfig;

/// Read a JSON file or a directory containing deployments.json, then validate
/// the deployment before accessing upstream or storage.
pub fn read_deployment(path: &std::path::Path) -> anyhow::Result<ContractConfig> {
    use anyhow::Context;
    let path = if path.is_dir() {
        path.join("deployments.json")
    } else {
        path.to_owned()
    };
    let deployment: ContractConfig = serde_json::from_str(
        &std::fs::read_to_string(&path)
            .with_context(|| format!("read deployment {}", path.display()))?,
    )
    .with_context(|| format!("parse deployment {}", path.display()))?;
    deployment.validate_network(deployment.network_passphrase.as_deref().unwrap_or_default())?;
    Ok(deployment)
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

pub fn current_deployment_storage_id(deployment: &ContractConfig) -> anyhow::Result<String> {
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
    fn directory_and_file_load_the_same_deployment() -> anyhow::Result<()> {
        let directory =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deployments/testnet");
        let from_directory = read_deployment(&directory)?;
        let from_file = read_deployment(&directory.join("deployments.json"))?;
        assert_eq!(
            serde_json::to_value(from_directory)?,
            serde_json::to_value(from_file)?
        );
        Ok(())
    }

    #[test]
    fn directory_without_manifest_reports_the_resolved_file() {
        let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let error = read_deployment(&directory).expect_err("no manifest in source directory");
        assert!(
            error
                .to_string()
                .contains(&directory.join("deployments.json").display().to_string())
        );
    }

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
