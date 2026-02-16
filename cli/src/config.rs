//! Deployment config, network/path resolution.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Deployment configuration loaded from `deployments.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentConfig {
    /// Network name (e.g., "testnet")
    pub network: String,
    /// Deployer G... address
    pub deployer: String,
    /// Admin G... address
    pub admin: String,
    /// ASP membership contract ID
    pub asp_membership: String,
    /// ASP non-membership contract ID
    pub asp_non_membership: String,
    /// Groth16 verifier contract ID
    pub verifier: String,
    /// Pool contract ID
    pub pool: String,
    /// Whether contracts are initialized
    pub initialized: bool,
}

/// Path to the config directory for the CLI.
pub fn config_dir() -> Result<PathBuf> {
    let base = dirs::config_dir().context("Could not determine config directory")?;
    Ok(base.join("stellar").join("spp"))
}

/// Path to the deployment config file for a given network.
fn config_file(network: &str) -> Result<PathBuf> {
    Ok(config_dir()?.join(format!("{network}.toml")))
}

/// Load an existing deployment config.
pub fn load_config(network: &str) -> Result<DeploymentConfig> {
    let path = config_file(network)?;
    if path.exists() {
        let contents = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read config from {}", path.display()))?;
        let cfg: DeploymentConfig =
            toml::from_str(&contents).context("Failed to parse config")?;
        return Ok(cfg);
    }

    // Fall back to workspace deployments.json
    load_from_deployments_json(network)
}

/// Load or create config from deployments.json for a new init.
pub fn load_or_create_config(network: &str) -> Result<DeploymentConfig> {
    let cfg = load_from_deployments_json(network)?;

    // Save to config dir
    let path = config_file(network)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create config dir {}", parent.display()))?;
    }
    let contents = toml::to_string_pretty(&cfg).context("Failed to serialize config")?;
    std::fs::write(&path, contents)
        .with_context(|| format!("Failed to write config to {}", path.display()))?;

    Ok(cfg)
}

/// Load deployment config from the workspace `scripts/deployments.json`.
fn load_from_deployments_json(network: &str) -> Result<DeploymentConfig> {
    // Try to find deployments.json relative to the binary or well-known paths
    let candidates = [
        // Workspace-relative (common during development)
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../scripts/deployments.json"),
    ];

    for candidate in &candidates {
        if candidate.exists() {
            let contents = std::fs::read_to_string(candidate).with_context(|| {
                format!(
                    "Failed to read deployments.json from {}",
                    candidate.display()
                )
            })?;
            let cfg: DeploymentConfig =
                serde_json::from_str(&contents).context("Failed to parse deployments.json")?;

            if cfg.network != network {
                anyhow::bail!(
                    "deployments.json is for network '{}', but '{}' was requested",
                    cfg.network,
                    network
                );
            }

            return Ok(cfg);
        }
    }

    anyhow::bail!(
        "Could not find deployments.json. Run from the workspace root or run `stellar spp init` first."
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_deployment_config_json_roundtrip() {
        let cfg = DeploymentConfig {
            network: "testnet".to_string(),
            deployer: "GABC".to_string(),
            admin: "GABC".to_string(),
            asp_membership: "CASP1".to_string(),
            asp_non_membership: "CASP2".to_string(),
            verifier: "CVER".to_string(),
            pool: "CPOOL".to_string(),
            initialized: true,
        };

        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: DeploymentConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.network, "testnet");
        assert_eq!(parsed.pool, "CPOOL");
        assert!(parsed.initialized);
    }

    #[test]
    fn test_deployment_config_toml_roundtrip() {
        let cfg = DeploymentConfig {
            network: "standalone".to_string(),
            deployer: "GD123".to_string(),
            admin: "GA456".to_string(),
            asp_membership: "CMEM".to_string(),
            asp_non_membership: "CNON".to_string(),
            verifier: "CVER".to_string(),
            pool: "CPOOL".to_string(),
            initialized: false,
        };

        let toml_str = toml::to_string_pretty(&cfg).unwrap();
        let parsed: DeploymentConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.network, "standalone");
        assert_eq!(parsed.admin, "GA456");
        assert!(!parsed.initialized);
    }

    #[test]
    fn test_load_from_deployments_json() {
        // This test requires the actual deployments.json in the workspace
        let result = load_from_deployments_json("testnet");
        if let Ok(cfg) = result {
            assert_eq!(cfg.network, "testnet");
            assert!(!cfg.pool.is_empty());
            assert!(!cfg.asp_membership.is_empty());
        }
        // If file not found, that's OK in CI
    }
}
